package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"gateway-service/internal/config"
	"gateway-service/internal/proxy"

	// Импорт go-sdk
	"gitlab.com/markerloop/go-sdk/pkg/i18n"
	"gitlab.com/markerloop/go-sdk/pkg/redis"
	"gitlab.com/markerloop/go-sdk/pkg/response"
)

// PermissionMiddlewareConfig конфигурация middleware проверки разрешений
type PermissionMiddlewareConfig struct {
	Config       *config.Config
	ProxyService proxy.ProxyService
	RedisService *redis.RedisService
	Logger       *logrus.Logger
}

// checkPermissionRequest — тело POST /internal/users/:id/check-permission
// user-service (models.CheckPermissionRequest там). WorkspaceID и
// WorkspaceRole непусты только на маршруте со скоупом пространства.
type checkPermissionRequest struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	WorkspaceID   string `json:"workspace_id,omitempty"`
	WorkspaceRole string `json:"workspace_role,omitempty"`
}

// PermissionMiddleware создает middleware для проверки разрешений
func PermissionMiddleware(cfg PermissionMiddlewareConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Получаем user_id из контекста (должен быть установлен JWT middleware)
		userID, exists := c.Get("user_id")
		if !exists {
			cfg.Logger.Warn("user_id не найден в контексте")
			response.Unauthorized(c, "Требуется авторизация")
			c.Abort()
			return
		}

		userIDStr, ok := userID.(string)
		if !ok {
			cfg.Logger.Error("user_id имеет неверный тип")
			response.InternalServerError(c, "Ошибка обработки запроса")
			c.Abort()
			return
		}

		// Получаем method и path из запроса
		method := c.Request.Method
		path := c.Request.URL.Path

		// Нормализуем путь
		normalizedPath := normalizePath(path)

		// Проверяем кэш для маппинга route -> permission
		cacheKey := fmt.Sprintf("route_permission:%s:%s", method, normalizedPath)
		ctx := context.Background()

		var routeConfig *config.RouteConfig
		var permissionCode string

		// Пытаемся получить из кэша
		if cfg.RedisService != nil {
			cached, err := cfg.RedisService.Get(ctx, cacheKey)
			if err == nil && cached != "" {
				permissionCode = cached
				cfg.Logger.Debugf("Получено разрешение из кэша: %s для маршрута %s %s", permissionCode, method, normalizedPath)
			}
		}

		// Если не найдено в кэше, ищем в конфигурации
		if permissionCode == "" {
			routeConfig = config.FindRouteConfig(method, normalizedPath)
			if routeConfig == nil {
				// Маршрут не найден в конфигурации - логируем предупреждение и возвращаем 403 (fail-safe).
				// В журнал — шаблон маршрута Gin, не normalizedPath: короткий
				// логин в /users/username/:x нормализатор оставляет как есть (SDL-738).
				cfg.Logger.Warnf("Маршрут не найден в конфигурации: %s %s", method, c.FullPath())
				sendForbiddenError(c, cfg, "FORBIDDEN")
				c.Abort()
				return
			}

			permissionCode = routeConfig.Permission

			// Сохраняем в кэш
			if cfg.RedisService != nil {
				if err := cfg.RedisService.Set(ctx, cacheKey, permissionCode, 1*time.Hour); err != nil {
					cfg.Logger.Warnf("Не удалось сохранить в кэш: %v", err)
				}
			}
		} else {
			// Если получили из кэша, все равно получаем конфигурацию для проверки Required
			routeConfig = config.FindRouteConfig(method, normalizedPath)
		}

		// Если разрешение не требуется, пропускаем
		if routeConfig != nil && !routeConfig.Required {
			c.Next()
			return
		}

		// Проверяем разрешение "own" - user_id из JWT должен совпадать с параметром :id
		if strings.Contains(permissionCode, ":own") {
			// Короткое замыкание на собственный профиль — только на ЧТЕНИЕ (SDL-426).
			// Раньше сюда попадал любой метод, и PUT /users/my проходил мимо
			// проверки: право users:update:own нельзя было отозвать ролью, из-за
			// чего роль "только на чтение" не означала этого буквально. Запись
			// теперь идёт общим путём и проверяется user-service.
			// Чтение оставлено замкнутым намеренно: профиль читается раньше, чем
			// у новой учётки появляются роли (та же причина, что у Required:false
			// на онбординг-маршрутах).
			// Сегмент сравнивается целиком, а не подстрокой: strings.Contains
			// матчил бы и /mystuff, стоило появиться третьему ':own'-маршруту
			// с пользовательским сегментом в пути.
			if method == http.MethodGet && hasPathSegment(normalizedPath, "my") {
				cfg.Logger.Debugf("Чтение собственного профиля разрешено: user_id=%s", userIDStr)
				c.Next()
				return
			}
			// Для других маршрутов проверяем, что :id совпадает с user_id
			paramID := c.Param("id")
			if paramID != "" && paramID != userIDStr {
				cfg.Logger.Warnf("Попытка доступа к чужому ресурсу: user_id=%s, param_id=%s", userIDStr, paramID)
				sendForbiddenError(c, cfg, "FORBIDDEN")
				c.Abort()
				return
			}
		}

		// Вызываем internal endpoint user-service для проверки разрешения.
		// Пространство и роль в нём (SDL-614) берутся ТОЛЬКО из контекста, куда
		// их положил ScopeMiddleware после сверки с workspace_members
		// collections-service, — не из строки запроса и не из тела: заявленному
		// клиентом пространству доверять нельзя. Право уровня workspace без
		// роли user-service отклоняет, поэтому в группе pages слой скоупа стоит
		// перед этим (routes.go).
		checkReq := checkPermissionRequest{
			Method: method,
			Path:   normalizedPath,
		}
		if ws, ok := WorkspaceScopeFromContext(c); ok {
			checkReq.WorkspaceID = ws.ID
			checkReq.WorkspaceRole = ws.Role
		}

		reqBody, err := json.Marshal(checkReq)
		if err != nil {
			cfg.Logger.Error("Ошибка сериализации запроса проверки разрешения:", err)
			response.InternalServerError(c, "Ошибка проверки разрешения")
			c.Abort()
			return
		}

		// Формируем заголовки для internal запроса
		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		headers["X-Service-Key"] = cfg.Config.Security.ServiceKey

		// Вызываем internal endpoint
		internalPath := fmt.Sprintf("/api/v1/internal/users/%s/check-permission", userIDStr)
		proxyResp, err := cfg.ProxyService.ProxyRequest(
			"user",
			"POST",
			internalPath,
			headers,
			nil,
			reqBody,
		)

		if err != nil {
			cfg.Logger.Error("Ошибка вызова user-service для проверки разрешения:", err)
			response.InternalServerError(c, "Ошибка проверки разрешения")
			c.Abort()
			return
		}

		// Парсим ответ
		if proxyResp.StatusCode != 200 {
			cfg.Logger.Warnf("user-service вернул статус %d при проверке разрешения", proxyResp.StatusCode)
			sendForbiddenError(c, cfg, "FORBIDDEN")
			c.Abort()
			return
		}

		// Проверяем ответ
		var checkResp struct {
			Data struct {
				HasPermission bool `json:"has_permission"`
			} `json:"data"`
		}

		if err := json.Unmarshal(proxyResp.Body, &checkResp); err != nil {
			cfg.Logger.Error("Ошибка парсинга ответа проверки разрешения:", err)
			sendForbiddenError(c, cfg, "FORBIDDEN")
			c.Abort()
			return
		}

		if !checkResp.Data.HasPermission {
			cfg.Logger.Warnf("У пользователя %s нет разрешения %s для %s %s", userIDStr, permissionCode, method, normalizedPath)
			sendForbiddenError(c, cfg, "FORBIDDEN")
			c.Abort()
			return
		}

		cfg.Logger.Debugf("Разрешение проверено успешно: user_id=%s, permission=%s, method=%s, path=%s", userIDStr, permissionCode, method, normalizedPath)
		c.Next()
	}
}

// hasPathSegment сообщает, содержит ли путь ровно такой сегмент.
// Отдельно от strings.Contains: подстрока матчит и часть чужого сегмента
// (например "my" внутри "mystuff"), а решение о доступе так принимать нельзя.
func hasPathSegment(path, segment string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == segment {
			return true
		}
	}
	return false
}

// normalizePath нормализует путь, заменяя UUID и другие параметры на плейсхолдеры
func normalizePath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		// Проверяем, является ли часть UUID (простая проверка по длине и формату)
		if len(part) == 36 && strings.Contains(part, "-") {
			parts[i] = ":id"
		} else if len(part) > 0 && part[0] != ':' {
			// Если это не плейсхолдер и не UUID, проверяем, не является ли это email
			if strings.Contains(part, "@") {
				parts[i] = ":email"
			} else if len(part) > 20 && !strings.Contains(part, "@") {
				// Длинные строки могут быть параметрами (но не email)
				// Проверяем, не является ли это username
				if i > 0 && parts[i-1] == "username" {
					parts[i] = ":username"
				} else if i > 0 && parts[i-1] == "email" {
					parts[i] = ":email"
				} else {
					parts[i] = ":param"
				}
			} else if isAllDigits(part) {
				// Числовые сегменты — версии, ревизии, страницы пагинации
				// и т.п. До этой ветки нумерованные URL ломали match
				// (`/revisions/3` пытался найтись дословно в registry).
				// Сворачиваем в общий `:param` чтобы один config-entry
				// покрывал любую числовую вариацию.
				parts[i] = ":param"
			}
		}
	}
	return strings.Join(parts, "/")
}

// isAllDigits returns true when `s` is non-empty and consists entirely
// of ASCII decimal digits. Conservative: avoids matching negative
// numbers, hex, or floats — currently no Markerloop route accepts
// any of those as a path parameter.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// sendForbiddenError отправляет локализованную ошибку 403
func sendForbiddenError(c *gin.Context, cfg PermissionMiddlewareConfig, errorCode string) {
	// Получаем язык из заголовка
	acceptLanguage := c.GetHeader("Accept-Language")
	language := i18n.LanguageRU // По умолчанию русский
	if acceptLanguage != "" {
		// Простой парсинг Accept-Language (берем первый язык)
		langParts := strings.Split(acceptLanguage, ",")
		if len(langParts) > 0 {
			lang := strings.TrimSpace(strings.Split(langParts[0], ";")[0])
			switch lang {
			case "en":
				language = i18n.LanguageEN
			case "kk":
				language = i18n.LanguageKK
			default:
				language = i18n.LanguageRU
			}
		}
	}

	// Создаем клиент для dictionary-service
	dictClient := i18n.NewClient(cfg.Config.Services.Dictionary.URL, cfg.Logger)

	// Получаем локализованную ошибку
	localizedError, err := dictClient.GetError(context.Background(), errorCode, language, nil)
	if err != nil {
		cfg.Logger.Warnf("Не удалось получить локализованную ошибку: %v", err)
		// Fallback на стандартное сообщение
		response.Forbidden(c, "Доступ запрещен")
		return
	}

	// Отправляем локализованную ошибку
	c.JSON(403, gin.H{
		"success": false,
		"error": gin.H{
			"code":    localizedError.Code,
			"message": localizedError.Message,
			"details": localizedError.Details,
		},
	})
	c.Abort()
}

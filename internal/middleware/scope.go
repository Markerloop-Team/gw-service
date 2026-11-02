package middleware

// SDL-587 (EP-121): шлюз резолвит причастность актора к пространству,
// которое тот назвал в запросе, и инжектит скоуп вниз заголовком.
// Проектный род скоупа снят в SDL-620 вместе с группой /api/v1/projects:
// единственный род — пространство (config.ScopeWorkspace).
//
// SDL-614 (EP-111): для пространства слой резолвит не факт членства, а РОЛЬ
// актора в нём (owner | member) — из единственного места, где живёт пара
// «человек + пространство»: workspace_members в collections-service
// (SDL-609). Пара «пространство + роль» кладётся в контекст, и
// permissionMiddleware отдаёт её в user-service вместе с методом и путём:
// право уровня workspace без роли — отказ. Слой стоит ПЕРЕД проверкой права
// (группа pages), чтобы в неё уехало проверенное пространство, а не то, что
// заявил клиент.
//
// permissionMiddleware отвечает только на «можно ли дёргать метод+путь» и
// про объекты не знает; продуктовые сервисы (files, pages) пространствами и
// проектами не владеют и проверить причастность сами не могут. Источник
// истины о членстве на сегодня — collections-service: он выводит личность из
// X-User-ID и отвечает 404 на чужое пространство. С SDL-613 S4 у токена
// пространства (claim wsid) источник — сам токен (wstoken.go); потребители
// заголовка и контекста не тронулись.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"gateway-service/internal/config"

	"gitlab.com/markerloop/go-sdk/pkg/logsafe"
	"gitlab.com/markerloop/go-sdk/pkg/response"
)

const (
	// HeaderScopeWorkspaceID — доверенный скоуп для апстрима. Клиентские
	// одноимённые заголовки вычищает sanitizeUpstreamHeaders (префикс
	// x-scope-, покрывает и бывший X-Scope-Project-ID), иначе проверка
	// бутафорская.
	HeaderScopeWorkspaceID = "X-Scope-Workspace-ID"

	// ScopeHeadersContextKey — ключ gin-контекста: map заголовков скоупа,
	// которые ProxyToService кладёт вниз ПОСЛЕ вычистки клиентских.
	ScopeHeadersContextKey = "scope_headers"

	// WorkspaceScopeContextKey — ключ gin-контекста: WorkspaceScope, пара
	// «пространство + роль актора в нём», сверенная этим слоем. Читает
	// permissionMiddleware; ничего другого источником пространства для
	// проверки права быть не может.
	WorkspaceScopeContextKey = "workspace_scope"

	// membershipCacheTTL короткий намеренно: членство спрашивается на каждый
	// скоупленный запрос, а отзыв доступа не должен ждать час, как у кэша
	// маршрут→право.
	membershipCacheTTL = 60 * time.Second

	// workspaceRoleCachePrefix — ключ роли актора в пространстве; значение —
	// сама роль. Префикс НЕ «membership:» намеренно (SDL-614): под старым
	// ключом лежит литерал "1", и первые 60 секунд после выката каждый
	// запрос читал бы его как роль и получал отказ.
	workspaceRoleCachePrefix = "workspace_role:"

	// workspaceRevokedMarkerPrefix — маркер «актора только что исключили из
	// пространства» (SDL-615 S2); ключ <prefix><user_id>:<workspace_id>,
	// значение "1". Пока маркер жив, resolveWorkspaceRole не читает и не
	// пишет кэш роли — резолвит вживую. Ставит MembershipRevocation.
	workspaceRevokedMarkerPrefix = "workspace_revoked:"
	// workspaceGoneMarkerPrefix — маркер «пространство только что удалили»
	// (SDL-615 S2); ключ <prefix><workspace_id>, действие то же, что у
	// workspaceRevokedMarkerPrefix, но для всех участников сразу.
	workspaceGoneMarkerPrefix = "workspace_gone:"
	// revocationMarkerTTL строго больше membershipCacheTTL: запрос
	// исключённого, начатый ДО удаления, может записать роль в кэш уже ПОСЛЕ
	// DEL — маркер должен пережить такую запись целиком (60 с), иначе
	// протухшая роль вернётся к жизни. Это маркеры старого пути (кэш роли,
	// значение "1"); токен пространства гасят другие отметки — wsaccess
	// wsrev:v1 / wsgone:v1 со временем отзыва и TTL wsaccess.RevocationTTL
	// (SDL-613 S4, revocation.go). Старые пишутся, пока жив старый путь.
	revocationMarkerTTL = 70 * time.Second
)

// WorkspaceScope — пространство запроса и роль актора в нём, сверенные
// шлюзом по workspace_members collections-service.
type WorkspaceScope struct {
	ID   string
	Role string
}

// uuidRe — каноническая форма UUID 8-4-4-4-12. Своя, чтобы не тянуть
// зависимость ради одной проверки формы.
var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// lookupRouteConfig — поиск записи реестра по методу и нормализованному
// пути. Переменная, а не прямой вызов: реестр — литерал в config, и единственный
// способ проверить ветку «неизвестный род скоупа» на уровне middleware —
// подменить поиск в тесте (scope_kind_test.go).
var lookupRouteConfig = config.FindRouteConfig

// ScopeMiddleware сверяет причастность актора к объявленному в реестре
// скоупу маршрута. Требует user_id в контексте (jwtMiddleware). Маршрут без
// объявления (ScopeParam пуст) проходит без изменений. Род скоупа один —
// пространство; запись с иным родом — 500 (fail-closed), а не пропуск.
func ScopeMiddleware(cfg PermissionMiddlewareConfig) gin.HandlerFunc {
	if cfg.RedisService == nil && cfg.Logger != nil {
		cfg.Logger.Warn("Redis не настроен: отзыв токенов пространства не проверяется, членство по ним спрашивается у collections-service на каждый запрос")
	}
	return func(c *gin.Context) {
		rc := lookupRouteConfig(c.Request.Method, normalizePath(c.Request.URL.Path))
		if rc == nil || rc.ScopeParam == "" {
			c.Next()
			return
		}

		userID, _ := c.Get("user_id")
		userIDStr, ok := userID.(string)
		if !ok || userIDStr == "" {
			response.Unauthorized(c, "Требуется авторизация")
			c.Abort()
			return
		}

		raw, err := scopeValue(c, rc)
		if err != nil {
			cfg.Logger.Error("Ошибка чтения тела запроса для скоупа:", err)
			response.InternalServerError(c, "Ошибка чтения тела запроса")
			c.Abort()
			return
		}
		if raw == "" {
			response.BadRequest(c, fmt.Sprintf("Параметр %s обязателен", rc.ScopeParam))
			c.Abort()
			return
		}
		// UUID сверяется на шлюзе: мусор не долетает до collections и не
		// попадает в ключ кэша.
		if !uuidRe.MatchString(raw) {
			response.BadRequest(c, fmt.Sprintf("Параметр %s не является UUID", rc.ScopeParam))
			c.Abort()
			return
		}

		scopeID := strings.ToLower(raw)
		if rc.ScopeKind != config.ScopeWorkspace {
			// Единственный род — пространство (SDL-620). Иной род в реестре —
			// ошибка конфигурации, отвечаем отказом, а не пропуском.
			cfg.Logger.Errorf("Неизвестный род скоупа %q на %s %s", rc.ScopeKind, c.Request.Method, logsafe.Path(c.Request.URL.Path))
			response.InternalServerError(c, "Ошибка проверки доступа")
			c.Abort()
			return
		}
		// SDL-613 S4: токен пространства — сам источник роли; токен сессии и
		// токен, об отзыве которого не у кого спросить, — живой collections.
		var role string
		if claims := workspaceTokenClaims(c); claims != nil {
			tokenRoleValue, verdict, reason := checkWorkspaceToken(c.Request.Context(), cfg, claims, scopeID)
			switch verdict {
			case tokenUnauthorized:
				cfg.Logger.Warnf("Токен пространства актора %s отвергнут (%s; %s %s)", userIDStr, reason, c.Request.Method, logsafe.Path(c.Request.URL.Path))
				response.Unauthorized(c, "Токен пространства недействителен, обменяйте токен заново")
				c.Abort()
				return
			case tokenMismatch:
				cfg.Logger.Warnf("Токен пространства актора %s выпущен на другое пространство (%s; %s %s)", userIDStr, reason, c.Request.Method, logsafe.Path(c.Request.URL.Path))
				sendForbiddenError(c, cfg, "FORBIDDEN")
				c.Abort()
				return
			case tokenFallback:
				if reason == redisNotConfigured {
					cfg.Logger.Debugf("Отзыв токена пространства не проверен, членство — у collections: %s", reason)
				} else {
					cfg.Logger.Warnf("Отзыв токена пространства не проверен, членство — у collections: %s", reason)
				}
				role, err = resolveWorkspaceRole(cfg, userIDStr, scopeID)
			default:
				role = tokenRoleValue
			}
		} else {
			role, err = resolveWorkspaceRole(cfg, userIDStr, scopeID)
		}
		if err != nil {
			cfg.Logger.Error("Ошибка вызова collections-service для проверки членства:", err)
			response.InternalServerError(c, "Ошибка проверки доступа")
			c.Abort()
			return
		}
		// SDL-617 G2: маршрут с ScopeOwnerOnly пускает только владельца —
		// участник (member) причастен, но отказ. Роль всё равно кладётся в
		// контекст ниже: на этих маршрутах Required:false, и проверка прав
		// её не читает.
		if role == "" || (rc.ScopeOwnerOnly && role != "owner") {
			cfg.Logger.Warnf("Актор %s не допущен к %s %s (роль %q, owner-only=%v; %s %s)",
				userIDStr, rc.ScopeKind, scopeID, role, rc.ScopeOwnerOnly, c.Request.Method, logsafe.Path(c.Request.URL.Path))
			sendForbiddenError(c, cfg, "FORBIDDEN")
			c.Abort()
			return
		}

		c.Set(ScopeHeadersContextKey, map[string]string{HeaderScopeWorkspaceID: scopeID})
		c.Set(WorkspaceScopeContextKey, WorkspaceScope{ID: scopeID, Role: role})
		c.Next()
	}
}

// WorkspaceScopeFromContext возвращает пару «пространство + роль», если её
// сверил ScopeMiddleware. Иначе пустую пару и false.
func WorkspaceScopeFromContext(c *gin.Context) (WorkspaceScope, bool) {
	v, exists := c.Get(WorkspaceScopeContextKey)
	if !exists {
		return WorkspaceScope{}, false
	}
	ws, ok := v.(WorkspaceScope)
	return ws, ok && ws.ID != "" && ws.Role != ""
}

// scopeValue достаёт идентификатор скоупа из строки запроса или JSON-тела.
// Тело читается целиком и возвращается на место: дальше его читает прокси.
// Для строки запроса берётся первое значение — ровно то, что ProxyToService
// отправит апстриму, иначе ?project_id=свой&project_id=чужой разошлись бы.
func scopeValue(c *gin.Context, rc *config.RouteConfig) (string, error) {
	if !rc.ScopeInBody {
		return c.Query(rc.ScopeParam), nil
	}
	if c.Request.Body == nil {
		return "", nil
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return "", err
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))

	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return "", nil
	}
	var v string
	if json.Unmarshal(fields[rc.ScopeParam], &v) != nil {
		return "", nil
	}
	return v, nil
}

// workspaceRoleCacheKey — ключ кэша роли актора в пространстве. Регистр
// обоих id нормализуется ЗДЕСЬ и только здесь (SDL-615 S2): user_id из
// токена приходит как есть, id из пути — как прислал клиент, а ключ у
// ScopeMiddleware и MembershipRevocation обязан совпасть.
func workspaceRoleCacheKey(userID, workspaceID string) string {
	return workspaceRoleCachePrefix + strings.ToLower(userID) + ":" + strings.ToLower(workspaceID)
}

// workspaceRevokedMarkerKey — ключ маркера исключения актора из пространства.
func workspaceRevokedMarkerKey(userID, workspaceID string) string {
	return workspaceRevokedMarkerPrefix + strings.ToLower(userID) + ":" + strings.ToLower(workspaceID)
}

// workspaceGoneMarkerKey — ключ маркера удалённого пространства.
func workspaceGoneMarkerKey(workspaceID string) string {
	return workspaceGoneMarkerPrefix + strings.ToLower(workspaceID)
}

// roleCacheTrusted отвечает, можно ли на этот запрос читать и пополнять кэш
// роли актора в пространстве. Нельзя, пока жив маркер исключения актора или
// удаления пространства (SDL-615 S2). Сбой Redis тоже «нельзя»: кэш, о
// состоянии которого нельзя спросить, не доверенный.
func roleCacheTrusted(ctx context.Context, cfg PermissionMiddlewareConfig, userID, workspaceID string) bool {
	if cfg.RedisService == nil {
		return false
	}
	n, err := cfg.RedisService.Exists(ctx,
		workspaceRevokedMarkerKey(userID, workspaceID),
		workspaceGoneMarkerKey(workspaceID))
	return err == nil && n == 0
}

// resolveWorkspaceRole спрашивает у collections-service участников
// пространства от имени актора и возвращает его роль. Пустая роль — не
// причастен: чужое пространство (404), актор не в списке, любой другой статус
// (fail-closed). Кэшируется только найденная роль: отказ не должен
// переживать выдачу доступа.
//
// При живом маркере исключения или удаления (SDL-615 S2) кэш роли не
// читается И не пишется: запрос исключённого, начатый до удаления, иначе
// вернул бы роль в кэш уже после DEL, и доступ пережил бы исключение на
// срок membershipCacheTTL.
func resolveWorkspaceRole(cfg PermissionMiddlewareConfig, userID, workspaceID string) (string, error) {
	cacheKey := workspaceRoleCacheKey(userID, workspaceID)
	ctx := context.Background()
	cacheTrusted := roleCacheTrusted(ctx, cfg, userID, workspaceID)
	if cacheTrusted {
		if cached, err := cfg.RedisService.Get(ctx, cacheKey); err == nil && cached != "" {
			return cached, nil
		}
	}

	resp, err := cfg.ProxyService.ProxyRequest("collections", http.MethodGet,
		"/api/v1/workspaces/"+workspaceID+"/members", map[string]string{
			"X-User-ID":     userID,
			"X-Service-Key": cfg.Config.Security.ServiceKey,
		}, nil, nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}

	var payload struct {
		Data []struct {
			UserID string `json:"user_id"`
			Role   string `json:"role"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		cfg.Logger.Warnf("Не удалось разобрать участников пространства %s: %v", workspaceID, err)
		return "", nil
	}
	var role string
	for _, m := range payload.Data {
		if strings.EqualFold(m.UserID, userID) {
			role = m.Role
			break
		}
	}
	if role == "" {
		return "", nil
	}

	// Повторная сверка перед записью: маркер мог появиться, пока шёл
	// вопрос к collections. Окно между сверкой и Set остаётся, его
	// закрывает revocationMarkerTTL > membershipCacheTTL.
	if cacheTrusted && roleCacheTrusted(ctx, cfg, userID, workspaceID) {
		if err := cfg.RedisService.Set(ctx, cacheKey, role, membershipCacheTTL); err != nil {
			cfg.Logger.Warnf("Не удалось сохранить роль в пространстве в кэш: %v", err)
		}
	}
	return role, nil
}

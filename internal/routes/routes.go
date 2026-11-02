package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"gateway-service/internal/config"
	"gateway-service/internal/handlers"
	"gateway-service/internal/middleware"
	"gateway-service/internal/proxy"

	// Импорт go-sdk
	sdkMiddleware "gitlab.com/markerloop/go-sdk/pkg/middleware"
	"gitlab.com/markerloop/go-sdk/pkg/redis"
	"gitlab.com/markerloop/go-sdk/pkg/requestid"
)

// paddleWebhookMaxBodyBytes — потолок тела вебхука Paddle (SDL-747). События
// Paddle весят единицы килобайт; 1 MiB — запас и совпадает с замеренным
// потолком тела на ingress (EP-13 §15.1).
const paddleWebhookMaxBodyBytes int64 = 1 << 20

// SetupRoutes настраивает все роуты приложения
func SetupRoutes(r *gin.Engine, proxyHandler *handlers.ProxyHandler, cfg *config.Config, proxyService proxy.ProxyService, redisService *redis.RedisService, log *logrus.Logger) {
	// Middleware из SDK
	// requestid — первым: id должен существовать до логирования и попасть в
	// c.Request.Header, откуда ProxyToService копирует заголовки вниз (SDL-87)
	r.Use(requestid.Middleware())
	r.Use(sdkMiddleware.Recovery(log))
	r.Use(sdkMiddleware.Logger(log))
	// CORS ветвится по пути (SDL-172): публичная плоскость /api/v1/data
	// отвечает Allow-Origin * без credentials (её читают произвольные сайты
	// клиентов, cookies там не используются никогда), всё остальное — прежний
	// allowlist-CORS из SDK.
	r.Use(middleware.SplitCORS(sdkMiddleware.CORS()))
	// SDL-692: Bearer-JWT с непустым aud (MCP access token, SDL-691, тот же
	// ключ) — 401 на ЛЮБОМ маршруте, включая /api/v1/data, где jwtMiddleware
	// нет и токен проверяет collections-service. После CORS — чтобы браузер
	// мог прочитать отказ.
	r.Use(middleware.RejectAudienceTokens())

	// JWT middleware — verify-only RS256 (Phase -1.5).
	jwtMiddleware := sdkMiddleware.JWTMiddleware(sdkMiddleware.JWTConfig{
		PublicKeyPEM: cfg.JWT.PublicKeyPEM,
		Logger:       log,
	})

	// Service-to-service auth middleware
	serviceAuthMiddleware := sdkMiddleware.ServiceToServiceAuth(cfg.Security.ServiceKey)

	// Permission middleware для проверки разрешений
	permissionMiddleware := middleware.PermissionMiddleware(middleware.PermissionMiddlewareConfig{
		Config:       cfg,
		ProxyService: proxyService,
		RedisService: redisService,
		Logger:       log,
	})

	// Scope middleware (SDL-587, EP-121): причастность актора к пространству
	// или проекту, объявленному в записи реестра. Стоит после
	// permissionMiddleware везде, кроме группы pages, где он идёт ПЕРЕД ним и
	// приносит проверке права роль актора в пространстве (SDL-614); маршрут
	// без объявления проходит как раньше.
	scopeMiddleware := middleware.ScopeMiddleware(middleware.PermissionMiddlewareConfig{
		Config:       cfg,
		ProxyService: proxyService,
		RedisService: redisService,
		Logger:       log,
	})

	// Сброс кэша роли после исключения участника / удаления пространства
	// (SDL-615 S2): стоит только на двух DELETE ниже, срабатывает после
	// обработчика и только на 2xx апстрима.
	membershipRevocation := middleware.MembershipRevocation(middleware.PermissionMiddlewareConfig{
		Config:       cfg,
		ProxyService: proxyService,
		RedisService: redisService,
		Logger:       log,
	})

	// SDL-613 S9: граница токена пространства (флаг
	// SCOPE_REQUIRE_WORKSPACE_TOKEN; выключен — оба слоя no-op). wsBoundary
	// стоит СРАЗУ за jwtMiddleware везде, где тот есть: маршрут без него
	// пропустил бы токен пространства как токен сессии
	// (TestEveryJWTRouteHasWorkspaceTokenBoundary). Что значит граница по
	// каждому префиксу — шапка middleware/wsboundary.go.
	boundaryCfg := middleware.PermissionMiddlewareConfig{
		Config:       cfg,
		ProxyService: proxyService,
		RedisService: redisService,
		Logger:       log,
	}
	wsBoundary := middleware.WorkspaceTokenBoundary(boundaryCfg)
	dataWorkspaceTokenGuard := middleware.DataPlaneWorkspaceTokenGuard(boundaryCfg)

	// SDL-692 (EP-20): метаданные OAuth-сервера по RFC 8414. Issuer —
	// апекс контура без пути (auth-service OAUTH_ISSUER), значит документ
	// лежит в корне хоста: апекс отправляет этот путь в шлюз отдельным
	// Ingress (dev-infra). Копия под /api — для хоста api.*, чей ingress
	// переписывает /(.*) -> /api/$1. Анонимно, вне реестра прав.
	r.GET("/.well-known/oauth-authorization-server", proxyHandler.ProxyToService("auth"))

	// API группа
	api := r.Group("/api")
	{
		api.GET("/.well-known/oauth-authorization-server", proxyHandler.ProxyToServicePath("auth", "/.well-known/oauth-authorization-server"))

		// Health check из SDK
		api.GET("/health", sdkMiddleware.HealthCheck("gateway-service", "1.0.0"))

		// Swagger документация сервисов (проксирование)
		docs := api.Group("/docs")
		{
			docs.GET("/auth/swagger/*any", proxyHandler.ProxySwagger("auth"))
			docs.GET("/users/swagger/*any", proxyHandler.ProxySwagger("user"))
			docs.GET("/dictionary/swagger/*any", proxyHandler.ProxySwagger("dictionary"))
			docs.GET("/notifications/swagger/*any", proxyHandler.ProxySwagger("notification"))
			docs.GET("/telegram/swagger/*any", proxyHandler.ProxySwagger("telegram-bot"))
			// SDL-169: спека коллекций для schemathesis-контура (dev-infra
			// tests/schemathesis читает /docs/collections/swagger/doc.json).
			docs.GET("/collections/swagger/*any", proxyHandler.ProxySwagger("collections"))
			// SDL-409 (EP-25): спека files-service для того же контура.
			// Ключ "files" — тот же, что у ProxyHealthCheck ниже и у
			// FILES_SERVICE_URL в конфиге: у сервиса один адрес на все
			// плоскости, и заводить второй ключ ради docs значило бы
			// развести их при первом же переезде.
			docs.GET("/files/swagger/*any", proxyHandler.ProxySwagger("files"))
			// SDL-585 (EP-110): спека pages-service для того же контура. Ключ
			// "pages" — тот же, что у ProxyHealthCheck и у редакторских ручек.
			docs.GET("/pages/swagger/*any", proxyHandler.ProxySwagger("pages"))
		}

		// API v1 роуты
		v1 := api.Group("/v1")
		{
			// Health check endpoints для всех сервисов (без защиты)
			v1.GET("/auth/health", proxyHandler.ProxyHealthCheck("auth"))                  // Health check auth-service
			v1.GET("/users/health", proxyHandler.ProxyHealthCheck("user"))                 // Health check user-service
			v1.GET("/notifications/health", proxyHandler.ProxyHealthCheck("notification")) // Health check notification-service
			v1.GET("/dictionary/health", proxyHandler.ProxyHealthCheck("dictionary"))      // Health check dictionary-service
			v1.GET("/telegram/health", proxyHandler.ProxyHealthCheck("telegram-bot"))      // Health check telegram-bot-service
			v1.GET("/collections/health", proxyHandler.ProxyHealthCheck("collections"))    // Health check collections-service
			v1.GET("/files/health", proxyHandler.ProxyHealthCheck("files"))                // Health check files-service
			// SDL-572 (EP-108): здоровье pages-service — вне защиты и записи в
			// реестре прав не требует. ОТМЕНЕНО с SDL-584 (17 Sep 2026): прежняя
			// оговорка «продуктовых маршрутов редактора здесь пока нет намеренно»
			// перестала быть верной — 29 редакторских ручек (22 + 6 темы, SDL-772, + publish блока, SDL-965) опубликованы ниже,
			// в группе под jwt, реестром прав и скоупом пространства.
			v1.GET("/pages/health", proxyHandler.ProxyHealthCheck("pages")) // Health check pages-service
			// SDL-584 (EP-110): публичная плоскость чтения pages — анонимна по
			// замыслу (опубликованная страница по адресу), поэтому вне
			// jwtMiddleware и permissionMiddleware и без записи в реестре прав.
			// Фильтр «только опубликованное» стоит в запросе pages-service, а не
			// в шлюзе. Редакторские ручки (routes/pages/blocks) — ниже, в
			// группе под jwt, реестром прав и скоупом пространства (SDL-584).
			v1.GET("/pages/public/pages/by-path", proxyHandler.ProxyToService("pages")) // Опубликованная страница по адресу (internal-preview)
			// SDL-684 (EP-113): сайт пространства по хосту — то, что читает
			// рендер поддомена. Анонимна так же, как by-path: вне jwt и
			// permissionMiddleware, без записи в реестре прав и без скоупа
			// пространства — workspace_id клиент не знает, пространство по
			// host находит сам pages-service (через collections by-host).
			v1.GET("/pages/public/site", proxyHandler.ProxyToService("pages")) // Сайт пространства по хосту
			// SDL-772: белый список шрифтов и перечисления темы сайта —
			// статичные данные pages-service, анонимно, как публичная плоскость.
			v1.GET("/pages/public/theme/fonts", proxyHandler.ProxyToService("pages")) // Шрифты и перечисления темы сайта
			// SDL-747 (EP-146): вебхук Paddle — его шлёт Paddle, не человек,
			// поэтому анонимно: вне jwtMiddleware и permissionMiddleware и без
			// записи в реестре прав (реестр читает только permissionMiddleware).
			// Подлинность проверяет collections-service по Paddle-Signature
			// (HMAC над сырым телом), поэтому заголовок и тело уходят вниз как
			// есть. Тело ограничено 1 MiB только здесь: общий ProxyToService
			// читает его в память без лимита, а этот путь открыт всему
			// интернету. Больше — 413 без похода в апстрим.
			v1.POST("/billing/paddle/webhook", proxyHandler.ProxyToServiceWithBodyLimit("collections", paddleWebhookMaxBodyBytes)) // Вебхук Paddle (без JWT)

			// Auth роуты - аутентификация и авторизация
			auth := v1.Group("/auth")
			{
				// Публичные эндпоинты (без защиты)
				auth.POST("/login", proxyHandler.ProxyToService("auth"))       // Вход пользователя
				auth.POST("/register", proxyHandler.ProxyToService("auth"))    // Регистрация пользователя
				auth.POST("/verify", proxyHandler.ProxyToService("auth"))      // Верификация email
				auth.GET("/verify-email", proxyHandler.ProxyToService("auth")) // Подтверждение верификации email по токену
				auth.POST("/refresh", proxyHandler.ProxyToService("auth"))     // Обновление токена
				// SDL-613 S5: выход гасит семью refresh-токена. Публичный
				// намеренно: право выйти даёт владение refresh-токеном из тела,
				// а access к моменту выхода часто уже истёк — требование JWT
				// не дало бы такому человеку выйти. Лимит по IP держит сам
				// auth-service (rl:logout:ip:). В route↔permission-реестр не
				// добавляется: на группе /auth permissionMiddleware нет вовсе.
				auth.POST("/logout", proxyHandler.ProxyToService("auth")) // Выход по refresh-токену (без JWT)
				// SDL-270: досылка письма подтверждения по одному адресу.
				// Публичный намеренно: страницу /email-verify открывает человек,
				// который НЕ вошёл и войти не может — адрес ещё не подтверждён,
				// поэтому защищённый request-email-verification ниже для неё
				// недостижим. Энумерацию и рассылку гасит сам auth-service:
				// ответ одинаков для любого адреса, лимиты по IP и по email
				// в Redis, сверх лимита — то же тело без отправки.
				// В route↔permission-реестр не добавляется: реестр читает
				// permissionMiddleware, а на группе /auth его нет вовсе.
				auth.POST("/resend-verification", proxyHandler.ProxyToService("auth")) // Досылка ссылки подтверждения (без JWT)
				// SDL-462: восстановление пароля. Публичные по той же причине,
				// что и resend-verification выше: человек, забывший пароль,
				// войти не может по определению, поэтому защищённой пары у
				// этих ручек нет. Энумерацию и рассылку гасит auth-service —
				// ответ forgot-password одинаков для любого адреса, лимиты по
				// IP и по email в Redis. В route↔permission-реестр не
				// добавляются: на группе /auth permissionMiddleware нет вовсе.
				auth.POST("/forgot-password", proxyHandler.ProxyToService("auth")) // Запрос ссылки восстановления (без JWT)
				auth.POST("/reset-password", proxyHandler.ProxyToService("auth"))  // Установка нового пароля по токену (без JWT)

				// OAuth эндпоинты (без защиты)
				auth.GET("/google", proxyHandler.ProxyToService("auth"))                   // Google OAuth URL
				auth.POST("/google/callback", proxyHandler.ProxyToService("auth"))         // Google OAuth callback
				auth.POST("/telegram/login", proxyHandler.ProxyToService("auth"))          // Telegram Login Widget (legacy)
				auth.POST("/telegram/login-request", proxyHandler.ProxyToService("auth"))  // Telegram bot login request
				auth.GET("/telegram/login-stream", proxyHandler.ProxySSEToService("auth")) // SSE login status stream
				auth.POST("/telegram/webapp", proxyHandler.ProxyToService("auth"))         // Telegram Mini App auth

				// Защищенные эндпоинты (требуют JWT)
				auth.POST("/request-email-verification", jwtMiddleware, wsBoundary, proxyHandler.ProxyToService("auth")) // Запрос верификации email
				// SDL-321: привязка Telegram к уже вошедшему профилю. auth-service
				// держал роут за своим JWT-middleware с самого начала (config.go
				// называет его причиной, по которой сервису нужен публичный ключ),
				// а шлюз его не публиковал никогда — снаружи ручка отвечала
				// молчаливым Gin-404, тем же, что и /dictionary/cities в SDL-315.
				// В route↔permission-реестр не добавляется по той же причине, что
				// и соседи: permissionMiddleware на группе /auth нет вовсе.
				auth.POST("/telegram/deeplink", jwtMiddleware, wsBoundary, proxyHandler.ProxyToService("auth")) // Deeplink привязки Telegram
				// SDL-613 S3: обмен токена сессии на токен пространства. Тело —
				// {"workspace_id"}; Authorization уходит в auth-service без
				// изменений (ProxyToService копирует заголовки), auth-service
				// сам сверяет членство у collections-service и выпускает токен
				// с claims wsid/wsr. Только jwtMiddleware: пространство здесь —
				// запрашиваемый объект, токена пространства у вызывающего ещё
				// нет, поэтому ни ScopeMiddleware, ни permissionMiddleware
				// (onboarding-класс, как POST /workspaces). В
				// route↔permission-реестр не добавляется по той же причине, что
				// и соседи: permissionMiddleware на группе /auth нет вовсе.
				auth.POST("/token/workspace", jwtMiddleware, wsBoundary, proxyHandler.ProxyToService("auth")) // Обмен токена сессии на токен пространства
			}

			// OAuth 2.1-сервер для MCP-клиентов (SDL-691 в auth-service,
			// публикация — SDL-692). Пути те же, что у auth-service и в его
			// метаданных (issuer + /api/v1/oauth/...), поэтому без переписи.
			// permissionMiddleware на группе нет — как у /auth, записей в
			// route↔permission-реестре нет: клиент MCP приходит без нашего
			// токена (register/authorize/token), а экран согласия — с токеном
			// сессии, право на который даёт само владение сессией.
			//   - register/authorize/token — анонимно; register дополнительно
			//     держит limit-rps на ingress апекса (dev-infra) и лимит
			//     auth-service;
			//   - authorize — без следования редиректам: 302 на согласие или
			//     redirect_uri уходит браузеру как есть;
			//   - requests/approve/deny — JWT сессии; MCP-токен (aud) — 401
			//     ещё в шлюзе, auth-service отвергает его повторно.
			//   - grants (SDL-693, «Connected agents» админки) — так же: JWT
			//     сессии, без прав и без скоупа пространства. Выдачи принадлежат
			//     человеку, а не пространству; свою выдачу и «чужая — 404»
			//     решает auth-service по user_id из токена. Новый пользователь
			//     без единой роли получает [] (bootstrapRoutes держит это).
			// /oauth/exchange НЕ публикуется: только X-Service-Key, вызывает
			// mcp-service по сети кластера (SDL-691; dev-infra gw-contract
			// NEVER_PUBLISHED). TestOAuthExchangeIsNotPublished держит это.
			oauth := v1.Group("/oauth")
			{
				oauth.POST("/register", proxyHandler.ProxyToService("auth"))                                                 // Динамическая регистрация клиента (RFC 7591)
				oauth.GET("/authorize", proxyHandler.ProxyRedirectToService("auth"))                                         // Начало авторизации (302)
				oauth.GET("/authorize/requests/:request_id", jwtMiddleware, wsBoundary, proxyHandler.ProxyToService("auth")) // Запрос на согласие
				oauth.POST("/authorize/approve", jwtMiddleware, wsBoundary, proxyHandler.ProxyToService("auth"))             // Согласие
				oauth.POST("/authorize/deny", jwtMiddleware, wsBoundary, proxyHandler.ProxyToService("auth"))                // Отказ
				oauth.GET("/grants", jwtMiddleware, wsBoundary, proxyHandler.ProxyToService("auth"))                         // Свои выдачи (подключённые агенты)
				oauth.DELETE("/grants/:grant_id", jwtMiddleware, wsBoundary, proxyHandler.ProxyToService("auth"))            // Отзыв своей выдачи
				oauth.POST("/token", proxyHandler.ProxyToService("auth"))                                                    // Обмен кода / refresh
			}

			// User роуты — доступны всем авторизованным (только JWT, без проверки разрешений)
			v1.GET("/users/my/access", jwtMiddleware, wsBoundary, proxyHandler.ProxyToService("user")) // Получить свои роли и разрешения

			// User роуты - управление пользователями (защищены JWT и проверкой разрешений)
			// Важно: специфичные роуты (/email, /username, /my) должны быть ДО параметризованных (/:id)
			users := v1.Group("/users")
			users.Use(jwtMiddleware, wsBoundary, permissionMiddleware)
			{
				// Регистрируем маршруты с явным указанием пути (без слеша в конце группы)
				users.GET("", proxyHandler.ProxyToService("user"))                    // Получить всех пользователей
				users.POST("", proxyHandler.ProxyToService("user"))                   // Создать пользователя
				users.GET("/email/:email", proxyHandler.ProxyToService("user"))       // Получить пользователя по email
				users.GET("/username/:username", proxyHandler.ProxyToService("user")) // Получить пользователя по username
				users.GET("/my", proxyHandler.ProxyToService("user"))                 // Получить свой профиль
				users.PUT("/my", proxyHandler.ProxyToService("user"))                 // Обновить свой профиль
				users.DELETE("/my", proxyHandler.ProxyToService("user"))              // SDL-742: удалить свой аккаунт
				// Журнал принятий правил (SDL-752): своё — замыкание ":own" на
				// чтении, как /my; чужое — право администратора в реестре.
				users.GET("/my/policy-acceptances", proxyHandler.ProxyToService("user"))
				// User roles и permissions маршруты (должны быть до простого /:id)
				users.GET("/:id/roles", proxyHandler.ProxyToService("user"))             // Получить роли пользователя
				users.POST("/:id/roles", proxyHandler.ProxyToService("user"))            // Назначить роль пользователю
				users.DELETE("/:id/roles/:role_id", proxyHandler.ProxyToService("user")) // Удалить роль у пользователя
				users.GET("/:id/permissions", proxyHandler.ProxyToService("user"))       // Получить разрешения пользователя
				// Чужой журнал принятий — у user-service своей проверки нет (SDL-752).
				users.GET("/:id/policy-acceptances", proxyHandler.ProxyToService("user"))
				users.GET("/:id", proxyHandler.ProxyToService("user"))    // Получить пользователя по ID
				users.PUT("/:id", proxyHandler.ProxyToService("user"))    // Обновить пользователя
				users.DELETE("/:id", proxyHandler.ProxyToService("user")) // Удалить пользователя
			}

			// Журнал принятий правил поперёк людей и сводка по редакциям
			// (SDL-752): право users:read:policy_acceptances в реестре — у
			// user-service своей проверки нет, шлюз — единственная защита.
			policyAcceptances := v1.Group("/policy-acceptances")
			policyAcceptances.Use(jwtMiddleware, wsBoundary, permissionMiddleware)
			{
				policyAcceptances.GET("", proxyHandler.ProxyToService("user"))
				policyAcceptances.GET("/summary", proxyHandler.ProxyToService("user"))
			}

			// Roles роуты - управление ролями (защищены JWT и проверкой разрешений)
			roles := v1.Group("/roles")
			roles.Use(jwtMiddleware, wsBoundary, permissionMiddleware)
			{
				roles.GET("", proxyHandler.ProxyToService("user"))  // Получить все роли
				roles.POST("", proxyHandler.ProxyToService("user")) // Создать роль
				// Role permissions маршруты (должны быть до простого /:id)
				roles.GET("/:id/permissions", proxyHandler.ProxyToService("user"))                   // Получить разрешения роли
				roles.POST("/:id/permissions", proxyHandler.ProxyToService("user"))                  // Назначить разрешение роли
				roles.DELETE("/:id/permissions/:permission_id", proxyHandler.ProxyToService("user")) // Удалить разрешение у роли
				roles.GET("/:id", proxyHandler.ProxyToService("user"))                               // Получить роль по ID
				roles.PUT("/:id", proxyHandler.ProxyToService("user"))                               // Обновить роль
				roles.DELETE("/:id", proxyHandler.ProxyToService("user"))                            // Удалить роль
			}

			// Permissions роуты - управление разрешениями (защищены JWT и проверкой разрешений)
			permissions := v1.Group("/permissions")
			permissions.Use(jwtMiddleware, wsBoundary, permissionMiddleware)
			{
				permissions.GET("", proxyHandler.ProxyToService("user"))        // Получить все разрешения
				permissions.POST("", proxyHandler.ProxyToService("user"))       // Создать разрешение
				permissions.GET("/:id", proxyHandler.ProxyToService("user"))    // Получить разрешение по ID
				permissions.PUT("/:id", proxyHandler.ProxyToService("user"))    // Обновить разрешение
				permissions.DELETE("/:id", proxyHandler.ProxyToService("user")) // Удалить разрешение
			}

			// External accounts роуты - управление внешними аккаунтами (защищены JWT и проверкой разрешений)
			externalAccounts := v1.Group("/external-accounts")
			externalAccounts.Use(jwtMiddleware, wsBoundary, permissionMiddleware)
			{
				externalAccounts.POST("", proxyHandler.ProxyToService("user"))              // Создать внешний аккаунт
				externalAccounts.POST("/link", proxyHandler.ProxyToService("user"))         // Привязать внешний аккаунт
				externalAccounts.GET("/user/:user_id", proxyHandler.ProxyToService("user")) // Получить внешние аккаунты пользователя
				externalAccounts.GET("/:id", proxyHandler.ProxyToService("user"))           // Получить внешний аккаунт по ID
				externalAccounts.PUT("/:id", proxyHandler.ProxyToService("user"))           // Обновить внешний аккаунт
				externalAccounts.DELETE("/:id", proxyHandler.ProxyToService("user"))        // Удалить внешний аккаунт
			}

			// Notification роуты - отправка уведомлений (защищены service-to-service)
			notifications := v1.Group("/notifications")
			notifications.Use(serviceAuthMiddleware) // Только сервисы могут отправлять уведомления
			{
				// Email уведомления
				email := notifications.Group("/email")
				{
					email.POST("/send", proxyHandler.ProxyToService("notification"))                // Отправить email
					email.POST("/send-verification", proxyHandler.ProxyToService("notification"))   // Отправить email верификации
					email.POST("/send-welcome", proxyHandler.ProxyToService("notification"))        // Отправить приветственный email
					email.POST("/send-password-reset", proxyHandler.ProxyToService("notification")) // Отправить email сброса пароля
				}

				// Telegram уведомления
				tg := notifications.Group("/telegram")
				{
					tg.POST("/send", proxyHandler.ProxyToService("notification")) // Отправить Telegram сообщение
				}

				// Deploy уведомления (ArgoCD webhook)
				notifications.POST("/deploy", proxyHandler.ProxyToService("notification")) // Deploy notification
			}

			// Dictionary роуты - словарь и локализация (без защиты)
			dictionary := v1.Group("/dictionary")
			{
				dictionary.POST("/error", proxyHandler.ProxyToService("dictionary"))        // Получить локализованную ошибку
				dictionary.GET("/errors", proxyHandler.ProxyToService("dictionary"))        // Получить список всех ошибок
				dictionary.POST("/translations", proxyHandler.ProxyToService("dictionary")) // Получить переводы
				dictionary.GET("/countries", proxyHandler.ProxyToService("dictionary"))     // Получить список стран
				dictionary.GET("/cities", proxyHandler.ProxyToService("dictionary"))        // Получить список городов (SDL-315: было POST, апстрим отдаёт GET)
				dictionary.GET("/languages", proxyHandler.ProxyToService("dictionary"))     // Получить список всех языков
			}

			// Telegram Bot роуты
			telegram := v1.Group("/telegram")
			{
				// Webhook от Telegram
				// Gateway: /api/v1/telegram/webhook -> Telegram Bot Service: /api/v1/webhook/telegram
				// Telegram отправляет secret_token в заголовке X-Telegram-Bot-Api-Secret-Token
				// Gateway передает токен дальше в telegram-bot-service для проверки
				telegram.POST("/webhook", func(c *gin.Context) {
					// Проверяем secret_token от Telegram (если настроен)
					// Telegram всегда отправляет токен в заголовке X-Telegram-Bot-Api-Secret-Token
					secretToken := c.GetHeader("X-Telegram-Bot-Api-Secret-Token")
					if secretToken != "" {
						// Добавляем токен в заголовки для передачи в telegram-bot-service
						// telegram-bot-service может дополнительно проверить токен
						c.Request.Header.Set("X-Telegram-Bot-Api-Secret-Token", secretToken)
					}

					// Переписываем путь для проксирования на правильный endpoint в telegram-bot-service
					originalPath := c.Request.URL.Path
					c.Request.URL.Path = "/api/v1/webhook/telegram"
					proxyHandler.ProxyToService("telegram-bot")(c)
					c.Request.URL.Path = originalPath // Восстанавливаем для логирования
				})

				// OAuth и уведомления (защищены service-to-service)
				telegram.Use(serviceAuthMiddleware)
				{
					// Gateway: /api/v1/telegram/oauth/generate-token -> Telegram Bot Service: /api/v1/oauth/generate-token
					telegram.POST("/oauth/generate-token", func(c *gin.Context) {
						originalPath := c.Request.URL.Path
						c.Request.URL.Path = "/api/v1/oauth/generate-token"
						proxyHandler.ProxyToService("telegram-bot")(c)
						c.Request.URL.Path = originalPath
					})

					// Gateway: /api/v1/telegram/notifications/send -> Telegram Bot Service: /api/v1/notifications/send
					telegram.POST("/notifications/send", func(c *gin.Context) {
						originalPath := c.Request.URL.Path
						c.Request.URL.Path = "/api/v1/notifications/send"
						proxyHandler.ProxyToService("telegram-bot")(c)
						c.Request.URL.Path = originalPath
					})

					// Gateway: /api/v1/telegram/notifications/broadcast -> Telegram Bot Service: /api/v1/notifications/broadcast
					telegram.POST("/notifications/broadcast", func(c *gin.Context) {
						originalPath := c.Request.URL.Path
						c.Request.URL.Path = "/api/v1/notifications/broadcast"
						proxyHandler.ProxyToService("telegram-bot")(c)
						c.Request.URL.Path = originalPath
					})
				}
			}

			// Collections routes (EP-13 / SDL-166). The gateway gives the
			// coarse-grained layer only: jwtMiddleware authenticates and
			// injects X-User-ID, permissionMiddleware enforces registry
			// coverage (all entries Required:false — see
			// internal/config/routes.go). Ownership (workspace →
			// collection → record) is checked by collections-service itself.
			// permissionMiddleware is attached deliberately even though every
			// entry is Required:false: without it the registry entries are
			// never read and routes_test.go's coverage sweep is vacuous.
			workspaces := v1.Group("/workspaces")
			workspaces.Use(jwtMiddleware, wsBoundary, permissionMiddleware, scopeMiddleware)
			{
				workspaces.GET("", proxyHandler.ProxyToService("collections"))                              // Список workspace актора
				workspaces.POST("", proxyHandler.ProxyToService("collections"))                             // Создать workspace
				workspaces.GET("/name-check", proxyHandler.ProxyToService("collections"))                   // Свободен ли адрес (SDL-758, Required:false — до первого пространства)
				workspaces.GET("/:id", proxyHandler.ProxyToService("collections"))                          // Получить workspace
				workspaces.PATCH("/:id", proxyHandler.ProxyToService("collections"))                        // Обновить workspace
				workspaces.DELETE("/:id", membershipRevocation, proxyHandler.ProxyToService("collections")) // Удалить workspace (+ маркер workspace_gone, SDL-615 S2)
				workspaces.POST("/:id/restore", proxyHandler.ProxyToService("collections"))                 // Восстановить из корзины (SDL-660)
				workspaces.GET("/:id/usage", proxyHandler.ProxyToService("collections"))                    // Расход счётных лимитов (SDL-661/SDL-664)
				workspaces.POST("/:id/billing/checkout", proxyHandler.ProxyToService("collections"))        // Переход на Pro через Paddle Checkout (SDL-748); владельца проверяет collections
				workspaces.GET("/:id/billing", proxyHandler.ProxyToService("collections"))                  // Состояние оплаты и ожидающая транзакция (SDL-748); участника проверяет collections
				workspaces.POST("/:id/billing/portal", proxyHandler.ProxyToService("collections"))          // Портал покупателя Paddle (SDL-749); владельца проверяет collections

				// Участники workspace (SDL-609): видимость workspace — членство,
				// а не owner_user_id. Роль и причастность проверяет
				// collections-service.
				workspaces.GET("/:id/members", proxyHandler.ProxyToService("collections"))                                   // Участники workspace
				workspaces.PUT("/:id/members", proxyHandler.ProxyToService("collections"))                                   // Добавить участника (upsert)
				workspaces.DELETE("/:id/members/:user_id", membershipRevocation, proxyHandler.ProxyToService("collections")) // Исключить участника (+ сброс кэша роли, SDL-615 S2)

				// Приглашения в workspace (SDL-615 S6): владелец приглашает по
				// почте, collections-service проверяет роль и причастность.
				workspaces.GET("/:id/invites", proxyHandler.ProxyToService("collections"))                    // Приглашения workspace
				workspaces.POST("/:id/invites", proxyHandler.ProxyToService("collections"))                   // Пригласить по почте
				workspaces.POST("/:id/invites/:invite_id/resend", proxyHandler.ProxyToService("collections")) // Отправить письмо заново (новый токен)
				workspaces.DELETE("/:id/invites/:invite_id", proxyHandler.ProxyToService("collections"))      // Отозвать приглашение

				// Роли и токены workspace (SDL-617a/SDL-620a): пока у
				// пространства один проект, collections-service делегирует ему.
				workspaces.GET("/:id/roles", proxyHandler.ProxyToService("collections"))                    // Роли workspace
				workspaces.POST("/:id/roles", proxyHandler.ProxyToService("collections"))                   // Создать роль
				workspaces.PATCH("/:id/roles/:role_id", proxyHandler.ProxyToService("collections"))         // Обновить роль
				workspaces.DELETE("/:id/roles/:role_id", proxyHandler.ProxyToService("collections"))        // Удалить роль
				workspaces.GET("/:id/tokens", proxyHandler.ProxyToService("collections"))                   // Токены workspace
				workspaces.POST("/:id/tokens", proxyHandler.ProxyToService("collections"))                  // Выпустить токен
				workspaces.POST("/:id/tokens/:token_id/rotate", proxyHandler.ProxyToService("collections")) // Ротация токена
				workspaces.DELETE("/:id/tokens/:token_id", proxyHandler.ProxyToService("collections"))      // Отозвать токен
			}

			// Ручки получателя приглашения (SDL-615 S6): любой вошедший, до
			// принятия он ещё не участник пространства. Без scopeMiddleware —
			// скоуп резолвить не по чему, а Required:true здесь означал бы
			// тупик первого входа (bootstrapRoutes в routes_test.go).
			invites := v1.Group("/invites")
			invites.Use(jwtMiddleware, wsBoundary, permissionMiddleware)
			{
				invites.POST("/preview", proxyHandler.ProxyToService("collections")) // Что за приглашение (не гасит токен)
				invites.POST("/accept", proxyHandler.ProxyToService("collections"))  // Принять приглашение
			}

			// Группы /api/v1/projects больше нет (SDL-620): с SDL-617b
			// «workspace = проект», collections-service эти пути не обслуживает,
			// а роли, токены и участники живут под /workspaces/:id/*. Маршрут без
			// записи в реестре отвечает 403 — отсутствие записей и есть закрытая
			// поверхность (TestGatewayPublishesNoProjectsRoutes).

			collections := v1.Group("/collections")
			collections.Use(jwtMiddleware, wsBoundary, permissionMiddleware, scopeMiddleware)
			{
				collections.GET("", proxyHandler.ProxyToService("collections"))        // Список коллекций проекта
				collections.POST("", proxyHandler.ProxyToService("collections"))       // Создать коллекцию
				collections.GET("/:id", proxyHandler.ProxyToService("collections"))    // Получить коллекцию
				collections.PATCH("/:id", proxyHandler.ProxyToService("collections"))  // Обновить коллекцию
				collections.DELETE("/:id", proxyHandler.ProxyToService("collections")) // Удалить коллекцию
				// Поля: плейсхолдеры в одном пути обязаны различаться (:id/:field_id),
				// иначе c.Param("id") неоднозначен.
				collections.GET("/:id/fields", proxyHandler.ProxyToService("collections"))               // Поля коллекции
				collections.POST("/:id/fields", proxyHandler.ProxyToService("collections"))              // Добавить поле
				collections.PATCH("/:id/fields/:field_id", proxyHandler.ProxyToService("collections"))   // Обновить поле
				collections.DELETE("/:id/fields/:field_id", proxyHandler.ProxyToService("collections"))  // Удалить поле
				collections.GET("/:id/indexes", proxyHandler.ProxyToService("collections"))              // Индексы коллекции (SDL-211)
				collections.POST("/:id/indexes", proxyHandler.ProxyToService("collections"))             // Создать индекс
				collections.DELETE("/:id/indexes/:index_id", proxyHandler.ProxyToService("collections")) // Удалить индекс
				// Гранты коллекции (SDL-306): роль × коллекция → права на
				// плоскости /data. Плейсхолдер :grant_id отличается от :id по
				// той же причине, что и :field_id/:index_id выше.
				collections.GET("/:id/grants", proxyHandler.ProxyToService("collections"))              // Гранты коллекции
				collections.POST("/:id/grants", proxyHandler.ProxyToService("collections"))             // Выдать грант
				collections.PATCH("/:id/grants/:grant_id", proxyHandler.ProxyToService("collections"))  // Изменить грант
				collections.DELETE("/:id/grants/:grant_id", proxyHandler.ProxyToService("collections")) // Отозвать грант
			}

			// Публичная плоскость коллекций (EP-13 §11.3, SDL-172):
			// /api/v1/data/:workspace/:collection[/:record_id] — ЕДИНСТВЕННАЯ
			// группа шлюза БЕЗ jwtMiddleware и БЕЗ permissionMiddleware, и это
			// не упрощение, а единственная форма, проходящая через шлюз:
			// анонима permissionMiddleware не пустит (он 401-ит до проверки
			// флага Required), а второй сегмент — key коллекции, произвольная
			// строка, — несовместим с normalizePath: маршрут не свернулся бы в
			// запись реестра и падал бы в fail-safe 403. Записи в реестре не
			// требуются: реестр читается только permissionMiddleware, которого
			// здесь нет.
			//
			// Первый сегмент — UUID пространства (SDL-618 S2). Шлюз его не
			// разбирает и не проверяет: форму решает collections-service,
			// старые UUID и slug проекта он пока резолвит (срок — замер
			// SDL-618). Имя сайта вместо UUID придёт хостом в EP-113, не
			// новым сегментом этого пути.
			//
			// Личность на этой плоскости выводит collections-service — ТОЛЬКО
			// из Authorization (mlp_-токен или JWT), который проксируется как
			// есть. Клиентский X-User-ID вычищается в sanitizeUpstreamHeaders
			// (EP-13 §11.4), а свой gw сюда не инжектит: jwtMiddleware нет,
			// user_id в контексте не появляется. Wildcard вместо
			// перечисления форм пути: не-GET/POST методы собственные роуты
			// collections-service отвергнут сами (404), а будущие формы v2 не
			// потребуют правки шлюза.
			v1.Any("/data/*path", dataWorkspaceTokenGuard, proxyHandler.ProxyToService("collections"))

			records := v1.Group("/records")
			records.Use(jwtMiddleware, wsBoundary, permissionMiddleware, scopeMiddleware)
			{
				records.GET("", proxyHandler.ProxyToService("collections"))        // Список записей коллекции
				records.POST("", proxyHandler.ProxyToService("collections"))       // Создать запись
				records.GET("/:id", proxyHandler.ProxyToService("collections"))    // Получить запись
				records.PATCH("/:id", proxyHandler.ProxyToService("collections"))  // Обновить запись
				records.DELETE("/:id", proxyHandler.ProxyToService("collections")) // Удалить запись
			}

			// Файлы (EP-25 Ф7, SDL-359). Через шлюз идёт ТОЛЬКО управляющая
			// плоскость: метаданные, выдача presigned-ссылок, CRUD.
			//
			// Чего здесь намеренно НЕТ, и это не пропуск:
			//   • PUT самих байтов — он идёт по presigned-ссылке ПРЯМО в
			//     бакет, мимо шлюза. Замеренный потолок тела на ingress —
			//     1 MiB, а gw при одной реплике читает тело в память
			//     целиком (EP-13 §15.1);
			//   • плоскость выдачи /files/:id — она cache-friendly и
			//     адресуется отдельно (EP-25 Ф4). Пустить трафик картинок
			//     через шлюз значит снова сделать его узким местом, теперь
			//     на статике;
			//   • /internal/v1/files/links — межсервисная ручка, её зовёт
			//     collections-service внутри кластера (прецедент SDL-323).
			//
			// Предикат workspace_id в files-service — скоуп, а не проверка: он
			// не говорит, твоё ли пространство. Причастность актора сверяет
			// scopeMiddleware по объявлению в реестре (SDL-587, EP-121): с G2
			// (SDL-617) — по пространству и только для роли owner
			// (ScopeOwnerOnly), вниз уходит один X-Scope-Workspace-ID;
			// проектного рода скоупа нет (SDL-620). Записи реестра — Required: false,
			// как у коллекций: права на маршрут тут ни при чём, поэтому порядок
			// jwt → permission → scope здесь безопасен — permissionMiddleware
			// выходит до похода в user-service.
			files := v1.Group("/files")
			files.Use(jwtMiddleware, wsBoundary, permissionMiddleware, scopeMiddleware)
			{
				files.POST("/upload-url", proxyHandler.ProxyToService("files"))   // Шаг 1 загрузки: проверки, дедуп, presigned PUT
				files.POST("/:id/complete", proxyHandler.ProxyToService("files")) // Шаг 3: истина о байтах, перевод в ready
				files.GET("", proxyHandler.ProxyToService("files"))               // Список файлов проекта (библиотека)
				files.GET("/:id", proxyHandler.ProxyToService("files"))           // Метаданные файла
				files.PATCH("/:id", proxyHandler.ProxyToService("files"))         // Имя и публичность
				files.DELETE("/:id", proxyHandler.ProxyToService("files"))        // Мягкое удаление; 409 при живых ссылках
				files.GET("/:id/url", proxyHandler.ProxyToService("files"))       // Ссылка на файл: presigned приватному, стабильный путь публичному
				files.GET("/:id/links", proxyHandler.ProxyToService("files"))     // Где используется файл: ссылки с source live/history (SDL-649)
				files.POST("/:id/replace", proxyHandler.ProxyToService("files"))  // Заменить файл во всех живых местах (SDL-651)
				files.GET("/usage", proxyHandler.ProxyToService("files"))         // Расход квот пространства (SDL-663/SDL-664); статика рядом с /:id — gin разводит сам
			}

			// Редактор pages (SDL-584, EP-110): адреса, страницы, блоки и их
			// журналы ревизий. Опубликованы только после того, как шлюз начал
			// сверять причастность актора к пространству (SDL-587, EP-121), а
			// pages-service — брать пространство из X-Scope-Workspace-ID
			// (SDL-589). До этого любой вошедший, зная чужой workspace_id,
			// читал бы и правил чужие страницы. Записи реестра — со скоупом
			// workspace_id, как у файлов; апстрим отвечает на тот же путь
			// /api/v1/pages/... (pages-service routes.go).
			//
			// Порядок слоёв здесь jwt → scope → permission, и ТОЛЬКО здесь
			// (SDL-614, EP-111): записи реестра — Required: true, право
			// pages:* в user-service уровня workspace и требует роли актора в
			// пространстве. Роль резолвит scopeMiddleware по workspace_members
			// collections-service и кладёт в контекст вместе с пространством;
			// permissionMiddleware берёт пару оттуда, а не из запроса. Стой
			// permission раньше scope — в проверку уехало бы пустое или
			// заявленное клиентом пространство. Остальные группы порядок не
			// меняют: у них права платформенные или Required: false.
			//
			// Имя :n у номера ревизии — то же, что в сервисе; в реестре он
			// записан литералом :param (см. комментарий в config/routes.go).
			pages := v1.Group("/pages")
			pages.Use(jwtMiddleware, wsBoundary, scopeMiddleware, permissionMiddleware)
			{
				pages.POST("/routes", proxyHandler.ProxyToService("pages"))        // Создать адрес
				pages.GET("/routes", proxyHandler.ProxyToService("pages"))         // Адреса пространства
				pages.GET("/routes/by-path", proxyHandler.ProxyToService("pages")) // Адрес по пути
				pages.GET("/routes/:id", proxyHandler.ProxyToService("pages"))     // Адрес
				pages.PATCH("/routes/:id", proxyHandler.ProxyToService("pages"))   // Изменить адрес (с version)
				pages.DELETE("/routes/:id", proxyHandler.ProxyToService("pages"))  // Удалить адрес

				pages.POST("/pages", proxyHandler.ProxyToService("pages"))                          // Создать страницу
				pages.GET("/pages", proxyHandler.ProxyToService("pages"))                           // Страницы пространства
				pages.GET("/pages/:id", proxyHandler.ProxyToService("pages"))                       // Страница
				pages.PATCH("/pages/:id", proxyHandler.ProxyToService("pages"))                     // Изменить страницу (с version)
				pages.DELETE("/pages/:id", proxyHandler.ProxyToService("pages"))                    // Удалить страницу
				pages.GET("/pages/:id/revisions", proxyHandler.ProxyToService("pages"))             // Журнал ревизий страницы
				pages.GET("/pages/:id/revisions/:n", proxyHandler.ProxyToService("pages"))          // Ревизия страницы
				pages.POST("/pages/:id/revisions/:n/restore", proxyHandler.ProxyToService("pages")) // Восстановить ревизию страницы

				pages.POST("/blocks", proxyHandler.ProxyToService("pages"))                          // Создать блок
				pages.GET("/blocks", proxyHandler.ProxyToService("pages"))                           // Блоки пространства
				pages.GET("/blocks/:id", proxyHandler.ProxyToService("pages"))                       // Блок
				pages.PATCH("/blocks/:id", proxyHandler.ProxyToService("pages"))                     // Изменить блок (с version)
				pages.DELETE("/blocks/:id", proxyHandler.ProxyToService("pages"))                    // Удалить блок
				pages.GET("/blocks/:id/revisions", proxyHandler.ProxyToService("pages"))             // Журнал ревизий блока
				pages.GET("/blocks/:id/revisions/:n", proxyHandler.ProxyToService("pages"))          // Ревизия блока
				pages.POST("/blocks/:id/revisions/:n/restore", proxyHandler.ProxyToService("pages")) // Восстановить ревизию блока
				pages.POST("/blocks/:id/publish", proxyHandler.ProxyToService("pages"))              // Выкатить Компонент на выбранные страницы (SDL-965)

				// Тема сайта (SDL-772).
				pages.GET("/theme", proxyHandler.ProxyToService("pages"))                       // Черновик темы
				pages.PATCH("/theme", proxyHandler.ProxyToService("pages"))                     // Правка черновика темы (частичная)
				pages.POST("/theme/publish", proxyHandler.ProxyToService("pages"))              // Опубликовать тему
				pages.GET("/theme/revisions", proxyHandler.ProxyToService("pages"))             // Журнал ревизий темы
				pages.GET("/theme/revisions/:n", proxyHandler.ProxyToService("pages"))          // Ревизия темы
				pages.POST("/theme/revisions/:n/restore", proxyHandler.ProxyToService("pages")) // Ревизия темы → черновик

				pages.GET("/usage", proxyHandler.ProxyToService("pages")) // Расход квот пространства (SDL-662/SDL-664); в реестре Required: false
			}
		}
	}
}

package middleware

// SDL-613 S9 (EP-111): токен пространства — граница на всём шлюзе, а на
// маршрутах со скоупом принимается только он. Включается флагом
// SCOPE_REQUIRE_WORKSPACE_TOKEN (config.Scope.RequireWorkspaceToken);
// выключен — оба слоя этого файла пропускают всё, поведение как до S9.
//
// Что значит «граница» по маршрутам (флаг включён):
//
//   - маршрут со скоупом (в реестре объявлен ScopeParam: редактор pages и
//     /pages/usage, все /files*): токен сессии — 401 workspace_token_required,
//     дальше запрос не идёт; токен пространства проходит в ScopeMiddleware,
//     который сверяет wsid и отметку отзыва, как с S4;
//   - /api/v1/workspaces/:id и всё под ним: wsid обязан совпасть с :id (иначе
//     403), токен не гашен отметкой (иначе 401). Право на действие по-прежнему
//     решает collections-service по X-User-ID; /members шлюз не спрашивает;
//   - GET /api/v1/collections?workspace_id= и POST /api/v1/collections
//     (workspace_id в теле): wsid обязан совпасть с названным пространством;
//   - /api/v1/collections/:id… и /api/v1/records…: пространство объекта
//     шлюзу не видно (его знает только collections-service), поэтому
//     сверяется сам токен — форма, срок, отметка отзыва; чей объект, решает
//     collections по X-User-ID. Граница здесь неполная, это вопрос к
//     collections-service, а не к шлюзу;
//   - все прочие маршруты за jwtMiddleware — действия над учёткой, а не над
//     одним пространством (/workspaces без id,
//     /invites/*, /users*, /roles*, /permissions*, /external-accounts*,
//     /auth/* и /oauth/* с JWT): токен пространства — 403
//     account_session_required, тот же код, что у auth-service
//     (RequireAccountSession). Новый маршрут за jwtMiddleware по умолчанию
//     попадает сюда же — закрыт для токена пространства;
//   - /api/v1/data/* (без jwtMiddleware, слой DataPlaneWorkspaceTokenGuard):
//     токен пространства — 403 account_session_required. collections-service
//     принял бы его как пользователя целиком (DataPrincipal не смотрит wsid).
//
// Токен сессии вне маршрутов со скоупом идёт как раньше: вход, обмен токена,
// первое пространство, список своих пространств, /users/my*, приглашения —
// всё, что нужно новому пользователю до первого обмена, токена пространства
// не требует (bootstrap-тупик, docs/guardrails.md).

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"gateway-service/internal/config"

	"gitlab.com/markerloop/go-sdk/pkg/response"
)

const (
	// WorkspaceTokenRequiredCode — токен сессии на маршруте со скоупом.
	// Клиент обменивает токен сессии (POST /api/v1/auth/token/workspace) и
	// повторяет запрос.
	WorkspaceTokenRequiredCode = "workspace_token_required"
	// AccountSessionRequiredCode — токен пространства там, где действие идёт
	// над учёткой. Код совпадает с auth-service (session_guard.go).
	AccountSessionRequiredCode = "account_session_required"

	// workspaceTokenScopeContextKey — WorkspaceScope из токена пространства,
	// сверенного WorkspaceTokenBoundary на /workspaces/:id (роль из wsr,
	// отметки отзыва нет). Читает MembershipRevocation, чтобы не спрашивать
	// роль у collections. Не WorkspaceScopeContextKey: тот читает
	// permissionMiddleware, а на /workspaces пара в проверку права не уходит.
	workspaceTokenScopeContextKey = "workspace_token_scope"

	workspacePathPrefix = "/api/v1/workspaces/:id"
	collectionsRoot     = "/api/v1/collections"
	recordsRoot         = "/api/v1/records"
)

// boundaryKind — как токен пространства сверяется на маршруте без скоупа.
type boundaryKind int

const (
	// boundaryAccount — действие над учёткой: токен пространства — 403.
	boundaryAccount boundaryKind = iota
	// boundaryNamed — пространство названо в запросе: wsid обязан совпасть.
	boundaryNamed
	// boundaryTokenOnly — пространство объекта шлюзу не видно: сверяется
	// только сам токен.
	boundaryTokenOnly
)

// requireWorkspaceToken — включён ли S9.
func requireWorkspaceToken(cfg PermissionMiddlewareConfig) bool {
	return cfg.Config != nil && cfg.Config.Scope.RequireWorkspaceToken
}

func passThrough(c *gin.Context) { c.Next() }

// WorkspaceTokenBoundary — слой S9 сразу за jwtMiddleware на каждом
// маршруте, который его требует (routes.go). Флаг выключен — no-op.
func WorkspaceTokenBoundary(cfg PermissionMiddlewareConfig) gin.HandlerFunc {
	if !requireWorkspaceToken(cfg) {
		return passThrough
	}
	if cfg.Logger != nil {
		cfg.Logger.Info("SCOPE_REQUIRE_WORKSPACE_TOKEN=true: на маршрутах со скоупом принимается только токен пространства, вне них он — граница своего пространства")
	}
	return func(c *gin.Context) {
		rc := lookupRouteConfig(c.Request.Method, normalizePath(c.Request.URL.Path))
		scoped := rc != nil && rc.ScopeParam != ""
		claims := workspaceTokenClaims(c)
		if claims == nil {
			if scoped {
				response.Error(c, http.StatusUnauthorized,
					"Нужен токен пространства: обменяйте токен сессии (POST /api/v1/auth/token/workspace)",
					WorkspaceTokenRequiredCode)
				c.Abort()
				return
			}
			c.Next()
			return
		}
		if scoped {
			// wsid и отзыв сверит ScopeMiddleware.
			c.Next()
			return
		}

		userID, _ := c.Get("user_id")
		userIDStr, _ := userID.(string)
		wsid, _, err := claims.WorkspaceScope()
		if err != nil {
			cfg.Logger.Warnf("Токен пространства актора %s отвергнут (%v; %s %s)", userIDStr, err, c.Request.Method, c.FullPath())
			response.Unauthorized(c, "Токен пространства недействителен, обменяйте токен заново")
			c.Abort()
			return
		}

		kind, target, err := boundaryTarget(c, wsid)
		if err != nil {
			cfg.Logger.Error("Ошибка чтения тела запроса для границы токена пространства:", err)
			response.InternalServerError(c, "Ошибка чтения тела запроса")
			c.Abort()
			return
		}
		if kind == boundaryAccount {
			cfg.Logger.Warnf("Токен пространства актора %s на маршруте учётки (%s %s)", userIDStr, c.Request.Method, c.FullPath())
			response.Error(c, http.StatusForbidden, "Нужен токен сессии, а не токен пространства", AccountSessionRequiredCode)
			c.Abort()
			return
		}

		role, verdict, reason := checkWorkspaceToken(c.Request.Context(), cfg, claims, target)
		switch verdict {
		case tokenUnauthorized:
			cfg.Logger.Warnf("Токен пространства актора %s отвергнут (%s; %s %s)", userIDStr, reason, c.Request.Method, c.FullPath())
			response.Unauthorized(c, "Токен пространства недействителен, обменяйте токен заново")
			c.Abort()
			return
		case tokenMismatch:
			cfg.Logger.Warnf("Токен пространства актора %s выпущен на другое пространство (%s; %s %s)", userIDStr, reason, c.Request.Method, c.FullPath())
			sendForbiddenError(c, cfg, "FORBIDDEN")
			c.Abort()
			return
		case tokenFallback:
			// Об отзыве спросить не у кого. Право решает collections по
			// X-User-ID — тот же источник истины, что и для токена сессии.
			if reason != redisNotConfigured {
				cfg.Logger.Warnf("Отзыв токена пространства не проверен, решает collections: %s", reason)
			}
		default:
			if strings.HasPrefix(c.FullPath(), workspacePathPrefix) {
				c.Set(workspaceTokenScopeContextKey, WorkspaceScope{ID: target, Role: role})
			}
		}
		c.Next()
	}
}

// boundaryTarget — род сверки и пространство, с которым сверяется wsid
// (в нижнем регистре). Маршрут определяется по шаблону Gin, а не по пути.
func boundaryTarget(c *gin.Context, wsid string) (boundaryKind, string, error) {
	fullPath := c.FullPath()
	switch {
	case fullPath == workspacePathPrefix || strings.HasPrefix(fullPath, workspacePathPrefix+"/"):
		return boundaryNamed, strings.ToLower(c.Param("id")), nil
	case fullPath == collectionsRoot:
		raw, err := scopeValue(c, &config.RouteConfig{
			ScopeParam:  "workspace_id",
			ScopeInBody: c.Request.Method != http.MethodGet,
		})
		if err != nil {
			return boundaryAccount, "", err
		}
		if raw == "" {
			// Без workspace_id collections ответит 400 сам.
			return boundaryTokenOnly, wsid, nil
		}
		return boundaryNamed, strings.ToLower(raw), nil
	case strings.HasPrefix(fullPath, collectionsRoot+"/"),
		fullPath == recordsRoot, strings.HasPrefix(fullPath, recordsRoot+"/"):
		return boundaryTokenOnly, wsid, nil
	}
	return boundaryAccount, "", nil
}

// workspaceTokenRoleFor — роль из токена пространства, если
// WorkspaceTokenBoundary сверил его именно на это пространство.
func workspaceTokenRoleFor(c *gin.Context, workspaceID string) string {
	v, ok := c.Get(workspaceTokenScopeContextKey)
	if !ok {
		return ""
	}
	ws, _ := v.(WorkspaceScope)
	if ws.ID == "" || !strings.EqualFold(ws.ID, workspaceID) {
		return ""
	}
	return ws.Role
}

// tokenHasWorkspaceID — у Bearer-JWT из заголовка есть непустой wsid.
// Подпись не проверяется: гард только отказывает.
func tokenHasWorkspaceID(authHeader string) bool {
	claims := unverifiedBearerClaims(authHeader)
	if claims == nil {
		return false
	}
	raw, ok := claims["wsid"]
	if !ok {
		return false
	}
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null" && s != `""`
}

// DataPlaneWorkspaceTokenGuard — граница S9 на /api/v1/data/*: там нет
// jwtMiddleware, токен проверяет collections-service и видит в токене
// пространства просто пользователя. Флаг выключен — no-op.
func DataPlaneWorkspaceTokenGuard(cfg PermissionMiddlewareConfig) gin.HandlerFunc {
	if !requireWorkspaceToken(cfg) {
		return passThrough
	}
	return func(c *gin.Context) {
		if tokenHasWorkspaceID(c.GetHeader("Authorization")) {
			response.Error(c, http.StatusForbidden, "Нужен токен сессии или ключ доступа, а не токен пространства", AccountSessionRequiredCode)
			c.Abort()
			return
		}
		c.Next()
	}
}

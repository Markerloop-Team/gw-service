package middleware

// SDL-613 S4 (EP-111): членство уезжает в токен. Токен пространства
// (auth POST /auth/token/workspace, S3) несёт wsid — пространство, wsr —
// роль актора в нём, и iat, по которому его гасит отметка отзыва. Шлюз
// читает двойным путём:
//
//   - токен с wsid — источник пространства и роли сам токен: wsid обязан
//     совпасть с workspace_id запроса (иначе 403), токен не гашен отметкой
//     отзыва wsrev:v1 / wsgone:v1 (иначе 401). collections не спрашивается;
//   - токен без wsid (токен сессии) — прежний путь resolveWorkspaceRole:
//     GET collections /workspaces/{id}/members + минутный кэш роли.
//
// Отметки читаются одним MGet (wsaccess.Store.IsRevoked). Redis не ответил
// или отметка нечитаема — не 503, а откат на живой collections: безопасно
// (членство спрашивается у источника истины) и не роняет редактор вместе с
// Redis. Обязательность токена пространства и граница вне маршрутов со
// скоупом — S9, wsboundary.go (флаг SCOPE_REQUIRE_WORKSPACE_TOKEN).

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"

	sdkjwt "gitlab.com/markerloop/go-sdk/pkg/jwt"
	"gitlab.com/markerloop/go-sdk/pkg/wsaccess"
)

// jwtClaimsContextKey — ключ, под которым go-sdk JWTMiddleware кладёт
// *jwt.Claims проверенного токена.
const jwtClaimsContextKey = "jwt_claims"

// redisNotConfigured — reason отката без Redis: о нём предупреждают один
// раз при сборке слоя (ScopeMiddleware), а не на каждый запрос.
const redisNotConfigured = "Redis не настроен"

// tokenVerdict — чем кончилась сверка токена пространства.
type tokenVerdict int

const (
	// tokenRole — роль взята из токена, collections не нужен.
	tokenRole tokenVerdict = iota
	// tokenFallback — токен в порядке, но об отзыве спросить не у кого
	// (Redis не ответил или не настроен): роль — у живого collections.
	tokenFallback
	// tokenUnauthorized — токен гашен отметкой или кривой: 401, клиент
	// обменивает токен сессии заново.
	tokenUnauthorized
	// tokenMismatch — токен выпущен на другое пространство: 403.
	tokenMismatch
)

// workspaceTokenClaims — claims токена пространства из контекста, либо nil
// (токена сессии, отсутствия claims).
func workspaceTokenClaims(c *gin.Context) *sdkjwt.Claims {
	v, ok := c.Get(jwtClaimsContextKey)
	if !ok {
		return nil
	}
	claims, _ := v.(*sdkjwt.Claims)
	if !claims.IsWorkspaceToken() {
		return nil
	}
	return claims
}

// checkWorkspaceToken сверяет токен пространства с пространством запроса
// (scopeID — уже в нижнем регистре) и отметками отзыва. reason — для лога.
func checkWorkspaceToken(ctx context.Context, cfg PermissionMiddlewareConfig, claims *sdkjwt.Claims, scopeID string) (role string, verdict tokenVerdict, reason string) {
	// Строгая форма: wsid и user_id равны каноническому UUID, wsr — из
	// закрытого списка. Иная запись id прошла бы мимо ключа отметки.
	wsid, wsr, err := claims.WorkspaceScope()
	if err != nil {
		return "", tokenUnauthorized, err.Error()
	}
	if claims.IssuedAt == nil || claims.ExpiresAt == nil {
		return "", tokenUnauthorized, "нет iat или exp"
	}
	iat, exp := claims.IssuedAt.Time, claims.ExpiresAt.Time
	// Токен длиннее WorkspaceTokenTTL выпущен не обменом и пережил бы
	// отметку отзыва (она живёт RevocationTTL); iat из будущего прошёл бы
	// любую отметку, поставленную «сейчас».
	if !wsaccess.LifetimeWithinTokenTTL(iat, exp) {
		return "", tokenUnauthorized, "exp - iat больше WorkspaceTokenTTL"
	}
	if wsaccess.IssuedInFuture(iat, time.Now()) {
		return "", tokenUnauthorized, "iat в будущем"
	}
	if wsid != scopeID {
		return "", tokenMismatch, "wsid " + wsid + " != " + scopeID
	}
	if cfg.RedisService == nil {
		return "", tokenFallback, redisNotConfigured
	}
	revoked, err := wsaccess.NewStore(cfg.RedisService).IsRevoked(ctx, claims.UserID, wsid, iat)
	if err != nil {
		return "", tokenFallback, "отметки отзыва не прочитаны: " + err.Error()
	}
	if revoked {
		return "", tokenUnauthorized, "токен гашен отметкой отзыва"
	}
	return string(wsr), tokenRole, ""
}

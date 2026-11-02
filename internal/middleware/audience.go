package middleware

// SDL-692 (EP-20): шлюз не принимает токен, выпущенный для другого
// получателя. MCP access token (auth-service SDL-691) подписан тем же
// RS256-ключом, что и токен сессии, и отличается только claim `aud`
// (= OAUTH_MCP_AUDIENCE). До go-sdk v0.36.0 JWTMiddleware `aud` не смотрел,
// поэтому без этого слоя MCP-токен проходил бы на любой маршрут шлюза.
//
// Токены сессии и пространства выпускаются без `aud` и идут как раньше.
// Гард стоит на всём роутере (routes.SetupRoutes, r.Use), ПЕРЕД проверкой
// подписи, и читает `aud` без неё: он только
// отказывает и никогда не пропускает — токен без `aud` всё равно уходит в
// полную проверку go-sdk, а токен с `aud` получает 401 подписан он или нет.
// go-sdk v0.36.0 получил такой же гард (jwt.RejectAudience в ValidateToken) —
// этот остаётся: шлюз не должен зависеть от того, какой тег SDK собран.
// Что считать «пустым `aud`», решает go-sdk, и гард с ним совпадает
// (TestAudienceIsSetMatchesSDK).

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"gitlab.com/markerloop/go-sdk/pkg/response"
)

// audienceRejectedCode — машинный код отказа, тот же, что у auth-service
// (handlers.RejectAudienceTokens).
const audienceRejectedCode = "token_audience_rejected"

// tokenHasAudience — у Bearer-токена из заголовка есть `aud` (audienceIsSet). Схема
// разбирается так же, как в collections-service (DataPrincipal): TrimSpace,
// "bearer " без учёта регистра, TrimSpace значения — иначе `bearer <mcp>`
// прошёл бы мимо гарда и был бы принят ниже. mlp_-ключи — не JWT, их не
// трогаем. Подпись не проверяется (см. шапку файла); нечитаемый JWT — false:
// его отвергнет проверка ниже.
func tokenHasAudience(authHeader string) bool {
	claims := unverifiedBearerClaims(authHeader)
	if claims == nil {
		return false
	}
	return audienceIsSet(claims["aud"])
}

// unverifiedBearerClaims — claims Bearer-JWT из заголовка БЕЗ проверки
// подписи, либо nil (не Bearer, mlp_-ключ, не JWT, нечитаемый payload).
// Годится только для гардов, которые отказывают и никогда не пропускают
// (tokenHasAudience, SDL-692; tokenHasWorkspaceID, SDL-613 S9).
func unverifiedBearerClaims(authHeader string) map[string]json.RawMessage {
	raw := strings.TrimSpace(authHeader)
	const bearer = "bearer "
	if len(raw) <= len(bearer) || !strings.EqualFold(raw[:len(bearer)], bearer) {
		return nil
	}
	value := strings.TrimSpace(raw[len(bearer):])
	if value == "" || strings.HasPrefix(value, "mlp_") {
		return nil
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	return claims
}

// audienceIsSet — у токена есть `aud`, ровно как его видит go-sdk v0.36.0
// (jwt.RejectAudience поверх jwt.ClaimStrings golang-jwt v5): пусто только
// отсутствующий `aud`, null и пустой массив []. Любая строка — даже "" —
// и любой непустой массив — даже [""] — это `aud`: go-sdk такой токен
// отвергает, шлюз тоже. Значение иной формы (число, объект, массив не
// строк) — тоже да: go-sdk его не разберёт, а выпущен такой токен не нами.
func audienceIsSet(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return false
	}
	var many []json.RawMessage
	if err := json.Unmarshal(raw, &many); err == nil {
		return len(many) > 0
	}
	return true
}

// RejectAudienceTokens — мидлварь уровня роутера: любой запрос с
// Bearer-JWT, у которого есть `aud`, — 401 до любой другой обработки.
// Стоит на всём роутере, а не на jwtMiddleware: плоскость /api/v1/data идёт
// без jwtMiddleware и отдаёт Authorization в collections-service, где
// DataPrincipal проверяет JWT go-sdk ValidateToken (до тега с SDL-692 —
// без `aud`) и принял бы MCP-токен как пользователя.
func RejectAudienceTokens() gin.HandlerFunc {
	return func(c *gin.Context) {
		if tokenHasAudience(c.GetHeader("Authorization")) {
			response.Error(c, http.StatusUnauthorized, "Этот токен выпущен для другого получателя и здесь не принимается", audienceRejectedCode)
			c.Abort()
			return
		}
		c.Next()
	}
}

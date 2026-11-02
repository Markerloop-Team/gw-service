package middleware

// SDL-613 S4: двойное чтение членства в ScopeMiddleware. Токен пространства
// (claims wsid/wsr) — источник роли сам; токен сессии — прежний путь через
// collections. Redis — miniredis, collections — стаб, токен — claims прямо
// в контексте (подпись проверяет go-sdk JWTMiddleware, её здесь нет; сквозной
// случай с подписью — internal/routes/workspace_token_scope_test.go).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	jwtlib "github.com/golang-jwt/jwt/v5"

	"gateway-service/internal/config"
	"gateway-service/internal/models"

	sdkjwt "gitlab.com/markerloop/go-sdk/pkg/jwt"
	"gitlab.com/markerloop/go-sdk/pkg/wsaccess"
)

const (
	wsTokUser    = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	wsTokOwnWS   = "12345678-1234-4123-8123-123456789abc"
	wsTokOtherWS = "87654321-4321-4321-8321-cba987654321"
)

// wsClaims — claims токена пространства; iat/exp задаются явно.
func wsClaims(user, ws, role string, iat, exp time.Time) *sdkjwt.Claims {
	return &sdkjwt.Claims{
		UserID:        user,
		Username:      "u",
		WorkspaceID:   ws,
		WorkspaceRole: role,
		RegisteredClaims: jwtlib.RegisteredClaims{
			ID:        "jti-1",
			IssuedAt:  jwtlib.NewNumericDate(iat),
			ExpiresAt: jwtlib.NewNumericDate(exp),
		},
	}
}

func withoutIAT(c *sdkjwt.Claims) *sdkjwt.Claims { c.IssuedAt = nil; return c }
func withoutEXP(c *sdkjwt.Claims) *sdkjwt.Claims { c.ExpiresAt = nil; return c }

// sessionClaims — токен сессии: без wsid.
func sessionClaims(user string) *sdkjwt.Claims {
	now := time.Now()
	return &sdkjwt.Claims{
		UserID: user, Username: "u",
		RegisteredClaims: jwtlib.RegisteredClaims{
			IssuedAt:  jwtlib.NewNumericDate(now),
			ExpiresAt: jwtlib.NewNumericDate(now.Add(time.Hour)),
		},
	}
}

type probeResult struct {
	code   int
	role   string
	header string
}

// runScopeProbe — один скоупленный запрос через ScopeMiddleware с claims в
// контексте. ownerOnly — запись реестра с ScopeOwnerOnly.
func runScopeProbe(t *testing.T, cfg PermissionMiddlewareConfig, claims *sdkjwt.Claims, workspaceID string, ownerOnly bool) probeResult {
	t.Helper()
	gin.SetMode(gin.TestMode)
	orig := lookupRouteConfig
	lookupRouteConfig = func(string, string) *config.RouteConfig {
		return &config.RouteConfig{Method: "GET", Path: "/api/v1/probe", ScopeParam: "workspace_id", ScopeKind: config.ScopeWorkspace, ScopeOwnerOnly: ownerOnly}
	}
	t.Cleanup(func() { lookupRouteConfig = orig })

	r := gin.New()
	r.GET("/api/v1/probe",
		func(c *gin.Context) {
			c.Set("user_id", claims.UserID)
			c.Set("jwt_claims", claims)
		},
		ScopeMiddleware(cfg),
		func(c *gin.Context) {
			ws, _ := WorkspaceScopeFromContext(c)
			hdrs, _ := c.Get(ScopeHeadersContextKey)
			h, _ := hdrs.(map[string]string)
			c.JSON(http.StatusOK, gin.H{"role": ws.Role, "header": h[HeaderScopeWorkspaceID]})
		})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/probe?workspace_id="+workspaceID, nil))
	res := probeResult{code: w.Code}
	if w.Code == http.StatusOK {
		var body struct{ Role, Header string }
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		res.role, res.header = body.Role, body.Header
	}
	return res
}

func unix(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

// Таблица случаев двойного чтения. collections на любой вопрос отвечает
// «актор — owner»: если роль member пришла в хендлер, её дал токен.
func TestScopeMiddlewareWorkspaceTokenTable(t *testing.T) {
	now := time.Now()
	iat := now.Add(-time.Minute)
	exp := iat.Add(wsaccess.WorkspaceTokenTTL)
	revKey := wsaccess.RevokedKeyPrefix + wsTokUser + ":" + wsTokOwnWS
	goneKey := wsaccess.GoneKeyPrefix + wsTokOwnWS

	cases := []struct {
		name         string
		claims       *sdkjwt.Claims
		workspace    string
		marks        map[string]string
		redisDown    bool
		noRedis      bool
		ownerOnly    bool
		wantCode     int
		wantRole     string
		wantCollects bool
	}{
		{name: "своё пространство — роль из токена", claims: wsClaims(wsTokUser, wsTokOwnWS, "member", iat, exp), workspace: wsTokOwnWS, wantCode: 200, wantRole: "member"},
		{name: "UPPER workspace_id в запросе совпадает с wsid", claims: wsClaims(wsTokUser, wsTokOwnWS, "member", iat, exp), workspace: strings.ToUpper(wsTokOwnWS), wantCode: 200, wantRole: "member"},
		{name: "чужое пространство — 403 mismatch", claims: wsClaims(wsTokUser, wsTokOwnWS, "owner", iat, exp), workspace: wsTokOtherWS, wantCode: 403},
		{name: "отметка исключения после iat — 401", claims: wsClaims(wsTokUser, wsTokOwnWS, "member", iat, exp), workspace: wsTokOwnWS, marks: map[string]string{revKey: unix(now)}, wantCode: 401},
		{name: "отметка удаления пространства после iat — 401", claims: wsClaims(wsTokUser, wsTokOwnWS, "owner", iat, exp), workspace: wsTokOwnWS, marks: map[string]string{goneKey: unix(now)}, wantCode: 401},
		{name: "отметка в пределах допуска 5 с до iat — 401", claims: wsClaims(wsTokUser, wsTokOwnWS, "member", iat, exp), workspace: wsTokOwnWS, marks: map[string]string{revKey: unix(iat.Add(-4 * time.Second))}, wantCode: 401},
		{name: "отметка раньше iat−5с — пропуск", claims: wsClaims(wsTokUser, wsTokOwnWS, "member", iat, exp), workspace: wsTokOwnWS, marks: map[string]string{revKey: unix(iat.Add(-10 * time.Second))}, wantCode: 200, wantRole: "member"},
		{name: "отметка другого участника не гасит", claims: wsClaims(wsTokUser, wsTokOwnWS, "member", iat, exp), workspace: wsTokOwnWS, marks: map[string]string{wsaccess.RevokedKeyPrefix + "99999999-8888-4777-8666-555555555555:" + wsTokOwnWS: unix(now)}, wantCode: 200, wantRole: "member"},
		{name: "Redis недоступен — откат на collections", claims: wsClaims(wsTokUser, wsTokOwnWS, "member", iat, exp), workspace: wsTokOwnWS, redisDown: true, wantCode: 200, wantRole: "owner", wantCollects: true},
		{name: "Redis не настроен — откат на collections", claims: wsClaims(wsTokUser, wsTokOwnWS, "member", iat, exp), workspace: wsTokOwnWS, noRedis: true, wantCode: 200, wantRole: "owner", wantCollects: true},
		{name: "нечитаемая отметка — откат на collections", claims: wsClaims(wsTokUser, wsTokOwnWS, "member", iat, exp), workspace: wsTokOwnWS, marks: map[string]string{revKey: "not-a-time"}, wantCode: 200, wantRole: "owner", wantCollects: true},
		{name: "токен сессии — старый путь", claims: sessionClaims(wsTokUser), workspace: wsTokOwnWS, wantCode: 200, wantRole: "owner", wantCollects: true},
		{name: "owner-only: member из токена — 403", claims: wsClaims(wsTokUser, wsTokOwnWS, "member", iat, exp), workspace: wsTokOwnWS, ownerOnly: true, wantCode: 403},
		{name: "owner-only: owner из токена — 200", claims: wsClaims(wsTokUser, wsTokOwnWS, "owner", iat, exp), workspace: wsTokOwnWS, ownerOnly: true, wantCode: 200, wantRole: "owner"},
		{name: "exp−iat больше 15 минут — 401", claims: wsClaims(wsTokUser, wsTokOwnWS, "member", iat, iat.Add(wsaccess.RevocationTTL)), workspace: wsTokOwnWS, wantCode: 401},
		{name: "iat из будущего — 401", claims: wsClaims(wsTokUser, wsTokOwnWS, "member", now.Add(time.Minute), now.Add(10*time.Minute)), workspace: wsTokOwnWS, wantCode: 401},
		{name: "wsid не в канонической форме — 401", claims: wsClaims(wsTokUser, strings.ToUpper(wsTokOwnWS), "member", iat, exp), workspace: wsTokOwnWS, wantCode: 401},
		{name: "нет iat — 401", claims: withoutIAT(wsClaims(wsTokUser, wsTokOwnWS, "member", iat, exp)), workspace: wsTokOwnWS, wantCode: 401},
		{name: "нет exp — 401", claims: withoutEXP(wsClaims(wsTokUser, wsTokOwnWS, "member", iat, exp)), workspace: wsTokOwnWS, wantCode: 401},
		{name: "user_id в верхнем регистре — 401", claims: wsClaims(strings.ToUpper(wsTokUser), wsTokOwnWS, "member", iat, exp), workspace: wsTokOwnWS, wantCode: 401},
		{name: "роль вне списка — 401", claims: wsClaims(wsTokUser, wsTokOwnWS, "admin", iat, exp), workspace: wsTokOwnWS, wantCode: 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mr, rs := newTestRedis(t)
			for k, v := range tc.marks {
				mr.Set(k, v)
			}
			stub := &collectionsProxy{status: http.StatusOK, body: membersBody(`{"user_id":"` + wsTokUser + `","role":"owner"}`)}
			cfg := revocationConfig(rs, stub)
			if tc.noRedis {
				cfg.RedisService = nil
			}
			if tc.redisDown {
				mr.Close()
			}
			got := runScopeProbe(t, cfg, tc.claims, tc.workspace, tc.ownerOnly)
			if got.code != tc.wantCode {
				t.Fatalf("код %d, ожидался %d", got.code, tc.wantCode)
			}
			if tc.wantCode == http.StatusOK {
				if got.role != tc.wantRole {
					t.Errorf("роль %q, ожидалась %q", got.role, tc.wantRole)
				}
				if got.header != wsTokOwnWS {
					t.Errorf("X-Scope-Workspace-ID = %q, ожидался %q", got.header, wsTokOwnWS)
				}
			}
			if asked := stub.path != ""; asked != tc.wantCollects {
				t.Errorf("collections спрошен = %v, ожидалось %v (path=%q)", asked, tc.wantCollects, stub.path)
			}
		})
	}
}

// Отметки нет — collections не спрашивается НИ РАЗУ, в том числе на серии
// запросов: токен пространства снимает вопрос о членстве с collections.
func TestWorkspaceTokenWithoutMarkMakesNoCollectionsCalls(t *testing.T) {
	_, rs := newTestRedis(t)
	iat := time.Now().Add(-time.Minute)
	claims := wsClaims(wsTokUser, wsTokOwnWS, "owner", iat, iat.Add(wsaccess.WorkspaceTokenTTL))
	calls := 0
	stub := &countingCollections{collectionsProxy: collectionsProxy{status: http.StatusOK, body: membersBody()}, calls: &calls}
	cfg := revocationConfig(rs, &collectionsProxy{})
	cfg.ProxyService = stub
	for i := 0; i < 3; i++ {
		if got := runScopeProbe(t, cfg, claims, wsTokOwnWS, true); got.code != http.StatusOK || got.role != "owner" {
			t.Fatalf("запрос %d: код %d роль %q", i, got.code, got.role)
		}
	}
	if calls != 0 {
		t.Fatalf("вызовов collections = %d, ожидалось 0", calls)
	}
}

type countingCollections struct {
	collectionsProxy
	calls *int
}

func (p *countingCollections) ProxyRequest(serviceName, method, path string, headers map[string]string, q map[string]string, b []byte) (*models.ProxyResponse, error) {
	*p.calls++
	return p.collectionsProxy.ProxyRequest(serviceName, method, path, headers, q, b)
}

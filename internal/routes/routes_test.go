package routes_test

// SDL-135: gateway route <-> permission-registry consistency tests.
//
// The gateway has a known bug class: a Gin route registered behind the
// permission middleware without a matching entry in
// internal/config/routes.go answers 403 ("Маршрут не найден в
// конфигурации") for every caller, no matter what permissions they hold.
// These tests build the real router (routes.SetupRoutes) with a stub
// ProxyService and sweep every registered route to prove the registry
// covers it.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"gateway-service/internal/config"
	"gateway-service/internal/handlers"
	"gateway-service/internal/models"
	"gateway-service/internal/proxy"
	"gateway-service/internal/routes"

	sdkjwt "gitlab.com/markerloop/go-sdk/pkg/jwt"
	"gitlab.com/markerloop/go-sdk/pkg/redis"
)

const (
	testUserID     = "11111111-2222-3333-4444-555555555555"
	testServiceKey = "test-service-key"
)

// stubProxy implements proxy.ProxyService without any network I/O.
// check-permission calls answer according to grantPermission; every
// other proxied request returns 200 so that the only source of a 403
// in the sweep is the gateway's own permission layer.
type stubProxy struct {
	grantPermission bool
}

func (s *stubProxy) ProxyRequest(serviceName, method, path string, headers map[string]string, queryParams map[string]string, body []byte) (*models.ProxyResponse, error) {
	if strings.Contains(path, "/check-permission") {
		payload, _ := json.Marshal(map[string]any{
			"data": map[string]any{"has_permission": s.grantPermission},
		})
		return &models.ProxyResponse{
			StatusCode: http.StatusOK,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       payload,
		}, nil
	}
	return &models.ProxyResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       []byte(`{"success":true}`),
	}, nil
}

// GetServiceURL points at a closed local port so handlers that open a
// raw connection (SSE proxy) fail fast instead of resolving DNS.
func (s *stubProxy) GetServiceURL(serviceName string) (string, error) {
	return "http://127.0.0.1:1", nil
}

// newTestRouter builds the production router with a stub proxy and a
// freshly generated RS256 keypair; returns the router and a valid
// Bearer access token for testUserID.
func newTestRouter(t *testing.T, grantPermission bool) (*gin.Engine, string) {
	t.Helper()
	return newRouterWithProxy(t, &stubProxy{grantPermission: grantPermission})
}

// newRouterWithProxy — то же, что newTestRouter, но с произвольным стабом
// ProxyService (SDL-587: стаб членства в scope_test.go).
func newRouterWithProxy(t *testing.T, stub proxy.ProxyService) (*gin.Engine, string) {
	t.Helper()
	return newRouterWithProxyAndRedis(t, stub, nil)
}

// newRouterWithProxyAndRedis — то же, но с Redis (SDL-615 S2: miniredis в
// membership_revocation_test.go); nil — без кэша, как во всех прочих тестах.
func newRouterWithProxyAndRedis(t *testing.T, stub proxy.ProxyService, redisService *redis.RedisService) (*gin.Engine, string) {
	t.Helper()
	r, signer := newRouterWithSigner(t, stub, redisService)
	pair, err := signer.GenerateTokensWithUsername(testUserID, "testuser", "test@example.com")
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}
	return r, pair.AccessToken
}

// newRouterWithSigner — роутер шлюза и подписант его ключом (SDL-613 S4:
// токены пространства в workspace_token_scope_test.go подписываются им же).
func newRouterWithSigner(t *testing.T, stub proxy.ProxyService, redisService *redis.RedisService, opts ...func(*config.Config)) (*gin.Engine, *sdkjwt.JWTService) {
	t.Helper()
	r, signer, _ := newRouterWithKey(t, stub, redisService, opts...)
	return r, signer
}

// newRouterWithKey — то же плюс сам RSA-ключ (SDL-692: MCP-токен с aud
// подписывается в тесте напрямую, у JWTService такого выпуска нет).
// opts правят конфиг до сборки роутера (SDL-613 S9: флаг
// Scope.RequireWorkspaceToken в workspace_token_boundary_test.go).
func newRouterWithKey(t *testing.T, stub proxy.ProxyService, redisService *redis.RedisService, opts ...func(*config.Config)) (*gin.Engine, *sdkjwt.JWTService, *rsa.PrivateKey) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	cfg := &config.Config{}
	cfg.JWT.PublicKeyPEM = string(pubPEM)
	cfg.Security.ServiceKey = testServiceKey
	// Closed port: the i18n fallback in sendForbiddenError fails fast
	// and the middleware answers with the plain 403 body.
	cfg.Services.Dictionary.URL = "http://127.0.0.1:1"
	for _, opt := range opts {
		opt(cfg)
	}

	proxyHandler := handlers.NewProxyHandler(stub, logger)

	r := gin.New()
	routes.SetupRoutes(r, proxyHandler, cfg, stub, redisService, logger)

	signer, err := sdkjwt.NewJWTServiceRS256(key, &key.PublicKey, time.Hour, time.Hour, logger)
	if err != nil {
		t.Fatalf("build jwt signer: %v", err)
	}
	return r, signer, key
}

// fillParams turns a Gin route pattern into a concrete request path the
// permission middleware normalizer maps back onto the same placeholders.
func fillParams(pattern string) string {
	parts := strings.Split(pattern, "/")
	for i, part := range parts {
		switch {
		case strings.HasPrefix(part, "*"):
			parts[i] = "index.html"
		case part == ":email":
			parts[i] = "someone@example.com"
		case part == ":username":
			// normalizePath maps segments longer than 20 chars after
			// "username" onto :username.
			parts[i] = "someveryverylongusername123"
		case part == ":n":
			// Номер ревизии (pages, SDL-584): числовой сегмент normalizePath
			// сворачивает в :param — ровно так, как придёт настоящий запрос.
			parts[i] = "3"
		case strings.HasPrefix(part, ":"):
			// Any other parameter is filled with a UUID; the request
			// normalizer collapses UUIDs to :id and normalizeConfigPath
			// does the same for config placeholders.
			parts[i] = testUserID
		}
	}
	return strings.Join(parts, "/")
}

func doRequest(r *gin.Engine, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestEveryGinRouteIsCoveredByPermissionRegistry sweeps every route the
// production router registers. With a valid JWT, the correct service
// key and a permission checker that grants everything, no route may
// answer 403 — a 403 here means the route is missing from
// internal/config/routes.go (the exact bug class this suite exists for).
func TestEveryGinRouteIsCoveredByPermissionRegistry(t *testing.T) {
	r, token := newTestRouter(t, true)

	for _, ri := range r.Routes() {
		w := doRequest(r, ri.Method, fillParams(ri.Path), map[string]string{
			"Authorization": "Bearer " + token,
			"X-Service-Key": testServiceKey,
		})
		if w.Code == http.StatusForbidden {
			t.Errorf("%s %s -> 403: route is registered in Gin but has no entry in the permission registry (internal/config/routes.go)", ri.Method, ri.Path)
		}
	}
}

// TestGatewayPublishesNoProjectsRoutes (SDL-620): the /api/v1/projects
// group is gone — "workspace = project" since SDL-617b, collections-service
// no longer serves those paths, and roles/tokens/members live under
// /workspaces/:id/*. A Gin route coming back here is red; a registry entry
// coming back is red in config.TestRegistryHasNoProjectsEntries. The two
// halves are what make "no entry => 403 by design" a closed surface.
func TestGatewayPublishesNoProjectsRoutes(t *testing.T) {
	r, token := newTestRouter(t, true)

	for _, ri := range r.Routes() {
		if ri.Path == "/api/v1/projects" || strings.HasPrefix(ri.Path, "/api/v1/projects/") {
			t.Errorf("%s %s: /projects route is registered in Gin again — surface closed in SDL-620", ri.Method, ri.Path)
		}
	}

	// Live probe through the real router: whatever a client dials under
	// /projects must not reach any upstream. Gin answers its default 404
	// (no NoRoute handler in this contour); a 403 would mean a route exists
	// but lacks a registry entry, a 200 would mean it is proxied.
	for _, probe := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/projects"},
		{http.MethodPost, "/api/v1/projects"},
		{http.MethodGet, fillParams("/api/v1/projects/:id")},
		{http.MethodGet, fillParams("/api/v1/projects/:id") + "/tokens"},
		{http.MethodGet, fillParams("/api/v1/projects/:id") + "/roles"},
		{http.MethodGet, fillParams("/api/v1/projects/:id") + "/members"},
	} {
		w := doRequest(r, probe.method, probe.path, map[string]string{
			"Authorization": "Bearer " + token,
		})
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s -> %d, want Gin 404: the /projects surface must not exist on the gateway", probe.method, probe.path, w.Code)
		}
	}
}

// TestRegistryHasNoDeadEntries walks the registry the other way: every
// RouteConfig must correspond to a route the router actually registers,
// so stale entries do not accumulate after route removals.
func TestRegistryHasNoDeadEntries(t *testing.T) {
	r, _ := newTestRouter(t, true)

	anonymize := func(path string) string {
		parts := strings.Split(path, "/")
		for i, part := range parts {
			if strings.HasPrefix(part, ":") {
				parts[i] = ":x"
			}
		}
		return strings.Join(parts, "/")
	}

	registered := make(map[string]bool)
	for _, ri := range r.Routes() {
		registered[ri.Method+" "+anonymize(ri.Path)] = true
	}

	for _, rc := range config.GetRouteConfigs() {
		key := rc.Method + " " + anonymize(rc.Path)
		if !registered[key] {
			t.Errorf("registry entry %s %s (permission %q) has no matching Gin route — dead entry in internal/config/routes.go", rc.Method, rc.Path, rc.Permission)
		}
	}
}

// bootstrapRoutes lists onboarding endpoints a brand-new user (zero
// roles, zero permissions) must be able to reach right after
// registration. If any of them is gated behind a Required permission,
// new users deadlock: they cannot obtain their first role because every
// endpoint that would grant it answers 403.
var bootstrapRoutes = []struct {
	method string
	path   string
}{
	{http.MethodGet, "/api/v1/users/my/access"},
	// EP-155 (SDL-762): registration creates no workspace; the first one
	// is created by POST /workspaces before the user has any role — a
	// Required:true entry here would deadlock every new user. The old
	// POST /workspaces/bootstrap is gone (TestWorkspaceBootstrapRouteGone).
	{http.MethodPost, "/api/v1/workspaces"},
	// SDL-615: the invitee is not yet a member of the workspace, and a
	// brand-new account has no role anywhere — both recipient routes must
	// pass with zero permissions and without a ScopeKind.
	{http.MethodPost, "/api/v1/invites/preview"},
	{http.MethodPost, "/api/v1/invites/accept"},
	// SDL-613 S3: a session token is exchanged for a workspace token BEFORE
	// the caller holds any workspace token — the workspace is the object
	// being requested, not the scope of the call. Zero roles, no ScopeKind.
	{http.MethodPost, "/api/v1/auth/token/workspace"},
	// SDL-693: "Connected agents" — any signed-in user lists and revokes
	// their own MCP grants; a user with no role at all must get 200 ([]),
	// never 403. Session token, no ScopeKind.
	{http.MethodGet, "/api/v1/oauth/grants"},
	{http.MethodDelete, "/api/v1/oauth/grants/" + testUserID},
}

// TestBootstrapEndpointsWorkWithoutAnyRole drives the bootstrap
// endpoints through the real router with a permission checker that
// DENIES everything — simulating a fresh user with no roles. The
// endpoints must still succeed.
func TestBootstrapEndpointsWorkWithoutAnyRole(t *testing.T) {
	r, token := newTestRouter(t, false)

	for _, br := range bootstrapRoutes {
		w := doRequest(r, br.method, br.path, map[string]string{
			"Authorization": "Bearer " + token,
		})
		if w.Code != http.StatusOK {
			t.Errorf("%s %s -> %d: bootstrap endpoint must be reachable for a user without any role (expected 200)", br.method, br.path, w.Code)
		}
	}
}

// TestWorkspaceBootstrapRouteGone — SDL-762 (EP-155): personal workspaces
// are retired, POST /workspaces/bootstrap is no longer published. Both
// halves must be gone: the Gin route (404 even with every permission
// granted) and the registry entry (a stale entry would hide a re-added
// route from the coverage sweep's intent).
func TestWorkspaceBootstrapRouteGone(t *testing.T) {
	r, token := newTestRouter(t, true)
	w := doRequest(r, http.MethodPost, "/api/v1/workspaces/bootstrap", map[string]string{
		"Authorization": "Bearer " + token,
	})
	if w.Code != http.StatusNotFound {
		t.Errorf("POST /api/v1/workspaces/bootstrap -> %d, expected 404 (route removed in SDL-762)", w.Code)
	}
	if rc := config.FindRouteConfig(http.MethodPost, "/api/v1/workspaces/bootstrap"); rc != nil {
		t.Errorf("registry still has POST /api/v1/workspaces/bootstrap (%s) — remove it together with the Gin route", rc.Permission)
	}
}

// TestBootstrapEndpointsNotRequiredInRegistry guards the registry side
// of the bootstrapRoutes invariant: if a bootstrap endpoint ever gets an entry in
// the permission registry, that entry must have Required: false.
func TestBootstrapEndpointsNotRequiredInRegistry(t *testing.T) {
	for _, br := range bootstrapRoutes {
		if rc := config.FindRouteConfig(br.method, br.path); rc != nil && rc.Required {
			t.Errorf("%s %s is marked Required:true in the permission registry — bootstrap endpoints must be Required:false (new-user deadlock)", br.method, br.path)
		}
	}
}

// TestProtectedRouteWithoutTokenReturns401 — the users group sits behind
// the JWT middleware.
func TestProtectedRouteWithoutTokenReturns401(t *testing.T) {
	r, _ := newTestRouter(t, true)

	w := doRequest(r, http.MethodGet, "/api/v1/users", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/users without token -> %d, want 401", w.Code)
	}
}

// TestPermissionDeniedReturns403 — a valid JWT whose user lacks the
// permission gets 403, not a proxied response.
func TestPermissionDeniedReturns403(t *testing.T) {
	r, token := newTestRouter(t, false)

	w := doRequest(r, http.MethodGet, "/api/v1/users", map[string]string{
		"Authorization": "Bearer " + token,
	})
	if w.Code != http.StatusForbidden {
		t.Errorf("GET /api/v1/users with denied permission -> %d, want 403", w.Code)
	}
}

// TestPublicAuthRouteNeedsNoToken — login is public and proxies straight
// through.
func TestPublicAuthRouteNeedsNoToken(t *testing.T) {
	r, _ := newTestRouter(t, true)

	w := doRequest(r, http.MethodPost, "/api/v1/auth/login", nil)
	if w.Code != http.StatusOK {
		t.Errorf("POST /api/v1/auth/login -> %d, want 200 (public route must not require auth)", w.Code)
	}
}

// TestResendVerificationIsPublic — SDL-270. The whole point of this route
// is that it works for somebody who is not signed in and cannot sign in
// (their address is unverified), so a token requirement creeping back onto
// it would silently restore the dead end it was added to remove. The
// sibling request-email-verification stays JWT-only, and that asymmetry is
// deliberate — assert both here so neither drifts into the other.
func TestResendVerificationIsPublic(t *testing.T) {
	r, _ := newTestRouter(t, true)

	w := doRequest(r, http.MethodPost, "/api/v1/auth/resend-verification", nil)
	if w.Code != http.StatusOK {
		t.Errorf("POST /api/v1/auth/resend-verification -> %d, want 200 (must not require auth)", w.Code)
	}

	w = doRequest(r, http.MethodPost, "/api/v1/auth/request-email-verification", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("POST /api/v1/auth/request-email-verification without token -> %d, want 401 (still JWT-only)", w.Code)
	}
}

// TestLogoutIsPublic — SDL-613 S5. auth-service serves POST /auth/logout
// without JWT (the refresh token in the body is the credential, and the
// access token is often already expired by the time the user signs out).
// A 404 here means the gateway stopped publishing it — the exact failure
// the dev-infra gw-contract sweep caught; a 401 means a token requirement
// crept onto it and an expired session could no longer sign out.
func TestLogoutIsPublic(t *testing.T) {
	const path = "/api/v1/auth/logout"

	r, _ := newTestRouter(t, true)

	w := doRequest(r, http.MethodPost, path, nil)
	if w.Code == http.StatusNotFound {
		t.Fatalf("POST %s -> 404: the gateway does not publish the route (auth-service serves it)", path)
	}
	if w.Code != http.StatusOK {
		t.Errorf("POST %s -> %d, want 200 (must not require auth)", path, w.Code)
	}
}

// TestServiceRouteRejectsMissingServiceKey — notification endpoints are
// service-to-service only.
func TestServiceRouteRejectsMissingServiceKey(t *testing.T) {
	r, token := newTestRouter(t, true)

	w := doRequest(r, http.MethodPost, "/api/v1/notifications/email/send", map[string]string{
		"Authorization": "Bearer " + token, // a user JWT must not be enough
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("POST /api/v1/notifications/email/send without X-Service-Key -> %d, want 401", w.Code)
	}
}

// TestTelegramDeeplinkIsPublishedAndProtected pins the route SDL-321 added.
//
// The class it guards is "the upstream serves it, the gateway never
// published it": auth-service has registered POST /auth/telegram/deeplink
// behind its own JWT middleware since the beginning, and the gateway did
// not carry the path at all, so from a browser the endpoint was a silent
// Gin 404 — indistinguishable from an endpoint that was never meant to
// exist. The dev-infra gw-contract sweep found it and had to list it in
// KNOWN_GAPS; this test is the offline half, so the route cannot quietly
// disappear again between nightly runs.
//
// Two halves, both required: the path must exist (a plain 404 means the
// gateway dropped it), and it must stay behind JWT (linking Telegram to a
// profile identifies the caller by their token — an anonymous caller has
// no profile to link).
func TestTelegramDeeplinkIsPublishedAndProtected(t *testing.T) {
	const path = "/api/v1/auth/telegram/deeplink"

	r, token := newTestRouter(t, true)

	w := doRequest(r, http.MethodPost, path, map[string]string{
		"Authorization": "Bearer " + token,
	})
	if w.Code == http.StatusNotFound {
		t.Fatalf("POST %s -> 404: the gateway does not publish the route (auth-service serves it)", path)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("POST %s -> %d with a valid token, expected the proxy to answer 200; body: %s", path, w.Code, w.Body.String())
	}

	anon := doRequest(r, http.MethodPost, path, nil)
	if anon.Code != http.StatusUnauthorized {
		t.Errorf("POST %s without a token -> %d, expected 401: the deeplink is issued for the caller in the token", path, anon.Code)
	}
}

// TestPasswordRecoveryRoutesArePublic — SDL-462. Обе ручки восстановления
// обязаны отвечать анониму: человек, забывший пароль, войти не может, и
// требование токена на любой из них вернуло бы ровно тот тупик, ради выхода
// из которого флоу и заводился.
func TestPasswordRecoveryRoutesArePublic(t *testing.T) {
	r, _ := newTestRouter(t, true)

	for _, path := range []string{"/api/v1/auth/forgot-password", "/api/v1/auth/reset-password"} {
		w := doRequest(r, http.MethodPost, path, nil)
		if w.Code != http.StatusOK {
			t.Errorf("POST %s -> %d, want 200 (must not require auth)", path, w.Code)
		}
	}
}

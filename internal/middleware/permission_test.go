package middleware

// SDL-135: unit tests for the permission middleware — path
// normalization and the fail-closed behavior for routes that are
// missing from the permission registry.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"gateway-service/internal/config"
	"gateway-service/internal/models"
)

func TestNormalizePath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/api/v1/users/11111111-2222-3333-4444-555555555555", "/api/v1/users/:id"},
		{"/api/v1/users/email/someone@example.com", "/api/v1/users/email/:email"},
		{"/api/v1/users/username/someveryverylongusername123", "/api/v1/users/username/:username"},
		{"/api/v1/users/11111111-2222-3333-4444-555555555555/roles/99999999-8888-7777-6666-555555555555", "/api/v1/users/:id/roles/:id"},
		// Numeric segments collapse to :param (revisions, pagination).
		{"/api/v1/things/42", "/api/v1/things/:param"},
		// Short plain segments stay literal.
		{"/api/v1/users/my", "/api/v1/users/my"},
		{"/api/v1/users", "/api/v1/users"},
	}
	for _, c := range cases {
		if got := normalizePath(c.in); got != c.want {
			t.Errorf("normalizePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// grantAllProxy answers every check-permission call with
// has_permission=true, so any 403 in these tests comes from the
// registry lookup, not from the permission decision.
type grantAllProxy struct{}

func (grantAllProxy) ProxyRequest(serviceName, method, path string, headers map[string]string, queryParams map[string]string, body []byte) (*models.ProxyResponse, error) {
	payload, _ := json.Marshal(map[string]any{
		"data": map[string]any{"has_permission": true},
	})
	return &models.ProxyResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       payload,
	}, nil
}

func (grantAllProxy) GetServiceURL(serviceName string) (string, error) {
	return "http://127.0.0.1:1", nil
}

func newPermissionTestEngine(userID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	cfg := &config.Config{}
	// Closed port: the i18n lookup in sendForbiddenError fails fast and
	// falls back to the plain 403 body.
	cfg.Services.Dictionary.URL = "http://127.0.0.1:1"

	mw := PermissionMiddleware(PermissionMiddlewareConfig{
		Config:       cfg,
		ProxyService: grantAllProxy{},
		Logger:       logger,
	})

	r := gin.New()
	r.Use(func(c *gin.Context) {
		if userID != "" {
			c.Set("user_id", userID)
		}
	})
	r.Use(mw)
	// Deliberately NOT present in internal/config/routes.go.
	r.GET("/api/v1/not-in-registry", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"reached": true})
	})
	// Present in the registry — the control route.
	r.GET("/api/v1/users", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"reached": true})
	})
	return r
}

// denyAllProxy answers every check-permission call with
// has_permission=false. Used to tell apart "the middleware asked
// user-service" from "the middleware short-circuited": a route that
// still answers 200 under this proxy never consulted anyone.
type denyAllProxy struct{}

func (denyAllProxy) ProxyRequest(serviceName, method, path string, headers map[string]string, queryParams map[string]string, body []byte) (*models.ProxyResponse, error) {
	payload, _ := json.Marshal(map[string]any{
		"data": map[string]any{"has_permission": false},
	})
	return &models.ProxyResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       payload,
	}, nil
}

func (denyAllProxy) GetServiceURL(serviceName string) (string, error) {
	return "http://127.0.0.1:1", nil
}

// newOwnRouteEngine wires the two ':own' routes from the registry
// (GET and PUT /api/v1/users/my) behind a permission checker that
// denies everything, plus a decoy path that merely *contains* "my".
func newOwnRouteEngine(userID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	cfg := &config.Config{}
	cfg.Services.Dictionary.URL = "http://127.0.0.1:1"

	mw := PermissionMiddleware(PermissionMiddlewareConfig{
		Config:       cfg,
		ProxyService: denyAllProxy{},
		Logger:       logger,
	})

	r := gin.New()
	r.Use(func(c *gin.Context) {
		if userID != "" {
			c.Set("user_id", userID)
		}
	})
	r.Use(mw)
	reached := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"reached": true}) }
	r.GET("/api/v1/users/my", reached)
	r.PUT("/api/v1/users/my", reached)
	return r
}

// TestOwnShortCircuitIsReadOnly — SDL-426. The ':own' short-circuit on
// /users/my must cover reads only. Before the fix any method skipped the
// permission check entirely, so users:update:own could not be revoked by
// role and a read-only role still wrote its own profile.
func TestOwnShortCircuitIsReadOnly(t *testing.T) {
	r := newOwnRouteEngine("11111111-2222-3333-4444-555555555555")

	// GET keeps the short-circuit: 200 even though the checker denies all.
	if w := serve(r, http.MethodGet, "/api/v1/users/my"); w.Code != http.StatusOK {
		t.Errorf("GET /users/my -> %d, want 200 (read short-circuit kept)", w.Code)
	}
	// PUT must now consult user-service, which denies -> 403.
	if w := serve(r, http.MethodPut, "/api/v1/users/my"); w.Code != http.StatusForbidden {
		t.Errorf("PUT /users/my -> %d, want 403 (write must be checked)", w.Code)
	}
}

// TestOwnShortCircuitGrantsWriteWhenPermitted — the mirror case: with a
// checker that grants, PUT /users/my passes. Without this the test above
// would also pass if the route were broken outright, which would prove
// nothing about permissions.
func TestOwnShortCircuitGrantsWriteWhenPermitted(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	cfg := &config.Config{}
	cfg.Services.Dictionary.URL = "http://127.0.0.1:1"

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", "11111111-2222-3333-4444-555555555555")
	})
	r.Use(PermissionMiddleware(PermissionMiddlewareConfig{
		Config:       cfg,
		ProxyService: grantAllProxy{},
		Logger:       logger,
	}))
	r.PUT("/api/v1/users/my", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"reached": true})
	})

	if w := serve(r, http.MethodPut, "/api/v1/users/my"); w.Code != http.StatusOK {
		t.Errorf("PUT /users/my with permission -> %d, want 200", w.Code)
	}
}

// TestHasPathSegment — the short-circuit compares a whole segment, not a
// substring. "mystuff" contains "my"; treating that as the own-profile
// route would silently widen the bypass the moment a third ':own' route
// carries a user-supplied segment.
func TestHasPathSegment(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/api/v1/users/my", true},
		{"/api/v1/users/mystuff", false},
		{"/api/v1/mycompany/users", false},
		{"/api/v1/users/:id", false},
	}
	for _, c := range cases {
		if got := hasPathSegment(c.path, "my"); got != c.want {
			t.Errorf("hasPathSegment(%q, \"my\") = %v, want %v", c.path, got, c.want)
		}
	}
}

func serve(r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestFailsClosedForUnregisteredRoute — a route behind the permission
// middleware but absent from the registry must answer 403 even when the
// permission checker would grant everything. This is the documented
// fail-safe ("Маршрут не найден в конфигурации").
func TestFailsClosedForUnregisteredRoute(t *testing.T) {
	r := newPermissionTestEngine("11111111-2222-3333-4444-555555555555")

	if w := serve(r, http.MethodGet, "/api/v1/not-in-registry"); w.Code != http.StatusForbidden {
		t.Errorf("unregistered route -> %d, want 403 (fail-closed)", w.Code)
	}
	// Control: the registered route passes with the same setup.
	if w := serve(r, http.MethodGet, "/api/v1/users"); w.Code != http.StatusOK {
		t.Errorf("registered route -> %d, want 200", w.Code)
	}
}

// TestRejectsRequestWithoutUserID — the middleware requires the JWT
// middleware to have run first; without user_id in the context it must
// answer 401, not pass through.
func TestRejectsRequestWithoutUserID(t *testing.T) {
	r := newPermissionTestEngine("")

	if w := serve(r, http.MethodGet, "/api/v1/users"); w.Code != http.StatusUnauthorized {
		t.Errorf("request without user_id -> %d, want 401", w.Code)
	}
}

// SDL-614: ключ кэша роли в пространстве обязан отличаться префиксом от
// старого "membership:" — под старым ключом лежит литерал "1", и после
// выката первые 60 секунд каждый запрос читал бы его как роль. Ключ
// причастности к проекту (project_ws:) снят в SDL-620 вместе с проектным
// скоупом.
func TestScopeCacheKeysHaveOwnPrefixes(t *testing.T) {
	ws := workspaceRoleCacheKey("u", "w")
	if strings.HasPrefix(ws, "membership:") {
		t.Fatalf("ключ %q под старым префиксом членства — кэш отдаст \"1\"", ws)
	}
	if !strings.HasPrefix(ws, workspaceRoleCachePrefix) {
		t.Fatalf("ключ роли %q не под префиксом %q", ws, workspaceRoleCachePrefix)
	}
}

// Пара «пространство + роль» читается из контекста только целиком: без записи,
// с чужим типом или с пустым полем — «нет пары», и permissionMiddleware не
// шлёт в user-service ничего из неё.
func TestWorkspaceScopeFromContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mk := func(v any, set bool) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		if set {
			c.Set(WorkspaceScopeContextKey, v)
		}
		return c
	}
	for name, tc := range map[string]struct {
		v    any
		set  bool
		want bool
	}{
		"absent":     {nil, false, false},
		"wrong type": {"owner", true, false},
		"empty role": {WorkspaceScope{ID: "w"}, true, false},
		"empty id":   {WorkspaceScope{Role: "owner"}, true, false},
		"complete":   {WorkspaceScope{ID: "w", Role: "owner"}, true, true},
	} {
		if _, ok := WorkspaceScopeFromContext(mk(tc.v, tc.set)); ok != tc.want {
			t.Errorf("%s: ok=%v, ожидалось %v", name, ok, tc.want)
		}
	}
}

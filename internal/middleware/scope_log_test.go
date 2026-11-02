package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"gateway-service/internal/config"

	sdkjwt "gitlab.com/markerloop/go-sdk/pkg/jwt"
	"gitlab.com/markerloop/go-sdk/pkg/logsafe"
)

// SDL-738: строки ScopeMiddleware пишут путь запроса через logsafe.Path —
// почта и логин из /users/email/:email и /users/username/:username в журнал
// не попадают. Реестр — литерал в config, поэтому запись со скоупом на этих
// путях подсовывается через lookupRouteConfig (как в scope_kind_test.go).
func TestScopeMiddlewareLog_NoPersonalData(t *testing.T) {
	const (
		email = "pii-scope738@example.com"
		login = "piiscope738"
	)
	paths := []struct {
		path    string
		secrets []string
	}{
		{"/api/v1/users/email/" + email, []string{"@", "pii-scope738"}},
		{"/api/v1/users/username/" + login, []string{login}},
	}
	now := time.Now()
	cases := []struct {
		name      string
		kind      config.ScopeKind
		ownerOnly bool
		claims    *sdkjwt.Claims
		wantCode  int
		wantLine  string
	}{
		{"unknown scope kind", "project", false, nil, http.StatusInternalServerError, "Неизвестный род скоупа"},
		{"workspace token rejected", config.ScopeWorkspace, false,
			wsClaims(wsTokUser, "NOT-A-UUID", "member", now, now.Add(10*time.Minute)),
			http.StatusUnauthorized, "отвергнут"},
		{"workspace token mismatch", config.ScopeWorkspace, false,
			wsClaims(wsTokUser, wsTokOtherWS, "member", now, now.Add(10*time.Minute)),
			http.StatusForbidden, "выпущен на другое пространство"},
		{"owner-only denial", config.ScopeWorkspace, true, nil, http.StatusForbidden, "не допущен"},
	}
	for _, p := range paths {
		for _, tc := range cases {
			t.Run(tc.name+" "+p.path, func(t *testing.T) {
				gin.SetMode(gin.TestMode)
				orig := lookupRouteConfig
				lookupRouteConfig = func(string, string) *config.RouteConfig {
					return &config.RouteConfig{Method: "GET", Path: "/probe", ScopeParam: "workspace_id",
						ScopeKind: tc.kind, ScopeOwnerOnly: tc.ownerOnly}
				}
				t.Cleanup(func() { lookupRouteConfig = orig })

				var buf bytes.Buffer
				stub := &collectionsProxy{status: http.StatusOK, body: membersBody(`{"user_id":"` + wsTokUser + `","role":"member"}`)}
				cfg := scopeStubConfig(stub)
				logger := logrus.New()
				logger.SetOutput(&buf)
				cfg.Logger = logger

				r := gin.New()
				r.Use(func(c *gin.Context) {
					c.Set("user_id", wsTokUser)
					if tc.claims != nil {
						c.Set(jwtClaimsContextKey, tc.claims)
					}
				})
				r.Use(ScopeMiddleware(cfg))
				h := func(c *gin.Context) { c.Status(http.StatusOK) }
				r.GET("/api/v1/users/email/:email", h)
				r.GET("/api/v1/users/username/:username", h)

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p.path+"?workspace_id="+wsTokOwnWS, nil))
				if w.Code != tc.wantCode {
					t.Fatalf("status = %d, want %d (behaviour unchanged by SDL-738)", w.Code, tc.wantCode)
				}
				out := buf.String()
				for _, s := range p.secrets {
					if strings.Contains(out, s) {
						t.Fatalf("log contains %q: %s", s, out)
					}
				}
				if !strings.Contains(out, tc.wantLine) {
					t.Fatalf("expected %q in log: %s", tc.wantLine, out)
				}
				if !strings.Contains(out, "GET "+logsafe.Path(p.path)) {
					t.Fatalf("masked path %q missing: %s", logsafe.Path(p.path), out)
				}
			})
		}
	}
}

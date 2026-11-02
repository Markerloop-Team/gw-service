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
)

// SDL-738: токен пространства на маршруте учётки /users/email/:email —
// предупреждения WorkspaceTokenBoundary пишут шаблон маршрута, а не почту.
func TestWorkspaceTokenBoundaryLog_NoEmail(t *testing.T) {
	const email = "pii-wsb738@example.com"
	now := time.Now()
	malformed := wsClaims(wsTokUser, "NOT-A-UUID", "member", now, now.Add(10*time.Minute))
	cases := []struct {
		name     string
		claims   *sdkjwt.Claims
		wantCode int
		wantLine string
	}{
		{"boundaryAccount", wsClaims(wsTokUser, wsTokOwnWS, "member", now, now.Add(10*time.Minute)),
			http.StatusForbidden, "на маршруте учётки (GET /api/v1/users/email/:email)"},
		{"malformed workspace token", malformed,
			http.StatusUnauthorized, "GET /api/v1/users/email/:email)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			var buf bytes.Buffer
			logger := logrus.New()
			logger.SetOutput(&buf)
			cfg := &config.Config{}
			cfg.Scope.RequireWorkspaceToken = true
			cfg.Services.Dictionary.URL = "http://127.0.0.1:1"

			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("user_id", wsTokUser)
				c.Set(jwtClaimsContextKey, tc.claims)
			})
			r.Use(WorkspaceTokenBoundary(PermissionMiddlewareConfig{Config: cfg, Logger: logger}))
			r.GET("/api/v1/users/email/:email", func(c *gin.Context) { c.Status(http.StatusOK) })

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/users/email/"+email, nil))
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantCode)
			}
			out := buf.String()
			if strings.Contains(out, "@") || strings.Contains(out, "pii-wsb738") {
				t.Fatalf("log contains the email: %s", out)
			}
			if !strings.Contains(out, tc.wantLine) {
				t.Fatalf("expected %q in log: %s", tc.wantLine, out)
			}
		})
	}
}

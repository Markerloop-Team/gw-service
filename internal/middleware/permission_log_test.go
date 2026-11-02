package middleware

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"gateway-service/internal/config"
)

// SDL-738: короткий логин нормализатор оставляет литералом, маршрут не
// находится в реестре — предупреждение пишет шаблон Gin, а не логин.
func TestUnregisteredRouteWarning_NoLogin(t *testing.T) {
	const login = "piilogin738"
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)

	cfg := &config.Config{}
	cfg.Services.Dictionary.URL = "http://127.0.0.1:1"
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("user_id", "11111111-2222-3333-4444-555555555555") })
	r.Use(PermissionMiddleware(PermissionMiddlewareConfig{Config: cfg, ProxyService: grantAllProxy{}, Logger: logger}))
	r.GET("/api/v1/users/username/:username", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := serve(r, http.MethodGet, "/api/v1/users/username/"+login)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (fail-safe; behaviour unchanged by SDL-738)", w.Code)
	}
	out := buf.String()
	if strings.Contains(out, login) {
		t.Fatalf("log contains the login: %s", out)
	}
	if !strings.Contains(out, "Маршрут не найден в конфигурации: GET /api/v1/users/username/:username") {
		t.Fatalf("route template missing: %s", out)
	}
}

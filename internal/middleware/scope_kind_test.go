package middleware

// SDL-620: род скоупа один — пространство. Запись реестра с любым иным родом
// (в том числе пустым при непустом ScopeParam) — ошибка конфигурации, и
// ScopeMiddleware обязан ответить 500 fail-closed, не спрашивая collections и
// не пропуская запрос. Реестр — литерал в config, поэтому запись с плохим
// родом подсовывается через lookupRouteConfig.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"gateway-service/internal/config"
)

func TestScopeMiddlewareUnknownKindIsFailClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, kind := range []config.ScopeKind{"project", "", "tenant"} {
		t.Run("kind="+string(kind), func(t *testing.T) {
			orig := lookupRouteConfig
			lookupRouteConfig = func(string, string) *config.RouteConfig {
				return &config.RouteConfig{Method: "GET", Path: "/api/v1/probe", ScopeParam: "workspace_id", ScopeKind: kind}
			}
			t.Cleanup(func() { lookupRouteConfig = orig })

			// Стаб отвечает «owner» на любой вопрос: если ветка неизвестного
			// рода пропустит запрос дальше, роль резолвится и хендлер отдаст 200.
			stub := &collectionsProxy{status: http.StatusOK, body: membersBody(`{"user_id":"` + scopeKindTestUserID + `","role":"owner"}`)}
			r := gin.New()
			r.GET("/api/v1/probe",
				func(c *gin.Context) { c.Set("user_id", scopeKindTestUserID) },
				ScopeMiddleware(scopeStubConfig(stub)),
				func(c *gin.Context) { c.Status(http.StatusOK) })

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/probe?workspace_id="+scopeKindTestWorkspace, nil))
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("род %q -> %d, ожидался 500 fail-closed", kind, w.Code)
			}
			if stub.path != "" {
				t.Fatalf("род %q: шлюз спросил collections %s %s — при неизвестном роде вниз идти нельзя", kind, stub.method, stub.path)
			}
		})
	}

	// Контроль: тот же роутер с родом workspace пропускает владельца — иначе
	// 500 выше мог бы быть чем угодно, а не именно веткой рода.
	t.Run("kind=workspace passes", func(t *testing.T) {
		orig := lookupRouteConfig
		lookupRouteConfig = func(string, string) *config.RouteConfig {
			return &config.RouteConfig{Method: "GET", Path: "/api/v1/probe", ScopeParam: "workspace_id", ScopeKind: config.ScopeWorkspace}
		}
		t.Cleanup(func() { lookupRouteConfig = orig })
		stub := &collectionsProxy{status: http.StatusOK, body: membersBody(`{"user_id":"` + scopeKindTestUserID + `","role":"owner"}`)}
		r := gin.New()
		r.GET("/api/v1/probe",
			func(c *gin.Context) { c.Set("user_id", scopeKindTestUserID) },
			ScopeMiddleware(scopeStubConfig(stub)),
			func(c *gin.Context) { c.Status(http.StatusOK) })
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/probe?workspace_id="+scopeKindTestWorkspace, nil))
		if w.Code != http.StatusOK || stub.path != "/api/v1/workspaces/"+scopeKindTestWorkspace+"/members" {
			t.Fatalf("workspace -> %d, спрошено %q; ожидались 200 и вопрос о членах пространства", w.Code, stub.path)
		}
	})
}

const (
	scopeKindTestUserID    = "11111111-2222-3333-4444-555555555555"
	scopeKindTestWorkspace = "dddddddd-0000-4000-8000-000000000004"
)

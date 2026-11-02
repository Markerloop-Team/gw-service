package routes_test

// SDL-172: публичная плоскость /api/v1/data (EP-13 §11.3/§11.4/§17).
//
// Инварианты, которые закрывает этот файл:
//   - группа /data доступна БЕЗ JWT: запрос без Authorization проксируется,
//     а не отбивается 401/403 шлюзом;
//   - клиентский X-User-ID НИКОГДА не доходит до collections-service
//     (единственный источник личности там — Authorization, который
//     проксируется как есть);
//   - preflight OPTIONS гасится на шлюзе с Allow-Origin * и не проксируется;
//   - CORS остальных групп не задет: там прежний allowlist без wildcard.

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"gateway-service/internal/config"
	"gateway-service/internal/handlers"
	"gateway-service/internal/models"
	"gateway-service/internal/routes"
)

// captureProxy — стаб ProxyService, запоминающий заголовки последнего
// проксированного запроса (stubProxy из routes_test.go их отбрасывает).
type captureProxy struct {
	mu          sync.Mutex
	lastHeaders map[string]string
	lastPath    string
	calls       int
}

func (s *captureProxy) ProxyRequest(serviceName, method, path string, headers map[string]string, queryParams map[string]string, body []byte) (*models.ProxyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.lastPath = path
	s.lastHeaders = make(map[string]string, len(headers))
	for k, v := range headers {
		s.lastHeaders[k] = v
	}
	return &models.ProxyResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       []byte(`{"success":true}`),
	}, nil
}

func (s *captureProxy) GetServiceURL(serviceName string) (string, error) {
	return "http://127.0.0.1:1", nil
}

// newDataPlaneRouter — продовый роутер с capture-стабом.
func newDataPlaneRouter(t *testing.T) (*gin.Engine, *captureProxy) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	cfg := &config.Config{}
	cfg.JWT.PublicKeyPEM = "irrelevant-for-data-plane"
	cfg.Security.ServiceKey = testServiceKey

	stub := &captureProxy{}
	proxyHandler := handlers.NewProxyHandler(stub, logger)
	r := gin.New()
	routes.SetupRoutes(r, proxyHandler, cfg, stub, nil, logger)
	return r, stub
}

// TestDataPlaneProxiesWithoutAuth — аноним проходит /data насквозь: ни
// jwtMiddleware, ни permissionMiddleware на группе нет.
func TestDataPlaneProxiesWithoutAuth(t *testing.T) {
	r, stub := newDataPlaneRouter(t)

	w := doRequest(r, http.MethodGet, "/api/v1/data/blog/articles", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/data без токена -> %d, ожидался проксированный 200", w.Code)
	}
	if stub.lastPath != "/api/v1/data/blog/articles" {
		t.Fatalf("путь проксирования %q, ожидался /api/v1/data/blog/articles", stub.lastPath)
	}
}

// TestDataPlaneStripsClientUserIDKeepsAuthorization — X-User-ID от клиента
// вычищен (EP-13 §11.4), Authorization пробрасывается как есть; свой
// X-User-ID шлюз не инжектит (jwtMiddleware на группе нет — user_id в
// контексте не появляется).
func TestDataPlaneStripsClientUserIDKeepsAuthorization(t *testing.T) {
	r, stub := newDataPlaneRouter(t)

	w := doRequest(r, http.MethodGet, "/api/v1/data/blog/articles", map[string]string{
		"X-User-ID":     testUserID,
		"Authorization": "Bearer mlp_test_0123456789ab_secret",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/data -> %d, ожидался 200", w.Code)
	}
	for k := range stub.lastHeaders {
		if strings.EqualFold(k, "X-User-ID") {
			t.Fatalf("клиентский X-User-ID дошёл до upstream: %q=%q", k, stub.lastHeaders[k])
		}
	}
	if got := stub.lastHeaders["Authorization"]; got != "Bearer mlp_test_0123456789ab_secret" {
		t.Fatalf("Authorization не проброшен как есть: %q", got)
	}
}

// TestDataPlanePreflight — OPTIONS гасится шлюзом: 204, Allow-Origin *,
// до проксирования дело не доходит.
func TestDataPlanePreflight(t *testing.T) {
	r, stub := newDataPlaneRouter(t)

	w := doRequest(r, http.MethodOptions, "/api/v1/data/blog/articles", map[string]string{
		"Origin":                        "https://any-customer-site.example",
		"Access-Control-Request-Method": "GET",
	})
	if w.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS /api/v1/data -> %d, ожидался 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, ожидался *", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got == "true" {
		t.Fatalf("credentials на публичной плоскости запрещены, получено Allow-Credentials=true")
	}
	if stub.calls != 0 {
		t.Fatalf("preflight не должен проксироваться, а ушло %d запросов", stub.calls)
	}
}

// TestNonDataRoutesKeepAllowlistCORS — вне /data действует прежний
// allowlist-CORS: произвольный origin не получает wildcard.
func TestNonDataRoutesKeepAllowlistCORS(t *testing.T) {
	r, _ := newDataPlaneRouter(t)

	w := doRequest(r, http.MethodOptions, "/api/v1/auth/login", map[string]string{
		"Origin":                        "https://any-customer-site.example",
		"Access-Control-Request-Method": "POST",
	})
	if got := w.Header().Get("Access-Control-Allow-Origin"); got == "*" {
		t.Fatalf("на админской плоскости появился wildcard-CORS")
	}
}

// TestDataPlaneKeepsPercentEncodingAndSurvivesControlChars — путь уходит
// upstream в percent-кодированном виде (EscapedPath): сырые управляющие
// символы не валят http.NewRequest (раньше 500 на фаззе, найдено nightly
// schemathesis 11 Aug 2026), а %2F не переклеивает сегменты маршрута.
func TestDataPlaneKeepsPercentEncodingAndSurvivesControlChars(t *testing.T) {
	r, stub := newDataPlaneRouter(t)

	w := doRequest(r, http.MethodGet, "/api/v1/data/a%02b/c%2Fd", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET с %%02/%%2F в пути -> %d, ожидался проксированный 200", w.Code)
	}
	if stub.lastPath != "/api/v1/data/a%02b/c%2Fd" {
		t.Fatalf("путь проксирования %q, ожидался percent-кодированный /api/v1/data/a%%02b/c%%2Fd", stub.lastPath)
	}
}

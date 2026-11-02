package routes_test

// SDL-747 (EP-146): вебхук Paddle через шлюз.
//
// Инварианты:
//   - POST /api/v1/billing/paddle/webhook анонимен: без Authorization и без
//     прав доходит до collections-service по тому же пути;
//   - сырое тело и Paddle-Signature приходят в апстрим байт-в-байт — по ним
//     collections-service считает HMAC, любая правка ломает подпись;
//   - тело больше 1 MiB — 413 от шлюза, апстрим не вызывается (и по
//     Content-Length, и для chunked без длины);
//   - в реестре прав маршрута нет: реестр читает только permissionMiddleware.

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
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

const (
	paddleWebhookPath = "/api/v1/billing/paddle/webhook"
	paddleMaxBody     = 1 << 20
	paddleSignature   = "ts=1671552777;h1=eb4d0dc8853be92b7f063b9f3ba5233eb920a09459b6e6b2c26705b4364db151"
)

type billingCall struct {
	service, method, path string
	headers               map[string]string
	body                  []byte
}

// billingProxy запоминает всё, что ушло в апстрим, включая тело.
type billingProxy struct {
	mu    sync.Mutex
	calls []billingCall
}

func (s *billingProxy) ProxyRequest(serviceName, method, path string, headers map[string]string, queryParams map[string]string, body []byte) (*models.ProxyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := make(map[string]string, len(headers))
	for k, v := range headers {
		h[k] = v
	}
	s.calls = append(s.calls, billingCall{serviceName, method, path, h, append([]byte(nil), body...)})
	return &models.ProxyResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       []byte(`{"success":true}`),
	}, nil
}

func (s *billingProxy) GetServiceURL(string) (string, error) { return "http://127.0.0.1:1", nil }

func newBillingRouter(t *testing.T) (*gin.Engine, *billingProxy) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	cfg := &config.Config{}
	cfg.JWT.PublicKeyPEM = "irrelevant-for-anonymous-route"
	cfg.Security.ServiceKey = testServiceKey
	cfg.Services.Dictionary.URL = "http://127.0.0.1:1"

	stub := &billingProxy{}
	r := gin.New()
	routes.SetupRoutes(r, handlers.NewProxyHandler(stub, logger), cfg, stub, nil, logger)
	return r, stub
}

func postWebhook(r *gin.Engine, body []byte, chunked bool, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, paddleWebhookPath, bytes.NewReader(body))
	if chunked {
		// Длина неизвестна шлюзу заранее — потолок держит MaxBytesReader.
		req.ContentLength = -1
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// paddleBody — тело события с пробелами и порядком ключей «как прислал
// Paddle»: шлюз не имеет права его нормализовать.
func paddleBody(size int) []byte {
	head := `{"event_id":"evt_01","event_type":"subscription.created",  "data":{"pad":"`
	tail := `"}}` + "\n"
	pad := size - len(head) - len(tail)
	if pad < 0 {
		pad = 0
	}
	return []byte(head + strings.Repeat("x", pad) + tail)
}

func TestPaddleWebhookIsAnonymousAndProxiedVerbatim(t *testing.T) {
	r, stub := newBillingRouter(t)
	body := paddleBody(512)

	w := postWebhook(r, body, false, map[string]string{
		"Paddle-Signature": paddleSignature,
		"X-User-ID":        testUserID, // клиентская личность не должна дойти вниз
	})
	if w.Code != http.StatusOK {
		t.Fatalf("POST %s без токена -> %d (%s), ожидался проксированный 200", paddleWebhookPath, w.Code, w.Body.String())
	}
	if len(stub.calls) != 1 {
		t.Fatalf("вызовов апстрима %d, ожидался 1", len(stub.calls))
	}
	c := stub.calls[0]
	if c.service != "collections" || c.method != http.MethodPost || c.path != paddleWebhookPath {
		t.Fatalf("ушло в %s %s %s, ожидалось collections POST %s", c.service, c.method, c.path, paddleWebhookPath)
	}
	if !bytes.Equal(c.body, body) {
		t.Fatalf("тело изменено по дороге: ушло %d байт, пришло %d", len(c.body), len(body))
	}
	if got := c.headers["Paddle-Signature"]; got != paddleSignature {
		t.Fatalf("Paddle-Signature в апстриме %q, ожидалось %q", got, paddleSignature)
	}
	if got := c.headers["Content-Type"]; got != "application/json" {
		t.Fatalf("Content-Type в апстриме %q", got)
	}
	for k := range c.headers {
		if strings.EqualFold(k, "X-User-ID") {
			t.Fatalf("клиентский X-User-ID дошёл до апстрима")
		}
	}
}

func TestPaddleWebhookBodyLimit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int
		chunked bool
		want    int
	}{
		{"ровно 1 MiB", paddleMaxBody, false, http.StatusOK},
		{"1 MiB + 1 по Content-Length", paddleMaxBody + 1, false, http.StatusRequestEntityTooLarge},
		{"1 MiB + 1 chunked", paddleMaxBody + 1, true, http.StatusRequestEntityTooLarge},
		{"ровно 1 MiB chunked", paddleMaxBody, true, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, stub := newBillingRouter(t)
			body := paddleBody(tc.size)
			if len(body) != tc.size {
				t.Fatalf("размер тела %d, ожидался %d", len(body), tc.size)
			}
			w := postWebhook(r, body, tc.chunked, map[string]string{"Paddle-Signature": paddleSignature})
			if w.Code != tc.want {
				t.Fatalf("%d байт -> %d (%s), ожидался %d", tc.size, w.Code, w.Body.String(), tc.want)
			}
			switch tc.want {
			case http.StatusOK:
				if len(stub.calls) != 1 || !bytes.Equal(stub.calls[0].body, body) {
					t.Fatalf("тело на потолке не дошло до апстрима целиком")
				}
			default:
				if len(stub.calls) != 0 {
					t.Fatalf("тело больше потолка ушло в апстрим (%d вызовов)", len(stub.calls))
				}
				if !strings.Contains(w.Body.String(), "request_body_too_large") {
					t.Fatalf("тело 413 без кода request_body_too_large: %s", w.Body.String())
				}
			}
		})
	}
}

// Потолок только у вебхука: общий прокси не изменён. Публичная плоскость
// /data с телом больше 1 MiB по-прежнему проксируется.
func TestBodyLimitDoesNotLeakToOtherRoutes(t *testing.T) {
	r, stub := newBillingRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/data/"+testUserID+"/articles", bytes.NewReader(paddleBody(paddleMaxBody+1)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || len(stub.calls) != 1 {
		t.Fatalf("POST /data с телом > 1 MiB -> %d, вызовов %d: лимит вебхука протёк в общий прокси", w.Code, len(stub.calls))
	}
}

func TestPaddleWebhookIsNotInPermissionRegistry(t *testing.T) {
	for _, rc := range config.GetRouteConfigs() {
		if strings.HasPrefix(rc.Path, "/api/v1/billing/") {
			t.Errorf("%s %s в реестре прав (permission %q): вебхук Paddle анонимен", rc.Method, rc.Path, rc.Permission)
		}
	}
}

// Только POST: Paddle шлёт вебхук POST-ом, другие методы шлюз не публикует.
func TestPaddleWebhookIsPostOnly(t *testing.T) {
	r, stub := newBillingRouter(t)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		w := doRequest(r, method, paddleWebhookPath, nil)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s -> %d, ожидался 404", method, paddleWebhookPath, w.Code)
		}
	}
	if len(stub.calls) != 0 {
		t.Fatalf("не-POST дошёл до апстрима (%d вызовов)", len(stub.calls))
	}
}

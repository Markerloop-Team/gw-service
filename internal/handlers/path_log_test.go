package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"gitlab.com/markerloop/go-sdk/pkg/logsafe"
)

// SDL-738: ProxyRedirectToService и ProxySwagger пишут путь запроса через
// logsafe.Path, а ошибку http.Client — без URL с query.
func TestPathLog_NoPersonalData(t *testing.T) {
	const login = "piilogin738"
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxRedirectProxyBody+1))
	}))
	defer big.Close()

	paths := []struct {
		path    string
		secrets []string
	}{
		{"/api/v1/users/email/" + piiEmail, []string{"@", "pii-gw738"}},
		{"/api/v1/users/username/" + login, []string{login}},
	}
	for _, p := range paths {
		cases := []struct {
			name, upstream, target, wantLine string
			wantCode                         int
		}{
			// Апстрим отдал тело больше лимита — 502 и строка «Ответ … больше».
			{"redirect proxy oversized", big.URL, p.path, "Ответ user " + logsafe.Path(p.path) + " больше", http.StatusBadGateway},
			// Апстрим недоступен — 500 и ошибка без пути и query.
			{"redirect proxy unreachable", "http://127.0.0.1:1", p.path + "?login_hint=" + piiEmail + "&u=" + login, "Ошибка проксирования", http.StatusInternalServerError},
			// Swagger: хвост пути уходит и в исходный, и в целевой путь.
			{"swagger", "http://127.0.0.1:1", "/api/docs/user/swagger" + p.path, "Проксирование Swagger: " + logsafe.Path("/api/docs/user/swagger"+p.path) + " -> " + logsafe.Path("/swagger"+p.path), http.StatusOK},
		}
		for _, tc := range cases {
			t.Run(tc.name+" "+p.path, func(t *testing.T) {
				gin.SetMode(gin.TestMode)
				var buf bytes.Buffer
				log := logrus.New()
				log.SetOutput(&buf)
				ph := NewProxyHandler(okProxy{url: tc.upstream}, log)
				r := gin.New()
				r.GET("/api/v1/users/email/:email", ph.ProxyRedirectToService("user"))
				r.GET("/api/v1/users/username/:username", ph.ProxyRedirectToService("user"))
				r.GET("/api/docs/user/swagger/*any", ph.ProxySwagger("user"))

				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.target, nil))
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
			})
		}
	}
}

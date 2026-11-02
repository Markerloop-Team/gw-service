package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"gateway-service/internal/models"

	"gitlab.com/markerloop/go-sdk/pkg/requestid"
)

const piiEmail = "pii-gw738@example.com"

// okProxy answers every call with 200 and an empty JSON body.
type okProxy struct{ url string }

func (okProxy) ProxyRequest(serviceName, method, path string, headers map[string]string, queryParams map[string]string, body []byte) (*models.ProxyResponse, error) {
	return &models.ProxyResponse{StatusCode: http.StatusOK, Body: []byte(`{}`)}, nil
}

func (p okProxy) GetServiceURL(string) (string, error) { return p.url, nil }

func newLoggedProxyEngine(buf *bytes.Buffer) *gin.Engine {
	gin.SetMode(gin.TestMode)
	log := logrus.New()
	log.SetOutput(buf)
	ph := NewProxyHandler(okProxy{url: "http://127.0.0.1:1"}, log)
	r := gin.New()
	r.Use(requestid.Middleware())
	r.GET("/api/v1/users", ph.ProxyToService("user"))
	r.GET("/api/v1/users/email/:email", ph.ProxyToService("user"))
	r.GET("/api/v1/users/username/:username", ph.ProxyToService("user"))
	r.GET("/api/v1/notifications/stream", ph.ProxySSEToService("notification"))
	return r
}

// SDL-738: строки шлюза о проксировании не несут почту и логин ни из пути,
// ни из query.
func TestProxyLog_NoPersonalData(t *testing.T) {
	const login = "piilogin738"
	cases := []struct {
		target, wantRoute string
		secrets           []string
	}{
		{"/api/v1/users?search=" + strings.ReplaceAll(piiEmail, "@", "%40"), "/api/v1/users", []string{"@", "%40", "pii-gw738"}},
		{"/api/v1/users/email/" + piiEmail, "/api/v1/users/email/:email", []string{"@", "pii-gw738"}},
		{"/api/v1/users/username/" + login, "/api/v1/users/username/:username", []string{login}},
		// SSE: апстрим недоступен — ошибка без URL с query.
		{"/api/v1/notifications/stream?email=" + piiEmail, "", []string{"@", "pii-gw738"}},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			var buf bytes.Buffer
			r := newLoggedProxyEngine(&buf)
			r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tc.target, nil))
			out := buf.String()
			if out == "" {
				t.Fatal("expected log output")
			}
			for _, s := range tc.secrets {
				if strings.Contains(out, s) {
					t.Fatalf("log contains %q: %s", s, out)
				}
			}
			if tc.wantRoute != "" && !strings.Contains(out, "Проксирование запроса: GET "+tc.wantRoute+" к сервису user") {
				t.Fatalf("route template missing: %s", out)
			}
		})
	}
}

// Строка «Проксирование запроса» несёт request_id — тот же, что уходит
// клиенту в X-Request-Id и пишется go-sdk Logger в «HTTP Request».
func TestProxyLog_HasRequestID(t *testing.T) {
	var buf bytes.Buffer
	r := newLoggedProxyEngine(&buf)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/users/email/"+piiEmail, nil))
	id := w.Header().Get("X-Request-Id")
	if id == "" {
		t.Fatal("no X-Request-Id in response")
	}
	var line string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, "Проксирование запроса") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no proxy line: %s", buf.String())
	}
	if !strings.Contains(line, "request_id="+id) {
		t.Fatalf("proxy line has no request_id=%s: %s", id, line)
	}
}

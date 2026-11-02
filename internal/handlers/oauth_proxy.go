package handlers

// SDL-692 (EP-20): публикация OAuth 2.1-сервера auth-service (SDL-691) для
// MCP-клиентов.

import (
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"gateway-service/internal/proxy"

	"gitlab.com/markerloop/go-sdk/pkg/logsafe"
	"gitlab.com/markerloop/go-sdk/pkg/response"
)

// ProxyToServicePath — ProxyToService с подменой пути апстрима. Нужен
// /api/.well-known/oauth-authorization-server: хост api.* переписывает
// /(.*) -> /api/$1, а auth-service отдаёт метаданные в корне.
func (ph *ProxyHandler) ProxyToServicePath(serviceName, upstreamPath string) gin.HandlerFunc {
	inner := ph.ProxyToService(serviceName)
	return func(c *gin.Context) {
		originalPath, originalRaw := c.Request.URL.Path, c.Request.URL.RawPath
		c.Request.URL.Path, c.Request.URL.RawPath = upstreamPath, ""
		inner(c)
		c.Request.URL.Path, c.Request.URL.RawPath = originalPath, originalRaw
	}
}

// ProxyRedirectToService проксирует запрос, НЕ следуя редиректам апстрима:
// 302 и его Location уходят клиенту как есть. Нужен GET /oauth/authorize —
// он отвечает 302 на экран согласия или на redirect_uri клиента, а общий
// http.Client прокси (proxy.NewProxyService) редиректы выполняет сам: шлюз
// сходил бы по адресу клиента со своей стороны, а браузер получил бы чужое
// тело вместо перехода.
//
// Заголовки чистятся тем же sanitizeUpstreamHeaders, что и в
// ProxyToService: X-User-ID / x-scope-* от клиента вниз не уходят.
func (ph *ProxyHandler) ProxyRedirectToService(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		serviceURL, err := ph.proxyService.GetServiceURL(serviceName)
		if err != nil {
			response.NotFound(c, "Сервис не найден")
			return
		}
		fullURL := strings.TrimRight(serviceURL, "/") + c.Request.URL.EscapedPath()
		if c.Request.URL.RawQuery != "" {
			fullURL += "?" + c.Request.URL.RawQuery
		}
		req, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, fullURL, nil)
		if err != nil {
			response.BadRequest(c, "Невалидный путь запроса")
			return
		}
		headers := make(map[string]string, len(c.Request.Header))
		for k, v := range c.Request.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}
		sanitizeUpstreamHeaders(headers)
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := noRedirectClient.Do(req)
		if err != nil {
			ph.log.Error("Ошибка проксирования:", proxy.RedactURLError(err))
			response.InternalServerError(c, "Ошибка проксирования запроса")
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxRedirectProxyBody+1))
		if err != nil {
			response.InternalServerError(c, "Ошибка проксирования запроса")
			return
		}
		if len(body) > maxRedirectProxyBody {
			// Не режем молча: обрезанное тело выдало бы битый ответ за целый.
			ph.log.Errorf("Ответ %s %s больше %d байт", serviceName, logsafe.Path(c.Request.URL.Path), maxRedirectProxyBody)
			response.Error(c, http.StatusBadGateway, "Ответ сервиса слишком велик", "upstream_response_too_large")
			return
		}
		for k, v := range resp.Header {
			if k != "Content-Length" && k != "Content-Type" && len(v) > 0 {
				c.Header(k, v[0])
			}
		}
		c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
}

// maxRedirectProxyBody — потолок тела ответа authorize: это 302 или
// короткая ошибка RFC 6749, не поток.
const maxRedirectProxyBody = 1 << 20

// noRedirectClient — клиент, который отдаёт 3xx как ответ, а не идёт по нему.
var noRedirectClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

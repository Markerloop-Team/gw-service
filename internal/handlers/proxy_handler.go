package handlers

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"gateway-service/internal/middleware"
	"gateway-service/internal/proxy"

	// Импорт go-sdk
	"gitlab.com/markerloop/go-sdk/pkg/logsafe"
	"gitlab.com/markerloop/go-sdk/pkg/requestid"
	"gitlab.com/markerloop/go-sdk/pkg/response"
)

// ProxyHandler обрабатывает HTTP запросы для проксирования
type ProxyHandler struct {
	proxyService proxy.ProxyService
	log          *logrus.Logger
}

// sanitizeUpstreamHeaders removes browser-specific headers that should not be forwarded
// to internal services, and strips client-supplied identity headers. CORS must be
// handled at the gateway boundary only.
//
// Why:
//   - Browsers send Origin/Referer/Sec-Fetch* headers.
//   - If we forward Origin to internal services, their CORS middleware may deny the request (403),
//     even though the request is same-origin with the gateway.
//   - X-User-ID is the identity contract between the gateway and internal services: services
//     trust it without further authentication. Anything a client sends under that name must
//     never reach upstream — only the value the gateway derives from a verified JWT may.
//     Callers must run this BEFORE injecting the trusted value from the request context.
func sanitizeUpstreamHeaders(headers map[string]string) {
	for k := range headers {
		lk := strings.ToLower(k)

		// Client-supplied identity headers: only the gateway may set these.
		// x-scope-* is the membership-checked workspace/project scope
		// (SDL-587): a forged one would turn the gateway check into a prop.
		if lk == "x-user-id" || strings.HasPrefix(lk, "x-ml-") || strings.HasPrefix(lk, "x-scope-") {
			delete(headers, k)
			continue
		}

		// Core browser CORS headers
		if lk == "origin" || lk == "referer" {
			delete(headers, k)
			continue
		}

		// Fetch metadata & UA client hints (browser-only)
		if strings.HasPrefix(lk, "sec-fetch-") || strings.HasPrefix(lk, "sec-ch-ua") {
			delete(headers, k)
			continue
		}

		// HTTP/2 priority header from browsers (not useful upstream)
		if lk == "priority" {
			delete(headers, k)
			continue
		}
	}
}

// NewProxyHandler создает новый хендлер проксирования
func NewProxyHandler(proxyService proxy.ProxyService, log *logrus.Logger) *ProxyHandler {
	return &ProxyHandler{
		proxyService: proxyService,
		log:          log,
	}
}

// ProxyToService создает функцию проксирования для указанного сервиса
func (ph *ProxyHandler) ProxyToService(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Читаем тело запроса
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			ph.log.Error("Ошибка чтения тела запроса:", err)
			response.InternalServerError(c, "Ошибка чтения тела запроса")
			return
		}

		// Преобразуем заголовки
		headers := make(map[string]string)
		for key, values := range c.Request.Header {
			if len(values) > 0 {
				headers[key] = values[0]
			}
		}

		// Do not forward browser-specific headers to internal services
		sanitizeUpstreamHeaders(headers)

		// Добавляем user_id из контекста в заголовок X-User-ID для передачи в сервисы
		if userID, exists := c.Get("user_id"); exists {
			if userIDStr, ok := userID.(string); ok {
				headers["X-User-ID"] = userIDStr
			}
		}

		// Скоуп, сверенный ScopeMiddleware (SDL-587). Кладётся после вычистки
		// клиентских x-scope-*, как и X-User-ID выше.
		if scope, exists := c.Get(middleware.ScopeHeadersContextKey); exists {
			if scopeHeaders, ok := scope.(map[string]string); ok {
				for k, v := range scopeHeaders {
					headers[k] = v
				}
			}
		}

		// Преобразуем query параметры
		queryParams := make(map[string]string)
		for key, values := range c.Request.URL.Query() {
			if len(values) > 0 {
				queryParams[key] = values[0]
			}
		}

		// Нормализуем путь для проксирования
		// Если это POST/PUT/DELETE запрос на коллекцию (путь заканчивается на /users, /roles и т.д.),
		// добавляем trailing slash, так как user-service регистрирует маршруты с trailing slash
		//
		// EscapedPath, а не Path: декодированный Path содержит сырые байты
		// клиентских сегментов (управляющие символы валят http.NewRequest →
		// 500 на фаззе /data), а decoded %2F менял бы маршрутизацию upstream.
		// Percent-кодирование клиента сохраняется как есть.
		proxyPath := c.Request.URL.EscapedPath()
		if (c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "DELETE") &&
			!strings.HasSuffix(proxyPath, "/") {
			// Проверяем, является ли это коллекцией (не имеет параметров после последнего слеша)
			if serviceName == "user" && (proxyPath == "/api/v1/users" || proxyPath == "/api/v1/roles" || proxyPath == "/api/v1/permissions") {
				proxyPath = proxyPath + "/"
			}
		}

		// Проксируем запрос. В журнал — шаблон маршрута Gin, а не путь:
		// в /users/email/:email и /users/username/:username путь несёт
		// персональные данные (SDL-738). request_id — тот же, что в строке
		// «HTTP Request» go-sdk Logger: по нему строки связываются.
		proxyLog := logrus.NewEntry(ph.log)
		if id, ok := c.Get(requestid.GinKey); ok {
			if s, ok := id.(string); ok && s != "" {
				proxyLog = proxyLog.WithField("request_id", s)
			}
		}
		proxyLog.Infof("Проксирование запроса: %s %s к сервису %s",
			c.Request.Method, c.FullPath(), serviceName)

		proxyResp, err := ph.proxyService.ProxyRequest(
			serviceName,
			c.Request.Method,
			proxyPath,
			headers,
			queryParams,
			body,
		)
		if err != nil {
			ph.log.Error("Ошибка проксирования:", err)
			if _, ok := err.(*proxy.ServiceNotFoundError); ok {
				response.NotFound(c, "Сервис не найден")
				return
			}
			if _, ok := err.(*proxy.InvalidRequestError); ok {
				response.BadRequest(c, "Невалидный путь запроса")
				return
			}
			response.InternalServerError(c, "Ошибка проксирования запроса")
			return
		}

		// Логируем ответ для диагностики
		ph.log.Infof("Ответ от сервиса %s: статус=%d, content-type=%s, размер_тела=%d байт",
			serviceName, proxyResp.StatusCode, proxyResp.GetContentType(), len(proxyResp.Body))

		// Передаем заголовки ответа от проксируемого сервиса клиенту
		// Это важно для редиректов (Location header) и других заголовков
		for key, value := range proxyResp.Headers {
			// Пропускаем некоторые заголовки, которые должны быть установлены Gin
			if key != "Content-Length" && key != "Content-Type" {
				c.Header(key, value)
			}
		}

		// Возвращаем ответ как есть, без дополнительной обертки
		// Это позволяет клиенту получать истинные ошибки от сервисов
		c.Data(proxyResp.StatusCode, proxyResp.GetContentType(), proxyResp.Body)
	}
}

// ProxyToServiceWithBodyLimit — ProxyToService с потолком тела запроса
// (SDL-747). Общий ProxyToService читает тело io.ReadAll без лимита; здесь
// тело сначала читается через http.MaxBytesReader, и запрос больше maxBytes
// получает 413, не доходя до апстрима. Прочитанные байты кладутся обратно в
// c.Request.Body без изменений, так что дальше работает обычный прокси —
// сырое тело и заголовки (Paddle-Signature) уходят вниз байт-в-байт.
func (ph *ProxyHandler) ProxyToServiceWithBodyLimit(serviceName string, maxBytes int64) gin.HandlerFunc {
	next := ph.ProxyToService(serviceName)
	return func(c *gin.Context) {
		// Заявленная длина больше потолка — отказ без чтения тела.
		if c.Request.ContentLength > maxBytes {
			ph.respondBodyTooLarge(c, serviceName, maxBytes)
			return
		}

		// Chunked или ложный Content-Length ловит сам MaxBytesReader.
		body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				ph.respondBodyTooLarge(c, serviceName, maxBytes)
				return
			}
			ph.log.Error("Ошибка чтения тела запроса:", err)
			response.InternalServerError(c, "Ошибка чтения тела запроса")
			c.Abort()
			return
		}

		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		next(c)
	}
}

func (ph *ProxyHandler) respondBodyTooLarge(c *gin.Context, serviceName string, maxBytes int64) {
	ph.log.Warnf("Тело запроса %s %s к сервису %s больше %d байт — 413",
		c.Request.Method, c.FullPath(), serviceName, maxBytes)
	response.Error(c, http.StatusRequestEntityTooLarge, "Тело запроса слишком большое", "request_body_too_large")
	c.Abort()
}

// ProxySSEToService проксирует SSE (Server-Sent Events) стрим от сервиса
func (ph *ProxyHandler) ProxySSEToService(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		serviceURL, err := ph.proxyService.GetServiceURL(serviceName)
		if err != nil {
			response.NotFound(c, "Сервис не найден")
			return
		}

		// Строим URL
		fullURL := serviceURL + c.Request.URL.Path
		if c.Request.URL.RawQuery != "" {
			fullURL += "?" + c.Request.URL.RawQuery
		}

		// Создаём запрос с контекстом клиента (отмена при disconnect)
		req, err := http.NewRequestWithContext(c.Request.Context(), "GET", fullURL, nil)
		if err != nil {
			ph.log.Error("Ошибка создания SSE запроса:", proxy.RedactURLError(err))
			response.InternalServerError(c, "Ошибка проксирования")
			return
		}

		// Передаём заголовки
		for key, values := range c.Request.Header {
			if len(values) > 0 {
				req.Header.Set(key, values[0])
			}
		}

		// HTTP клиент без таймаута для SSE
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			ph.log.Error("Ошибка SSE подключения к сервису:", proxy.RedactURLError(err))
			response.InternalServerError(c, "Ошибка подключения к сервису")
			return
		}
		defer resp.Body.Close()

		// Если не SSE ответ — проксируем как обычно
		if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
			body, _ := io.ReadAll(resp.Body)
			c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
			return
		}

		// SSE headers
		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		c.Header("X-Accel-Buffering", "no")
		c.Writer.Flush()

		// Стримим построчно
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			c.Writer.WriteString(line + "\n")
			// SSE события разделяются пустой строкой — flush после каждой
			if line == "" {
				c.Writer.Flush()
			}
		}
	}
}

// ProxySwagger проксирует запросы к Swagger UI сервиса
// Gateway: /api/docs/{service}/swagger/* -> Service: /swagger/*
func (ph *ProxyHandler) ProxySwagger(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Извлекаем путь после /swagger/
		swaggerPath := c.Param("any")
		targetPath := "/swagger" + swaggerPath

		headers := make(map[string]string)
		for key, values := range c.Request.Header {
			if len(values) > 0 {
				headers[key] = values[0]
			}
		}
		sanitizeUpstreamHeaders(headers)

		queryParams := make(map[string]string)
		for key, values := range c.Request.URL.Query() {
			if len(values) > 0 {
				queryParams[key] = values[0]
			}
		}

		ph.log.Infof("Проксирование Swagger: %s -> %s к сервису %s", logsafe.Path(c.Request.URL.Path), logsafe.Path(targetPath), serviceName)

		proxyResp, err := ph.proxyService.ProxyRequest(
			serviceName,
			"GET",
			targetPath,
			headers,
			queryParams,
			nil,
		)
		if err != nil {
			ph.log.Error("Ошибка проксирования Swagger:", err)
			if _, ok := err.(*proxy.ServiceNotFoundError); ok {
				response.NotFound(c, "Сервис не найден")
				return
			}
			response.InternalServerError(c, "Ошибка проксирования Swagger")
			return
		}

		for key, value := range proxyResp.Headers {
			if key != "Content-Length" && key != "Content-Type" {
				c.Header(key, value)
			}
		}

		c.Data(proxyResp.StatusCode, proxyResp.GetContentType(), proxyResp.Body)
	}
}

// ProxyHealthCheck проксирует health check запрос на /health endpoint сервиса
func (ph *ProxyHandler) ProxyHealthCheck(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Преобразуем заголовки
		headers := make(map[string]string)
		for key, values := range c.Request.Header {
			if len(values) > 0 {
				headers[key] = values[0]
			}
		}

		// Преобразуем query параметры
		queryParams := make(map[string]string)
		for key, values := range c.Request.URL.Query() {
			if len(values) > 0 {
				queryParams[key] = values[0]
			}
		}

		// Проксируем на /health endpoint сервиса (не зависимо от пути в gateway)
		ph.log.Infof("Проксирование health check к сервису %s", serviceName)

		proxyResp, err := ph.proxyService.ProxyRequest(
			serviceName,
			"GET",
			"/health", // Всегда проксируем на /health внутри сервиса
			headers,
			queryParams,
			nil, // Health check не имеет body
		)
		if err != nil {
			ph.log.Error("Ошибка проксирования health check:", err)
			if _, ok := err.(*proxy.ServiceNotFoundError); ok {
				response.NotFound(c, "Сервис не найден")
				return
			}
			response.InternalServerError(c, "Ошибка проксирования health check")
			return
		}

		// Возвращаем ответ как есть
		c.Data(proxyResp.StatusCode, proxyResp.GetContentType(), proxyResp.Body)
	}
}

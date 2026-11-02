package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"

	"gateway-service/internal/models"
)

// ProxyService интерфейс для проксирования запросов
type ProxyService interface {
	ProxyRequest(serviceName, method, path string, headers map[string]string, queryParams map[string]string, body []byte) (*models.ProxyResponse, error)
	GetServiceURL(serviceName string) (string, error)
}

// proxyService реализация сервиса проксирования
type proxyService struct {
	services map[string]string
	log      *logrus.Logger
	client   *http.Client
}

// NewProxyService создает новый сервис проксирования
func NewProxyService(services map[string]string, timeout time.Duration, log *logrus.Logger) ProxyService {
	return &proxyService{
		services: services,
		log:      log,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// ProxyRequest проксирует запрос к указанному сервису
func (ps *proxyService) ProxyRequest(serviceName, method, path string, headers map[string]string, queryParams map[string]string, body []byte) (*models.ProxyResponse, error) {
	// Получаем URL сервиса
	serviceURL, err := ps.GetServiceURL(serviceName)
	if err != nil {
		return nil, err
	}

	// Создаем полный URL
	fullURL := serviceURL + path

	// Создаем HTTP запрос
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		// Невалидный URL — это дефект ЗАПРОСА клиента (сырые управляющие
		// символы и т.п.), а не сбой шлюза: наверх уходит типизированная
		// ошибка, хендлер отвечает 400, не 500.
		err = RedactURLError(err)
		ps.log.Warn("Невалидный путь проксирования:", err)
		return nil, &InvalidRequestError{Reason: err.Error()}
	}

	// Добавляем заголовки
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Убеждаемся, что Accept-Language передается
	if acceptLanguage := headers["Accept-Language"]; acceptLanguage != "" {
		req.Header.Set("Accept-Language", acceptLanguage)
	}

	// Добавляем query параметры
	if len(queryParams) > 0 {
		q := req.URL.Query()
		for key, value := range queryParams {
			q.Add(key, value)
		}
		req.URL.RawQuery = q.Encode()
	}

	// Добавляем тело запроса
	if len(body) > 0 {
		req.Body = io.NopCloser(bytes.NewReader(body))
	}

	// Выполняем запрос
	resp, err := ps.client.Do(req)
	if err != nil {
		// *url.Error несёт полный URL с query — наверх и в журнал без него.
		err = RedactURLError(err)
		ps.log.Errorf("Ошибка проксирования к %s: %v", serviceName, err)
		return nil, err
	}
	defer resp.Body.Close()

	// Читаем ответ
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		ps.log.Error("Ошибка чтения ответа:", err)
		return nil, err
	}

	// Преобразуем заголовки
	respHeaders := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			respHeaders[key] = values[0]
		}
	}

	// Создаем ответ
	proxyResp := &models.ProxyResponse{
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		Body:       respBody,
	}

	// Парсим JSON ответ, если возможно
	if data, err := proxyResp.ParseResponseBody(); err == nil {
		proxyResp.Data = data
	}

	return proxyResp, nil
}

// GetServiceURL возвращает URL сервиса по имени
func (ps *proxyService) GetServiceURL(serviceName string) (string, error) {
	service, exists := ps.services[serviceName]
	if !exists {
		return "", &ServiceNotFoundError{ServiceName: serviceName}
	}
	return service, nil
}

// ServiceNotFoundError ошибка, когда сервис не найден
type ServiceNotFoundError struct {
	ServiceName string
}

func (e *ServiceNotFoundError) Error() string {
	return "сервис не найден: " + e.ServiceName
}

// InvalidRequestError — запрос клиента не собирается в валидный
// upstream-URL (например, сырые управляющие символы в пути).
type InvalidRequestError struct {
	Reason string
}

func (e *InvalidRequestError) Error() string {
	return "невалидный запрос: " + e.Reason
}

// RedactURLError убирает из *url.Error путь и query запроса — там бывают
// почта и логин (/users/email/:email, ?search=), SDL-738. Остаются операция,
// схема и хост сервиса и исходная причина (ue.Err), так что Timeout() и
// errors.Is/As по причине работают как прежде. Прочие ошибки — без изменений.
func RedactURLError(err error) error {
	ue, ok := err.(*url.Error)
	if !ok {
		return err
	}
	redacted := "[redacted]"
	if u, perr := url.Parse(ue.URL); perr == nil && u.Host != "" {
		redacted = u.Scheme + "://" + u.Host + "/[redacted]"
	}
	return &url.Error{Op: ue.Op, URL: redacted, Err: ue.Err}
}

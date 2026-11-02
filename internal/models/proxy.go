package models

import (
	"encoding/json"
)

// ProxyResponse представляет ответ от проксируемого сервиса
type ProxyResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"body"`
	Data       interface{}       `json:"data,omitempty"`
}

// HealthResponse ответ health check
type HealthResponse struct {
	Service string `json:"service"`
	Status  string `json:"status"`
	Version string `json:"version"`
	Time    string `json:"time"`
}

// ParseResponseBody парсит тело ответа в JSON
func (pr *ProxyResponse) ParseResponseBody() (map[string]interface{}, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(pr.Body, &data); err != nil {
		return nil, err
	}
	return data, nil
}

// IsSuccess проверяет, является ли ответ успешным
func (pr *ProxyResponse) IsSuccess() bool {
	return pr.StatusCode >= 200 && pr.StatusCode < 300
}

// GetContentType возвращает Content-Type заголовка
func (pr *ProxyResponse) GetContentType() string {
	if contentType, exists := pr.Headers["Content-Type"]; exists {
		return contentType
	}
	return "application/json"
}

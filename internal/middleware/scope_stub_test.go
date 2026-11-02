package middleware

// Стаб collections-service для тестов слоёв скоупа и сброса кэша
// (revocation_test.go): один ответ на один вопрос. До SDL-620 жил в
// scope_internal_test.go рядом с покрытием проектного скоупа; проектный
// скоуп снят, стаб остался — он про пространство.

import (
	"io"

	"github.com/sirupsen/logrus"

	"gateway-service/internal/config"
	"gateway-service/internal/models"
)

// collectionsProxy — стаб collections для одного вопроса о пространстве.
type collectionsProxy struct {
	status int
	body   string
	err    error

	method, path string
	headers      map[string]string
}

func (p *collectionsProxy) ProxyRequest(serviceName, method, path string, headers map[string]string, _ map[string]string, _ []byte) (*models.ProxyResponse, error) {
	p.method, p.path = method, path
	p.headers = headers
	if p.err != nil {
		return nil, p.err
	}
	return &models.ProxyResponse{StatusCode: p.status, Body: []byte(p.body)}, nil
}

func (p *collectionsProxy) GetServiceURL(string) (string, error) { return "http://127.0.0.1:1", nil }

func scopeStubConfig(p *collectionsProxy) PermissionMiddlewareConfig {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	cfg := &config.Config{}
	cfg.Security.ServiceKey = "test-service-key"
	return PermissionMiddlewareConfig{Config: cfg, ProxyService: p, Logger: logger}
}

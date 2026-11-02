package routes_test

// SDL-613 S3: шлюз публикует POST /api/v1/auth/token/workspace — обмен
// токена сессии на токен пространства, который реализует auth-service
// (MR !25). Три половины контракта шлюза, каждая ломается одной строкой
// в routes.go:
//
//  1. маршрут существует (Gin-404 = шлюз его не публикует);
//  2. он стоит за jwtMiddleware (аноним получает 401 на шлюзе, а не
//     доходит до auth-service);
//  3. Authorization уходит в auth-service без изменений — auth-service
//     читает из него токен сессии и именно его обменивает; подменённый
//     или вычищенный заголовок означал бы токен пространства для
//     неизвестно кого.
//
// Реестра прав это не касается: на группе /auth permissionMiddleware
// нет вовсе, а инвариант «onboarding-класс, Required:false» держит
// bootstrapRoutes в routes_test.go.

import (
	"net/http"
	"testing"

	"gateway-service/internal/config"
)

const workspaceTokenExchangePath = "/api/v1/auth/token/workspace"

func TestWorkspaceTokenExchangeIsPublishedAndProtected(t *testing.T) {
	stub := &captureProxy{}
	r, token := newRouterWithProxy(t, stub)

	w := doRequest(r, http.MethodPost, workspaceTokenExchangePath, map[string]string{
		"Authorization": "Bearer " + token,
	})
	if w.Code == http.StatusNotFound {
		t.Fatalf("POST %s -> 404: the gateway does not publish the route (auth-service serves it)", workspaceTokenExchangePath)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("POST %s -> %d with a valid session token, expected the proxy to answer 200; body: %s", workspaceTokenExchangePath, w.Code, w.Body.String())
	}
	if stub.calls != 1 {
		t.Fatalf("expected exactly one upstream call, got %d", stub.calls)
	}
	if got := stub.lastHeaders["Authorization"]; got != "Bearer "+token {
		t.Errorf("Authorization must reach auth-service unchanged (it carries the session token being exchanged); got %q", got)
	}
	if got := stub.lastHeaders["X-User-ID"]; got != testUserID {
		t.Errorf("X-User-ID = %q, want the actor from the JWT %q", got, testUserID)
	}

	anon := doRequest(r, http.MethodPost, workspaceTokenExchangePath, nil)
	if anon.Code != http.StatusUnauthorized {
		t.Errorf("POST %s without a token -> %d, expected 401: the exchange is for the session in the token", workspaceTokenExchangePath, anon.Code)
	}
	if stub.calls != 1 {
		t.Errorf("an anonymous call must be stopped at the gateway, but auth-service was called %d times in total", stub.calls)
	}
}

// TestWorkspaceTokenExchangeNeedsNoWorkspaceScope — пространство здесь
// запрашиваемый объект, а не контекст вызова: у вызывающего ещё нет токена
// пространства, поэтому запись реестра с ScopeKind или Required:true
// вернула бы тупик, ради выхода из которого ручка и заводилась.
func TestWorkspaceTokenExchangeNeedsNoWorkspaceScope(t *testing.T) {
	rc := config.FindRouteConfig(http.MethodPost, workspaceTokenExchangePath)
	if rc == nil {
		return // группа /auth не читает реестр — отсутствие записи и есть норма
	}
	if rc.Required {
		t.Errorf("%s is Required:true in the permission registry — a caller without any role must be able to exchange a session token", workspaceTokenExchangePath)
	}
	if rc.ScopeKind != "" {
		t.Errorf("%s declares ScopeKind %v — the workspace is the requested object, the caller holds no workspace token yet", workspaceTokenExchangePath, rc.ScopeKind)
	}
}

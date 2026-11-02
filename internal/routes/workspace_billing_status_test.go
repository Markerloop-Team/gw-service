package routes_test

// SDL-748 (EP-146): состояние оплаты пространства для экрана тарифа.
// Инварианты те же, что у checkout:
//   - маршрут есть и в Gin, и в реестре прав (без записи — 403 шлюза, без
//     Gin-маршрута — 404);
//   - запись Required:false и без скоупа: участника проверяет
//     collections-service (чужой — 404), права collections:ws:billing:read
//     у бутстрап-юзера в user-service нет;
//   - запрос уходит только в collections тем же путём, с актором из JWT.

import (
	"net/http"
	"testing"

	"gateway-service/internal/config"
)

const (
	billingStatusPattern = "/api/v1/workspaces/:id/billing"
	billingStatusPath    = "/api/v1/workspaces/" + ownWorkspaceID + "/billing"
)

func TestWorkspaceBillingStatusRegisteredInGin(t *testing.T) {
	r, _ := newTestRouter(t, true)
	for _, ri := range r.Routes() {
		if ri.Method == http.MethodGet && ri.Path == billingStatusPattern {
			return
		}
	}
	t.Errorf("GET %s не зарегистрирован в Gin (internal/routes/routes.go) — фронт получит 404", billingStatusPattern)
}

func TestWorkspaceBillingStatusRegistryEntry(t *testing.T) {
	rc := config.FindRouteConfig(http.MethodGet, billingStatusPattern)
	if rc == nil {
		t.Fatalf("GET %s: нет записи в реестре прав — шлюз ответит 403", billingStatusPattern)
	}
	if rc.Permission != "collections:ws:billing:read" {
		t.Errorf("Permission=%q, ожидалось collections:ws:billing:read", rc.Permission)
	}
	if rc.Required {
		t.Error("Required:true — у участника нет права collections:ws:billing:read в user-service, шлюз ответит 403")
	}
	if rc.ScopeKind != "" || rc.ScopeParam != "" {
		t.Errorf("скоуп %q/%q: участника проверяет collections, как у checkout", rc.ScopeKind, rc.ScopeParam)
	}
}

// Даже при чекере, отказывающем во всём, маршрут проходит.
func TestWorkspaceBillingStatusReachableWithoutAnyPermission(t *testing.T) {
	r, token := newTestRouter(t, false)
	w := doRequest(r, http.MethodGet, billingStatusPath, map[string]string{"Authorization": "Bearer " + token})
	if w.Code != http.StatusOK {
		t.Errorf("GET %s при отказе во всех правах -> %d (%s), ожидался 200", billingStatusPath, w.Code, w.Body.String())
	}
}

// Запрос уходит только в collections-service тем же путём, с актором из JWT,
// без похода в check-permission.
func TestWorkspaceBillingStatusProxiedToCollectionsAsActor(t *testing.T) {
	_, stub := doScoped(t, http.MethodGet, billingStatusPath, "", nil)
	var hit bool
	for _, c := range stub.callsTo("collections") {
		if c.method == http.MethodGet && c.path == billingStatusPath {
			hit = true
			if c.headers["X-User-ID"] != testUserID {
				t.Errorf("X-User-ID=%q, ожидался актор %s", c.headers["X-User-ID"], testUserID)
			}
		}
	}
	if !hit {
		t.Errorf("GET %s не дошёл до collections-service тем же путём: %+v", billingStatusPath, stub.callsTo("collections"))
	}
	if n := len(stub.permissionChecks()); n != 0 {
		t.Errorf("check-permission вызван %d раз — запись Required:false в user-service ходить не должна", n)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	for _, c := range stub.calls {
		if c.path == billingStatusPath && c.service != "collections" {
			t.Errorf("GET %s ушёл в %s, а не в collections", billingStatusPath, c.service)
		}
	}
}

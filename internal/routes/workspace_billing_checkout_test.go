package routes_test

// SDL-748 (EP-146): переход пространства на Pro через Paddle Checkout.
// Инварианты:
//   - маршрут есть и в Gin, и в реестре прав (без записи шлюз ответит 403
//     «Маршрут не найден в конфигурации», без Gin-маршрута — 404);
//   - запись Required:false и без скоупа, как /members: владельца проверяет
//     collections-service (не владелец — 403, посторонний — 404), а права
//     collections:ws:billing:checkout у владельца в user-service нет;
//   - запрос уходит в collections тем же путём, с актором из JWT и телом
//     {"plan","period"} без изменений.

import (
	"net/http"
	"testing"

	"gateway-service/internal/config"
)

const (
	billingCheckoutPattern = "/api/v1/workspaces/:id/billing/checkout"
	billingCheckoutPath    = "/api/v1/workspaces/" + ownWorkspaceID + "/billing/checkout"
	billingCheckoutBody    = `{"plan":"pro","period":"year"}`
)

func TestWorkspaceBillingCheckoutRegisteredInGin(t *testing.T) {
	r, _ := newTestRouter(t, true)
	for _, ri := range r.Routes() {
		if ri.Method == http.MethodPost && ri.Path == billingCheckoutPattern {
			return
		}
	}
	t.Errorf("POST %s не зарегистрирован в Gin (internal/routes/routes.go) — фронт получит 404", billingCheckoutPattern)
}

func TestWorkspaceBillingCheckoutRegistryEntry(t *testing.T) {
	rc := config.FindRouteConfig(http.MethodPost, billingCheckoutPattern)
	if rc == nil {
		t.Fatalf("POST %s: нет записи в реестре прав — шлюз ответит 403", billingCheckoutPattern)
	}
	if rc.Required {
		t.Error("Required:true — у владельца нет права collections:ws:billing:checkout в user-service, шлюз ответит 403")
	}
	if rc.ScopeKind != "" || rc.ScopeParam != "" {
		t.Errorf("скоуп %q/%q: владельца проверяет collections, как у /members", rc.ScopeKind, rc.ScopeParam)
	}
}

// Даже при чекере, отказывающем во всём, маршрут проходит: запись в реестре
// есть и она Required:false.
func TestWorkspaceBillingCheckoutReachableWithoutAnyPermission(t *testing.T) {
	r, token := newTestRouter(t, false)
	w := doRequest(r, http.MethodPost, billingCheckoutPath, map[string]string{"Authorization": "Bearer " + token})
	if w.Code != http.StatusOK {
		t.Errorf("POST %s при отказе во всех правах -> %d (%s), ожидался 200", billingCheckoutPath, w.Code, w.Body.String())
	}
}

// Запрос уходит только в collections-service тем же путём, с актором из JWT
// и телом без изменений.
func TestWorkspaceBillingCheckoutProxiedToCollectionsAsActor(t *testing.T) {
	_, stub := doScoped(t, http.MethodPost, billingCheckoutPath, billingCheckoutBody, nil)
	var hit bool
	for _, c := range stub.callsTo("collections") {
		if c.method == http.MethodPost && c.path == billingCheckoutPath {
			hit = true
			if c.headers["X-User-ID"] != testUserID {
				t.Errorf("X-User-ID=%q, ожидался актор %s", c.headers["X-User-ID"], testUserID)
			}
			if string(c.body) != billingCheckoutBody {
				t.Errorf("тело в апстриме %q, ожидалось %q", c.body, billingCheckoutBody)
			}
		}
	}
	if !hit {
		t.Errorf("POST %s не дошёл до collections-service тем же путём: %+v", billingCheckoutPath, stub.callsTo("collections"))
	}
	if n := len(stub.permissionChecks()); n != 0 {
		t.Errorf("check-permission вызван %d раз — запись Required:false в user-service ходить не должна", n)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	for _, c := range stub.calls {
		if c.path == billingCheckoutPath && c.service != "collections" {
			t.Errorf("POST %s ушёл в %s, а не в collections", billingCheckoutPath, c.service)
		}
	}
}

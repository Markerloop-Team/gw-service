package routes_test

// SDL-749 (EP-146): портал покупателя Paddle — отмена, смена карты, счета.
// Инварианты:
//   - маршрут есть и в Gin, и в реестре прав (без записи шлюз ответит 403
//     «Маршрут не найден в конфигурации», без Gin-маршрута — 404);
//   - запись Required:false и без скоупа, как /members: владельца проверяет
//     collections-service (не владелец — 403, посторонний — 404), а права
//     collections:ws:billing:portal у владельца в user-service нет;
//   - запрос уходит в collections тем же путём, с актором из JWT и телом
//     без изменений.

import (
	"net/http"
	"testing"

	"gateway-service/internal/config"
)

const (
	billingPortalPattern = "/api/v1/workspaces/:id/billing/portal"
	billingPortalPath    = "/api/v1/workspaces/" + ownWorkspaceID + "/billing/portal"
	billingPortalBody    = `{}`
)

func TestWorkspaceBillingPortalRegisteredInGin(t *testing.T) {
	r, _ := newTestRouter(t, true)
	for _, ri := range r.Routes() {
		if ri.Method == http.MethodPost && ri.Path == billingPortalPattern {
			return
		}
	}
	t.Errorf("POST %s не зарегистрирован в Gin (internal/routes/routes.go) — фронт получит 404", billingPortalPattern)
}

func TestWorkspaceBillingPortalRegistryEntry(t *testing.T) {
	rc := config.FindRouteConfig(http.MethodPost, billingPortalPattern)
	if rc == nil {
		t.Fatalf("POST %s: нет записи в реестре прав — шлюз ответит 403", billingPortalPattern)
	}
	if rc.Required {
		t.Error("Required:true — у владельца нет права collections:ws:billing:portal в user-service, шлюз ответит 403")
	}
	if rc.ScopeKind != "" || rc.ScopeParam != "" {
		t.Errorf("скоуп %q/%q: владельца проверяет collections, как у /members", rc.ScopeKind, rc.ScopeParam)
	}
}

// Даже при чекере, отказывающем во всём, маршрут проходит: запись в реестре
// есть и она Required:false.
func TestWorkspaceBillingPortalReachableWithoutAnyPermission(t *testing.T) {
	r, token := newTestRouter(t, false)
	w := doRequest(r, http.MethodPost, billingPortalPath, map[string]string{"Authorization": "Bearer " + token})
	if w.Code != http.StatusOK {
		t.Errorf("POST %s при отказе во всех правах -> %d (%s), ожидался 200", billingPortalPath, w.Code, w.Body.String())
	}
}

// Запрос уходит только в collections-service тем же путём, с актором из JWT
// и телом без изменений.
func TestWorkspaceBillingPortalProxiedToCollectionsAsActor(t *testing.T) {
	_, stub := doScoped(t, http.MethodPost, billingPortalPath, billingPortalBody, nil)
	var hit bool
	for _, c := range stub.callsTo("collections") {
		if c.method == http.MethodPost && c.path == billingPortalPath {
			hit = true
			if c.headers["X-User-ID"] != testUserID {
				t.Errorf("X-User-ID=%q, ожидался актор %s", c.headers["X-User-ID"], testUserID)
			}
			if string(c.body) != billingPortalBody {
				t.Errorf("тело в апстриме %q, ожидалось %q", c.body, billingPortalBody)
			}
		}
	}
	if !hit {
		t.Errorf("POST %s не дошёл до collections-service тем же путём: %+v", billingPortalPath, stub.callsTo("collections"))
	}
	if n := len(stub.permissionChecks()); n != 0 {
		t.Errorf("check-permission вызван %d раз — запись Required:false в user-service ходить не должна", n)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	for _, c := range stub.calls {
		if c.path == billingPortalPath && c.service != "collections" {
			t.Errorf("POST %s ушёл в %s, а не в collections", billingPortalPath, c.service)
		}
	}
}

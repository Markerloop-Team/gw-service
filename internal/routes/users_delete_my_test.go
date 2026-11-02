package routes_test

// SDL-742: DELETE /api/v1/users/my — self-deletion of an account.
//
// Pinned: the route is published (not a Gin 404 and not DELETE /users/:id
// with id "my"), it sits behind JWT, it is NOT short-circuited like the GET
// read of "my" — user-service is asked for the permission — and with the
// permission granted the request reaches user-service on the same path.

import (
	"net/http"
	"testing"

	"gateway-service/internal/config"
)

const deleteMyPath = "/api/v1/users/my"

func TestDeleteMyRequiresToken(t *testing.T) {
	r, _ := newRouterWithProxy(t, &policyJournalProxy{grant: true})
	w := doRequest(r, http.MethodDelete, deleteMyPath, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("DELETE %s without a token -> %d, want 401", deleteMyPath, w.Code)
	}
}

func TestDeleteMyAsksPermissionAndProxies(t *testing.T) {
	stub := &policyJournalProxy{grant: true}
	r, token := newRouterWithProxy(t, stub)

	w := doRequest(r, http.MethodDelete, deleteMyPath, map[string]string{"Authorization": "Bearer " + token})
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE %s with permission -> %d, want upstream status; body: %s", deleteMyPath, w.Code, w.Body.String())
	}
	if stub.checks != 1 {
		t.Errorf("permission checks = %d, want 1: a write on \"my\" must not short-circuit", stub.checks)
	}
	if len(stub.upstream) != 1 || stub.upstream[0] != "user DELETE "+deleteMyPath {
		t.Fatalf("upstream calls = %v, want exactly [user DELETE %s]", stub.upstream, deleteMyPath)
	}
}

func TestDeleteMyDeniedWithoutPermission(t *testing.T) {
	stub := &policyJournalProxy{grant: false}
	r, token := newRouterWithProxy(t, stub)

	w := doRequest(r, http.MethodDelete, deleteMyPath, map[string]string{"Authorization": "Bearer " + token})
	if w.Code != http.StatusForbidden {
		t.Fatalf("DELETE %s without permission -> %d, want 403", deleteMyPath, w.Code)
	}
	if len(stub.upstream) != 0 {
		t.Errorf("user-service reached without permission: %v", stub.upstream)
	}
}

func TestDeleteMyRegistryEntry(t *testing.T) {
	rc := config.FindRouteConfig(http.MethodDelete, deleteMyPath)
	if rc == nil {
		t.Fatal("no registry entry for DELETE /api/v1/users/my: the gateway fails closed with 403")
	}
	if rc.Permission != "users:delete:own" || !rc.Required {
		t.Errorf("registry entry = %+v, want users:delete:own, Required:true", *rc)
	}
}

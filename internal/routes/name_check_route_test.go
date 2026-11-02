package routes_test

// SDL-758 (EP-155): шлюз публикует GET /api/v1/workspaces/name-check —
// проверку адреса до создания первого пространства. Запись реестра
// Required:false и без скоупа (у пользователя ещё нет ни роли, ни
// workspace), запрос доходит до collections тем же путём со строкой
// запроса, а не уходит в GET /workspaces/:id с id="name-check".

import (
	"net/http"
	"testing"

	"gateway-service/internal/config"
)

const nameCheckPath = "/api/v1/workspaces/name-check"

func TestNameCheckRegistryEntry(t *testing.T) {
	rc := config.FindRouteConfig(http.MethodGet, nameCheckPath)
	if rc == nil {
		t.Fatalf("GET %s: нет записи в реестре — шлюз ответит 403", nameCheckPath)
	}
	if rc.Required {
		t.Errorf("GET %s: Required:true — пользователь без ролей получит 403 (ловушка бутстрапа)", nameCheckPath)
	}
	if rc.ScopeParam != "" || rc.ScopeKind != "" {
		t.Errorf("GET %s: скоуп %q/%q — до первого пространства скоупа нет", nameCheckPath, rc.ScopeParam, rc.ScopeKind)
	}
	if rc.Permission != "collections:ws:name-check" {
		t.Errorf("GET %s: permission %q", nameCheckPath, rc.Permission)
	}
}

func TestNameCheckReachesCollections(t *testing.T) {
	stub := &membershipProxy{}
	r, token := newRouterWithProxy(t, stub)
	w := doRequest(r, http.MethodGet, nameCheckPath+"?slug=acme-studio", map[string]string{"Authorization": "Bearer " + token})
	// Стаб отвечает 404 на всё, чего не знает: ответ апстрима шлюз
	// отдаёт как есть, а 401/403 значили бы отказ самого шлюза.
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Fatalf("GET %s -> %d (%s): шлюз отказал до апстрима", nameCheckPath, w.Code, w.Body.String())
	}
	calls := stub.callsTo("collections")
	if len(calls) != 1 || calls[0].method != http.MethodGet || calls[0].path != nameCheckPath {
		t.Fatalf("к collections ушло %+v, ожидался один GET %s", calls, nameCheckPath)
	}
	if got := calls[0].query["slug"]; got != "acme-studio" {
		t.Fatalf("slug до апстрима не дошёл: %q", got)
	}
}

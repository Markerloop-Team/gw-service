package routes_test

// SDL-660: восстановление пространства из корзины. Маршрут опубликован,
// доходит до collections-service тем же путём, не требует прав из реестра
// (Required:false) и без скоупа — владельца проверяет сам сервис, а выдача
// участников для пространства в корзине отвечает 404 (скоуп дал бы 403).

import (
	"net/http"
	"testing"

	"gateway-service/internal/config"
)

const restorePath = "/api/v1/workspaces/" + ownWorkspaceID + "/restore"

// Даже при чекере, отказывающем во всём, маршрут проходит: запись в
// реестре есть и она Required:false.
func TestWorkspaceRestoreReachableWithoutAnyPermission(t *testing.T) {
	r, token := newTestRouter(t, false)
	w := doRequest(r, http.MethodPost, restorePath, map[string]string{"Authorization": "Bearer " + token})
	if w.Code != http.StatusOK {
		t.Errorf("POST %s -> %d: ожидался 200 (запись в реестре обязана быть и быть Required:false)", restorePath, w.Code)
	}
}

// Запрос уходит в collections-service тем же путём, с актором из JWT, и
// только туда.
func TestWorkspaceRestoreProxiedToCollectionsAsActor(t *testing.T) {
	_, stub := doScoped(t, http.MethodPost, restorePath, "", nil)
	var hit bool
	for _, c := range stub.callsTo("collections") {
		if c.method == http.MethodPost && c.path == restorePath {
			hit = true
			if c.headers["X-User-ID"] != testUserID {
				t.Errorf("X-User-ID=%q, ожидался актор %s", c.headers["X-User-ID"], testUserID)
			}
		}
	}
	if !hit {
		t.Errorf("POST %s не дошёл до collections-service тем же путём: %+v", restorePath, stub.callsTo("collections"))
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	for _, c := range stub.calls {
		if c.path == restorePath && c.service != "collections" {
			t.Errorf("POST %s ушёл в %s, а не в collections", restorePath, c.service)
		}
	}
}

func TestWorkspaceRestoreRegistryEntry(t *testing.T) {
	rc := config.FindRouteConfig(http.MethodPost, "/api/v1/workspaces/:id/restore")
	if rc == nil {
		t.Fatal("POST /api/v1/workspaces/:id/restore: нет записи в реестре — шлюз ответит 403 «Маршрут не найден в конфигурации»")
	}
	if rc.Required {
		t.Error("Required:true — права уровня шлюза тут ни при чём, владельца проверяет collections")
	}
	if rc.ScopeKind != "" || rc.ScopeParam != "" {
		t.Errorf("скоуп %q/%q: выдача участников для пространства в корзине — 404, скоуп дал бы 403 всегда", rc.ScopeKind, rc.ScopeParam)
	}
}

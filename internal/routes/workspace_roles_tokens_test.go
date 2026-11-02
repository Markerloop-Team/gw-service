package routes_test

// SDL-620a: роли и токены workspace (добавлены в collections-service в
// SDL-617a). Маршруты опубликованы, доходят до collections-service тем же
// путём и не требуют прав из реестра (Required:false) — причастность и роль
// проверяет сам сервис.

import (
	"net/http"
	"testing"

	"gateway-service/internal/config"
)

const (
	testRoleID  = "22222222-2222-2222-2222-222222222222"
	testTokenID = "33333333-3333-3333-3333-333333333333"
)

var workspaceRoleTokenRoutes = []struct{ method, path, body string }{
	{http.MethodGet, "/api/v1/workspaces/" + ownWorkspaceID + "/roles", ""},
	{http.MethodPost, "/api/v1/workspaces/" + ownWorkspaceID + "/roles", `{"name":"editor"}`},
	{http.MethodPatch, "/api/v1/workspaces/" + ownWorkspaceID + "/roles/" + testRoleID, `{"name":"editor"}`},
	{http.MethodDelete, "/api/v1/workspaces/" + ownWorkspaceID + "/roles/" + testRoleID, ""},
	{http.MethodGet, "/api/v1/workspaces/" + ownWorkspaceID + "/tokens", ""},
	{http.MethodPost, "/api/v1/workspaces/" + ownWorkspaceID + "/tokens", `{"name":"ci"}`},
	{http.MethodPost, "/api/v1/workspaces/" + ownWorkspaceID + "/tokens/" + testTokenID + "/rotate", ""},
	{http.MethodDelete, "/api/v1/workspaces/" + ownWorkspaceID + "/tokens/" + testTokenID, ""},
}

// Даже при чекере, отказывающем во всём, маршруты проходят: запись в
// реестре есть и она Required:false.
func TestWorkspaceRolesTokensReachableWithoutAnyPermission(t *testing.T) {
	r, token := newTestRouter(t, false)
	for _, rt := range workspaceRoleTokenRoutes {
		w := doRequest(r, rt.method, rt.path, map[string]string{"Authorization": "Bearer " + token})
		if w.Code != http.StatusOK {
			t.Errorf("%s %s -> %d: ожидался 200 (запись в реестре обязана быть и быть Required:false)", rt.method, rt.path, w.Code)
		}
	}
}

// Запрос уходит в collections-service тем же путём, с актором из JWT.
func TestWorkspaceRolesTokensProxiedToCollectionsAsActor(t *testing.T) {
	for _, rt := range workspaceRoleTokenRoutes {
		_, stub := doScoped(t, rt.method, rt.path, rt.body, nil)
		var hit bool
		for _, c := range stub.callsTo("collections") {
			if c.method == rt.method && c.path == rt.path {
				hit = true
				if c.headers["X-User-ID"] != testUserID {
					t.Errorf("%s %s: X-User-ID=%q, ожидался актор %s", rt.method, rt.path, c.headers["X-User-ID"], testUserID)
				}
			}
		}
		if !hit {
			t.Errorf("%s %s не дошёл до collections-service тем же путём: %+v", rt.method, rt.path, stub.callsTo("collections"))
		}
	}
}

func TestWorkspaceRolesTokensRegistryEntriesAreNotRequired(t *testing.T) {
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/workspaces/:id/roles"},
		{http.MethodPost, "/api/v1/workspaces/:id/roles"},
		{http.MethodPatch, "/api/v1/workspaces/:id/roles/:id"},
		{http.MethodDelete, "/api/v1/workspaces/:id/roles/:id"},
		{http.MethodGet, "/api/v1/workspaces/:id/tokens"},
		{http.MethodPost, "/api/v1/workspaces/:id/tokens"},
		{http.MethodPost, "/api/v1/workspaces/:id/tokens/:id/rotate"},
		{http.MethodDelete, "/api/v1/workspaces/:id/tokens/:id"},
	} {
		rc := config.FindRouteConfig(rt.method, rt.path)
		if rc == nil {
			t.Errorf("%s %s: нет записи в реестре — шлюз ответит 403 «Маршрут не найден в конфигурации»", rt.method, rt.path)
			continue
		}
		if rc.Required {
			t.Errorf("%s %s: Required:true — права уровня шлюза тут ни при чём", rt.method, rt.path)
		}
	}
}

package routes_test

// SDL-609: участники workspace. Маршруты опубликованы, доходят до
// collections-service тем же путём и не требуют прав из реестра
// (Required:false) — роль проверяет сам сервис.

import (
	"net/http"
	"testing"

	"gateway-service/internal/config"
)

var workspaceMemberRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/v1/workspaces/" + ownWorkspaceID + "/members"},
	{http.MethodPut, "/api/v1/workspaces/" + ownWorkspaceID + "/members"},
	{http.MethodDelete, "/api/v1/workspaces/" + ownWorkspaceID + "/members/" + testUserID},
}

// Даже при чекере, отказывающем во всём, маршруты проходят: запись в
// реестре есть и она Required:false.
func TestWorkspaceMembersReachableWithoutAnyPermission(t *testing.T) {
	r, token := newTestRouter(t, false)
	for _, rt := range workspaceMemberRoutes {
		w := doRequest(r, rt.method, rt.path, map[string]string{"Authorization": "Bearer " + token})
		if w.Code != http.StatusOK {
			t.Errorf("%s %s -> %d: ожидался 200 (запись в реестре обязана быть и быть Required:false)", rt.method, rt.path, w.Code)
		}
	}
}

// Запрос уходит в collections-service тем же путём, с актором из JWT.
func TestWorkspaceMembersProxiedToCollectionsAsActor(t *testing.T) {
	for _, rt := range workspaceMemberRoutes {
		body := ""
		if rt.method == http.MethodPut {
			body = `{"user_id":"` + testUserID + `"}`
		}
		// Код ответа тут — ответ стаба апстрима, не шлюза; важен сам вызов.
		_, stub := doScoped(t, rt.method, rt.path, body, nil)
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

func TestWorkspaceMembersRegistryEntriesAreNotRequired(t *testing.T) {
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/workspaces/:id/members"},
		{http.MethodPut, "/api/v1/workspaces/:id/members"},
		{http.MethodDelete, "/api/v1/workspaces/:id/members/:id"},
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

package routes_test

// SDL-615 S6: приглашения в workspace. Четыре ручки владельца под
// /workspaces/:id/invites и две ручки получателя под /invites. Все
// опубликованы, доходят до collections-service тем же путём с актором из
// JWT и не требуют прав из реестра (Required:false): роль и причастность
// проверяет сам сервис, а получатель до принятия вообще не участник.

import (
	"net/http"
	"strings"
	"testing"

	"gateway-service/internal/config"
)

const testInviteID = "44444444-4444-4444-4444-444444444444"

var workspaceInviteRoutes = []struct{ method, path, body string }{
	{http.MethodGet, "/api/v1/workspaces/" + ownWorkspaceID + "/invites", ""},
	{http.MethodPost, "/api/v1/workspaces/" + ownWorkspaceID + "/invites", `{"email":"guest@example.com","locale":"en"}`},
	{http.MethodPost, "/api/v1/workspaces/" + ownWorkspaceID + "/invites/" + testInviteID + "/resend", ""},
	{http.MethodDelete, "/api/v1/workspaces/" + ownWorkspaceID + "/invites/" + testInviteID, ""},
	{http.MethodPost, "/api/v1/invites/preview", `{"token":"mli_x"}`},
	{http.MethodPost, "/api/v1/invites/accept", `{"token":"mli_x"}`},
}

// Даже при чекере, отказывающем во всём, маршруты проходят: запись в
// реестре есть и она Required:false.
func TestWorkspaceInvitesReachableWithoutAnyPermission(t *testing.T) {
	r, token := newTestRouter(t, false)
	for _, rt := range workspaceInviteRoutes {
		w := doRequest(r, rt.method, rt.path, map[string]string{"Authorization": "Bearer " + token})
		if w.Code != http.StatusOK {
			t.Errorf("%s %s -> %d: ожидался 200 (запись в реестре обязана быть и быть Required:false)", rt.method, rt.path, w.Code)
		}
	}
}

// Без JWT — 401: группа /invites сидит за jwtMiddleware, анонимного
// принятия нет.
func TestInviteRecipientRoutesRequireJWT(t *testing.T) {
	r, _ := newTestRouter(t, true)
	for _, path := range []string{"/api/v1/invites/preview", "/api/v1/invites/accept"} {
		w := doRequest(r, http.MethodPost, path, nil)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("POST %s без токена -> %d, ожидался 401", path, w.Code)
		}
	}
}

// Запрос уходит в collections-service тем же путём, с актором из JWT.
func TestWorkspaceInvitesProxiedToCollectionsAsActor(t *testing.T) {
	for _, rt := range workspaceInviteRoutes {
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

// Подделанные клиентом X-User-ID и X-Scope-* не доходят до
// collections-service: вниз уходит только актор из JWT, а скоуп для этих
// маршрутов шлюз не объявляет и не инжектит вовсе. Иначе приглашающий
// назвался бы владельцем чужого пространства одним заголовком. Ключи
// сверяются без учёта регистра: net/http канонизирует клиентский
// заголовок в X-User-Id, и он лёг бы рядом с доверенным X-User-ID.
func TestWorkspaceInvitesForgedIdentityHeadersNeverReachUpstream(t *testing.T) {
	forged := map[string]string{
		"X-User-ID":            otherUserID,
		"X-Scope-Workspace-ID": foreignWorkspaceID,
		"X-Scope-Project-ID":   foreignWorkspaceID,
	}
	for _, rt := range workspaceInviteRoutes {
		_, stub := doScoped(t, rt.method, rt.path, rt.body, forged)
		var hit bool
		for _, c := range stub.callsTo("collections") {
			if c.method != rt.method || c.path != rt.path {
				continue
			}
			hit = true
			for k, v := range c.headers {
				lk := strings.ToLower(k)
				if lk == "x-user-id" && v != testUserID {
					t.Errorf("%s %s: клиентский %s=%q дошёл до collections, ожидался только актор %s", rt.method, rt.path, k, v, testUserID)
				}
				if strings.HasPrefix(lk, "x-scope-") {
					t.Errorf("%s %s: вниз ушёл %s=%q — маршрут вне скоупа, шлюз не пропускает чужой и не инжектит свой", rt.method, rt.path, k, v)
				}
			}
		}
		if !hit {
			t.Errorf("%s %s не дошёл до collections-service тем же путём: %+v", rt.method, rt.path, stub.callsTo("collections"))
		}
	}
}

func TestWorkspaceInvitesRegistryEntriesAreNotRequiredAndUnscoped(t *testing.T) {
	for _, rt := range []struct{ method, path, perm string }{
		{http.MethodGet, "/api/v1/workspaces/:id/invites", "collections:ws:invites:read"},
		{http.MethodPost, "/api/v1/workspaces/:id/invites", "collections:ws:invites:create"},
		{http.MethodPost, "/api/v1/workspaces/:id/invites/:id/resend", "collections:ws:invites:resend"},
		{http.MethodDelete, "/api/v1/workspaces/:id/invites/:id", "collections:ws:invites:revoke"},
		{http.MethodPost, "/api/v1/invites/preview", "collections:invites:preview"},
		{http.MethodPost, "/api/v1/invites/accept", "collections:invites:accept"},
	} {
		rc := config.FindRouteConfig(rt.method, rt.path)
		if rc == nil {
			t.Errorf("%s %s: нет записи в реестре — шлюз ответит 403 «Маршрут не найден в конфигурации»", rt.method, rt.path)
			continue
		}
		if rc.Permission != rt.perm {
			t.Errorf("%s %s: permission %q, ожидался %q", rt.method, rt.path, rc.Permission, rt.perm)
		}
		if rc.Required {
			t.Errorf("%s %s: Required:true — права уровня шлюза тут ни при чём", rt.method, rt.path)
		}
		if rc.ScopeKind != "" {
			t.Errorf("%s %s: ScopeKind=%q — как у соседних members, скоуп не объявляется, причастность проверяет сервис", rt.method, rt.path, rc.ScopeKind)
		}
		if rc.ScopeParam != "" {
			t.Errorf("%s %s: ScopeParam=%q — маршрут вне скоупа, шлюз не читает параметр запроса и не сверяет по нему причастность", rt.method, rt.path, rc.ScopeParam)
		}
	}
}

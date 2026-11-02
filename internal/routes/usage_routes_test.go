package routes_test

// SDL-664 (EP-127): шлюз публикует три ручки расхода и восстановление
// пространства. Инварианты:
//   - три записи реестра — Required:false (свежий пользователь без ролей
//     обязан видеть расход своего пространства: ловушка бутстрапа);
//   - /workspaces/:id/usage — без скоупа, как GET /workspaces/:id: причастность
//     проверяет collections; /pages/usage — скоуп пространства (owner|member);
//     /files/usage — скоуп пространства и owner-only, как остальные файлы;
//   - /pages/usage не ходит в check-permission: права pages:usage в
//     user-service нет, и с Required:true любой актор получал бы 403;
//   - чужое пространство — 403 до апстрима; без workspace_id — 400;
//   - маркер workspace_gone, поставленный DELETE пространства, не мешает ни
//     POST restore, ни расходу после него: он только отключает кэш роли.

import (
	"net/http"
	"testing"

	"gateway-service/internal/config"
)

const (
	pagesUsagePath = "/api/v1/pages/usage"
	filesUsagePath = "/api/v1/files/usage"
)

func TestUsageRoutesRegistryEntries(t *testing.T) {
	for _, tc := range []struct {
		path              string
		scoped, ownerOnly bool
	}{
		{"/api/v1/workspaces/:id/usage", false, false},
		{pagesUsagePath, true, false},
		{filesUsagePath, true, true},
	} {
		rc := config.FindRouteConfig(http.MethodGet, tc.path)
		if rc == nil {
			t.Errorf("GET %s: нет записи в реестре — шлюз ответит 403", tc.path)
			continue
		}
		if rc.Required {
			t.Errorf("GET %s: Required:true — свежий пользователь без ролей получит 403 (ловушка бутстрапа)", tc.path)
		}
		if tc.scoped {
			if rc.ScopeParam != "workspace_id" || rc.ScopeKind != config.ScopeWorkspace || rc.ScopeInBody {
				t.Errorf("GET %s: скоуп {%q %q body=%v}, ожидался workspace_id из строки запроса", tc.path, rc.ScopeParam, rc.ScopeKind, rc.ScopeInBody)
			}
		} else if rc.ScopeParam != "" || rc.ScopeKind != "" {
			t.Errorf("GET %s: скоуп %q/%q — причастность проверяет collections, как у GET /workspaces/:id", tc.path, rc.ScopeParam, rc.ScopeKind)
		}
		if rc.ScopeOwnerOnly != tc.ownerOnly {
			t.Errorf("GET %s: ScopeOwnerOnly=%v, ожидался %v", tc.path, rc.ScopeOwnerOnly, tc.ownerOnly)
		}
	}
}

// Своё пространство: расход pages и files доходит до апстрима тем же путём с
// проверенным скоупом; pages — без похода в check-permission (user-service
// здесь отказал бы в любом праве pages:*).
func TestUsageScopedRoutesReachUpstreamInOwnWorkspace(t *testing.T) {
	for _, tc := range []struct{ path, service string }{
		{pagesUsagePath, "pages"},
		{filesUsagePath, "files"},
	} {
		stub := &membershipProxy{denyPages: true}
		r, token := newRouterWithProxy(t, stub)
		w := doRequest(r, http.MethodGet, tc.path+"?workspace_id="+ownWorkspaceID, map[string]string{"Authorization": "Bearer " + token})
		if w.Code != http.StatusOK {
			t.Errorf("GET %s своего пространства -> %d (%s), ожидался 200", tc.path, w.Code, w.Body.String())
			continue
		}
		calls := stub.callsTo(tc.service)
		if len(calls) != 1 || calls[0].method != http.MethodGet || calls[0].path != tc.path {
			t.Errorf("GET %s: к %s ушло %+v, ожидался один GET тем же путём", tc.path, tc.service, calls)
			continue
		}
		if got := calls[0].headers["X-Scope-Workspace-ID"]; got != ownWorkspaceID {
			t.Errorf("GET %s: X-Scope-Workspace-ID=%q, ожидался %s", tc.path, got, ownWorkspaceID)
		}
		if n := len(stub.permissionChecks()); n != 0 {
			t.Errorf("GET %s: check-permission вызван %d раз — запись Required:false в user-service ходить не должна", tc.path, n)
		}
	}
}

// Чужое пространство — 403, без workspace_id — 400; до апстрима не доходит.
func TestUsageScopedRoutesForeignOrMissingWorkspace(t *testing.T) {
	for _, tc := range []struct{ path, service string }{
		{pagesUsagePath, "pages"},
		{filesUsagePath, "files"},
	} {
		w, stub := doScoped(t, http.MethodGet, tc.path+"?workspace_id="+foreignWorkspaceID, "", nil)
		if w.Code != http.StatusForbidden || len(stub.callsTo(tc.service)) != 0 {
			t.Errorf("GET %s чужого пространства -> %d, к %s ушло %d; ожидался 403 и 0", tc.path, w.Code, tc.service, len(stub.callsTo(tc.service)))
		}
		w, stub = doScoped(t, http.MethodGet, tc.path, "", nil)
		if w.Code != http.StatusBadRequest || len(stub.callsTo(tc.service)) != 0 {
			t.Errorf("GET %s без workspace_id -> %d, к %s ушло %d; ожидался 400 и 0", tc.path, w.Code, tc.service, len(stub.callsTo(tc.service)))
		}
	}
}

// Роль member: расход pages открыт (как редактор), расход files закрыт
// (owner-only, как остальные файлы).
func TestUsageMemberRoleSeesPagesButNotFiles(t *testing.T) {
	w, stub := doScoped(t, http.MethodGet, pagesUsagePath+"?workspace_id="+memberWorkspaceID, "", nil)
	if w.Code != http.StatusOK || len(stub.callsTo("pages")) != 1 {
		t.Errorf("GET %s участником -> %d, к pages ушло %d; ожидался 200 и 1", pagesUsagePath, w.Code, len(stub.callsTo("pages")))
	}
	w, stub = doScoped(t, http.MethodGet, filesUsagePath+"?workspace_id="+memberWorkspaceID, "", nil)
	if w.Code != http.StatusForbidden || len(stub.callsTo("files")) != 0 {
		t.Errorf("GET %s участником -> %d, к files ушло %d; ожидался 403 и 0", filesUsagePath, w.Code, len(stub.callsTo("files")))
	}
}

// Расход пространства уходит в collections тем же путём, с актором из JWT, и
// проходит при чекере, отказывающем во всём (Required:false).
func TestWorkspaceUsageProxiedToCollectionsWithoutPermission(t *testing.T) {
	path := "/api/v1/workspaces/" + ownWorkspaceID + "/usage"
	r, token := newTestRouter(t, false)
	if w := doRequest(r, http.MethodGet, path, map[string]string{"Authorization": "Bearer " + token}); w.Code != http.StatusOK {
		t.Errorf("GET %s при отказе во всех правах -> %d, ожидался 200", path, w.Code)
	}
	w, stub := doScoped(t, http.MethodGet, path, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s -> %d (%s)", path, w.Code, w.Body.String())
	}
	var hit bool
	for _, c := range stub.callsTo("collections") {
		if c.method == http.MethodGet && c.path == path {
			hit = true
			if c.headers["X-User-ID"] != testUserID {
				t.Errorf("X-User-ID=%q, ожидался актор %s", c.headers["X-User-ID"], testUserID)
			}
		}
	}
	if !hit {
		t.Errorf("GET %s не дошёл до collections тем же путём: %+v", path, stub.callsTo("collections"))
	}
}

// Сквозной сценарий корзины на настоящем роутере с Redis: DELETE ставит
// маркер workspace_gone, и пока он жив, POST restore и все три расхода того
// же пространства проходят — маркер только отключает кэш роли, а не закрывает
// пространство.
func TestRestoreAndUsageWorkWhileWorkspaceGoneMarkerIsLive(t *testing.T) {
	mr, rs := newTestRedis(t)
	stub := &membershipProxy{}
	r, token := newRouterWithProxyAndRedis(t, stub, rs)
	auth := map[string]string{"Authorization": "Bearer " + token}

	if w := doRequest(r, http.MethodDelete, "/api/v1/workspaces/"+ownWorkspaceID, auth); w.Code != http.StatusOK {
		t.Fatalf("DELETE пространства -> %d (%s)", w.Code, w.Body.String())
	}
	if !mr.Exists(goneKeyPrefix + ownWorkspaceID) {
		t.Fatalf("маркер workspace_gone не поставлен — сценарий ничего не проверит; ключи: %v", mr.Keys())
	}
	// Роль, закэшированную до удаления (проверка права на отметку отзыва),
	// снимаем: дальше доказываем, что при живом маркере она не пишется снова.
	roleKey := roleKeyPrefix + testUserID + ":" + ownWorkspaceID
	mr.Del(roleKey)

	if w := doRequest(r, http.MethodPost, restorePath, auth); w.Code != http.StatusOK {
		t.Errorf("POST %s при живом маркере -> %d (%s)", restorePath, w.Code, w.Body.String())
	}
	for _, path := range []string{
		"/api/v1/workspaces/" + ownWorkspaceID + "/usage",
		pagesUsagePath + "?workspace_id=" + ownWorkspaceID,
		filesUsagePath + "?workspace_id=" + ownWorkspaceID,
	} {
		if w := doRequest(r, http.MethodGet, path, auth); w.Code != http.StatusOK {
			t.Errorf("GET %s при живом маркере -> %d (%s)", path, w.Code, w.Body.String())
		}
	}
	if !mr.Exists(goneKeyPrefix + ownWorkspaceID) {
		t.Errorf("маркер пропал раньше TTL — сценарий шёл не при живом маркере")
	}
	if mr.Exists(roleKey) {
		t.Errorf("роль попала в кэш при живом маркере workspace_gone")
	}
}

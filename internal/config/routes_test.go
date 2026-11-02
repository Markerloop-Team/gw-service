package config

// SDL-135: unit tests for the route <-> permission registry lookup.

import (
	"strings"
	"testing"
)

func TestNormalizeConfigPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Canonical placeholders survive untouched.
		{"/api/v1/users/:id", "/api/v1/users/:id"},
		{"/api/v1/users/email/:email", "/api/v1/users/email/:email"},
		{"/api/v1/users/username/:username", "/api/v1/users/username/:username"},
		// Custom parameter names collapse to :id — the request
		// normalizer turns UUIDs into :id regardless of the Gin name.
		{"/api/v1/users/:id/roles/:role_id", "/api/v1/users/:id/roles/:id"},
		{"/api/v1/roles/:id/permissions/:permission_id", "/api/v1/roles/:id/permissions/:id"},
		{"/api/v1/external-accounts/user/:user_id", "/api/v1/external-accounts/user/:id"},
		// No placeholders — identity.
		{"/api/v1/users", "/api/v1/users"},
	}
	for _, c := range cases {
		if got := normalizeConfigPath(c.in); got != c.want {
			t.Errorf("normalizeConfigPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFindRouteConfig(t *testing.T) {
	t.Run("known route resolves", func(t *testing.T) {
		rc := FindRouteConfig("GET", "/api/v1/users")
		if rc == nil {
			t.Fatal("GET /api/v1/users not found in registry")
		}
		if rc.Permission != "users:read:all" {
			t.Errorf("permission = %q, want users:read:all", rc.Permission)
		}
		if !rc.Required {
			t.Error("GET /api/v1/users must be Required:true")
		}
	})

	t.Run("custom param names match normalized request path", func(t *testing.T) {
		// The permission middleware normalizes a real request
		// DELETE /api/v1/users/<uuid>/roles/<uuid> to
		// /api/v1/users/:id/roles/:id — the registry entry uses
		// :role_id and must still match.
		rc := FindRouteConfig("DELETE", "/api/v1/users/:id/roles/:id")
		if rc == nil {
			t.Fatal("DELETE /api/v1/users/:id/roles/:id not found in registry")
		}
		if rc.Permission != "users:remove:role" {
			t.Errorf("permission = %q, want users:remove:role", rc.Permission)
		}
	})

	t.Run("unknown route returns nil", func(t *testing.T) {
		if rc := FindRouteConfig("GET", "/api/v1/definitely-not-registered"); rc != nil {
			t.Errorf("unexpected registry hit: %+v", rc)
		}
	})

	t.Run("method mismatch returns nil", func(t *testing.T) {
		if rc := FindRouteConfig("PATCH", "/api/v1/users"); rc != nil {
			t.Errorf("unexpected registry hit for PATCH: %+v", rc)
		}
	})
}

// SDL-587 (EP-121), SDL-617 G2: маршруты, на которых шлюз обязан сверять
// причастность актора к объекту. Потерянное объявление не ломает ни сборку,
// ни свип реестра — маршрут просто снова пропускает чужой workspace_id. Этот
// список краснеет поимённо. Все десять маршрутов файлов — по пространству и
// только для владельца: запись, потерявшая ScopeOwnerOnly, — красная.
func TestScopedRoutesKeepDeclarations(t *testing.T) {
	want := []struct {
		method, path, param string
		kind                ScopeKind
		inBody, ownerOnly   bool
	}{
		{"POST", "/api/v1/files/upload-url", "workspace_id", ScopeWorkspace, true, true},
		{"POST", "/api/v1/files/:id/complete", "workspace_id", ScopeWorkspace, false, true},
		{"GET", "/api/v1/files", "workspace_id", ScopeWorkspace, false, true},
		{"GET", "/api/v1/files/:id", "workspace_id", ScopeWorkspace, false, true},
		{"PATCH", "/api/v1/files/:id", "workspace_id", ScopeWorkspace, false, true},
		{"DELETE", "/api/v1/files/:id", "workspace_id", ScopeWorkspace, false, true},
		{"GET", "/api/v1/files/:id/url", "workspace_id", ScopeWorkspace, false, true},
		{"GET", "/api/v1/files/:id/links", "workspace_id", ScopeWorkspace, false, true},
		{"POST", "/api/v1/files/:id/replace", "workspace_id", ScopeWorkspace, false, true},
		{"GET", "/api/v1/files/usage", "workspace_id", ScopeWorkspace, false, true},
		// SDL-664: расход pages — скоуп пространства без owner-only.
		{"GET", "/api/v1/pages/usage", "workspace_id", ScopeWorkspace, false, false},
	}
	for _, w := range want {
		rc := FindRouteConfig(w.method, normalizeConfigPath(w.path))
		if rc == nil {
			t.Errorf("%s %s: нет в реестре", w.method, w.path)
			continue
		}
		if rc.ScopeParam != w.param || rc.ScopeKind != w.kind || rc.ScopeInBody != w.inBody || rc.ScopeOwnerOnly != w.ownerOnly {
			t.Errorf("%s %s: скоуп {%q %q body=%v owner=%v}, ожидался {%q %q body=%v owner=%v}",
				w.method, w.path, rc.ScopeParam, rc.ScopeKind, rc.ScopeInBody, rc.ScopeOwnerOnly,
				w.param, w.kind, w.inBody, w.ownerOnly)
		}
	}
}

// SDL-620: группы /api/v1/projects в реестре нет. Маршрут без записи
// отвечает 403 (permissionMiddleware fail-safe), поэтому отсутствие записей
// и есть закрытая поверхность; вернувшаяся запись — красная здесь, а
// вернувшийся Gin-маршрут — в routes.TestGatewayPublishesNoProjectsRoutes.
func TestRegistryHasNoProjectsEntries(t *testing.T) {
	for _, rc := range GetRouteConfigs() {
		if rc.Path == "/api/v1/projects" || strings.HasPrefix(rc.Path, "/api/v1/projects/") {
			t.Errorf("%s %s (%s): запись /projects вернулась в реестр — поверхность снята в SDL-620", rc.Method, rc.Path, rc.Permission)
		}
	}
	for _, path := range []string{"/api/v1/projects", "/api/v1/projects/:id", "/api/v1/projects/:id/tokens", "/api/v1/projects/:id/roles", "/api/v1/projects/:id/members"} {
		for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			if rc := FindRouteConfig(method, path); rc != nil {
				t.Errorf("%s %s резолвится в запись %+v", method, path, *rc)
			}
		}
	}
}

// Объявление скоупа либо полное, либо отсутствует: параметр без рода
// middleware не сможет проверить, род без параметра — мёртвая запись.
// Род один — ScopeWorkspace (SDL-620): у каждой записи со скоупом
// ScopeKind == ScopeWorkspace, и ни у одной — литерал "project" (константы
// ScopeProject больше нет, вернуть её можно только вместе с этим литералом;
// проверка по литералу — явная, чтобы возврат проектного рода краснел
// поимённо, а не как «неизвестный род»). ScopeOwnerOnly без параметра
// скоупа никем не читается.
func TestScopeDeclarationsAreConsistent(t *testing.T) {
	scoped := 0
	for _, rc := range GetRouteConfigs() {
		if rc.ScopeKind == ScopeKind("project") {
			t.Errorf("%s %s: проектный род скоупа снят в SDL-620", rc.Method, rc.Path)
		}
		if rc.ScopeParam == "" {
			if rc.ScopeKind != "" || rc.ScopeInBody || rc.ScopeOwnerOnly {
				t.Errorf("%s %s: род, body или owner-only без ScopeParam", rc.Method, rc.Path)
			}
			continue
		}
		scoped++
		if rc.ScopeKind != ScopeWorkspace {
			t.Errorf("%s %s: род скоупа %q, единственный допустимый — %q", rc.Method, rc.Path, rc.ScopeKind, ScopeWorkspace)
		}
	}
	if scoped == 0 {
		t.Fatal("в реестре нет ни одной записи со скоупом — тест ничего не проверяет")
	}
}

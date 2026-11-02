package routes_test

// SDL-572, SDL-584 (EP-108, EP-110): что шлюз знает про pages-service — и на
// каких условиях. Публичное чтение анонимно; редакторские ручки опубликованы
// только за JWT, реестром прав и скоупом пространства (SDL-587, EP-121).
//
// Реестр апстримов стережёт internal/config/services_test.go: он ловит
// пропавшее поле ServicesConfig. Но сам маршрут ему не виден — строку
// v1.GET("/pages/...", ...) из routes.go можно удалить, и та проверка
// останется зелёной. Поэтому маршруты закреплены здесь, тем же приёмом, что и
// files (SDL-359): роут зарегистрирован, отвечает без токена и упирается в
// объявленный апстрим, а не в «Сервис не найден».

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gateway-service/internal/config"
)

const pagesPublicByPath = "/api/v1/pages/public/pages/by-path" +
	"?workspace_id=00000000-0000-0000-0000-000000000001&path=/"

// pagesPublicSite — чтение сайта по хосту (SDL-684): без workspace_id и без
// токена, пространство по host находит сам pages-service.
const pagesPublicSite = "/api/v1/pages/public/site?host=acme.test.example.com&path=/"

// pagesPublicPaths — вся анонимная плоскость чтения pages.
// pagesPublicThemeFonts — белый список шрифтов темы (SDL-772): статичные
// данные сервиса, без токена и без пространства.
const pagesPublicThemeFonts = "/api/v1/pages/public/theme/fonts"

var pagesPublicPaths = []string{pagesPublicByPath, pagesPublicSite, pagesPublicThemeFonts}

// Здоровье апстрима обязано быть зарегистрировано и доступно без токена:
// проброс здоровья ходит на "/health" апстрима и аутентификации не требует.
func TestPagesHealthIsPublic(t *testing.T) {
	r, _ := newTestRouter(t, false)

	w := doRequest(r, http.MethodGet, "/api/v1/pages/health", nil)
	if w.Code == http.StatusNotFound {
		t.Fatalf("шлюз не знает маршрут /api/v1/pages/health (404)")
	}
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Fatalf("health апстрима не должен требовать токен, пришло %d", w.Code)
	}
}

// Апстрим объявлен в карте сервисов: маршрут, зарегистрированный в Gin без
// поля в ServicesConfig, отвечает «Сервис не найден» уже в рантайме.
//
// Эта сторона (загрузчик действительно кладёт ключ "pages" в карту)
// закреплена в internal/config/services_test.go — там она проверяется на
// настоящем config.Load(), а не на стабе прокси, который отвечает 200 на что
// угодно и до карты сервисов не доходит вовсе.
func TestPagesHealthDoesNotAnswerUnknownService(t *testing.T) {
	r, _ := newTestRouter(t, false)

	for _, path := range append([]string{"/api/v1/pages/health"}, pagesPublicPaths...) {
		w := doRequest(r, http.MethodGet, path, nil)
		if strings.Contains(w.Body.String(), "Сервис не найден") {
			t.Fatalf("%s: апстрим pages не объявлен: %s", path, w.Body.String())
		}
	}
}

// Публичная плоскость чтения (SDL-583 в сервисе, SDL-584 в шлюзе) анонимна:
// клиентский сайт читает опубликованную страницу без токена. Маршрут обязан
// дойти до апстрима без Authorization и без выданных прав — роутер собран с
// grantPermission=false, так что попадание под permissionMiddleware дало бы
// 401/403. Что отдаётся только опубликованное, решает запрос pages-service,
// а не шлюз (TestPublicPlaneIsAnonymous и соседи в pages-service).
func TestPagesPublicPlaneIsAnonymous(t *testing.T) {
	r, _ := newTestRouter(t, false)

	for _, path := range pagesPublicPaths {
		w := doRequest(r, http.MethodGet, path, nil)
		switch w.Code {
		case http.StatusNotFound:
			t.Fatalf("%s: шлюз не публикует публичное чтение pages (404)", path)
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest:
			t.Fatalf("%s: публичное чтение pages не должно требовать токен, права или пространство, пришло %d", path, w.Code)
		}
	}
}

// TestPagesPublicSiteHasNoRegistryScope (SDL-684): чтение сайта по хосту не
// объявлено в реестре прав и не несёт скоупа пространства. Запись со
// ScopeParam заставила бы шлюз требовать workspace_id, которого у посетителя
// поддомена нет, — каждый сайт отвечал бы 400/403 вместо страницы.
func TestPagesPublicSiteHasNoRegistryScope(t *testing.T) {
	for _, rc := range config.GetRouteConfigs() {
		if strings.HasPrefix(rc.Path, "/api/v1/pages/public/") {
			t.Errorf("%s %s: публичная плоскость pages в реестре прав (permission %q, scope %q) — она анонимна",
				rc.Method, rc.Path, rc.Permission, rc.ScopeParam)
		}
	}
}

// Публичная плоскость — только чтение: запись по тому же пути шлюз не
// пропускает к апстриму ни с токеном, ни без.
func TestPagesPublicPlaneIsReadOnly(t *testing.T) {
	r, token := newTestRouter(t, true)

	for _, path := range pagesPublicPaths {
		for _, headers := range []map[string]string{nil, {"Authorization": "Bearer " + token}} {
			for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodDelete} {
				w := doRequest(r, method, path, headers)
				if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
					t.Errorf("%s %s (auth=%v): публичная плоскость пропустила запись (%d)",
						method, path, headers != nil, w.Code)
				}
			}
		}
	}
}

// editorRoutes — редакторская поверхность pages: настоящие пути сервиса
// (pages-service/internal/routes/routes.go). Create несёт workspace_id в теле,
// остальные — в строке запроса.
var editorRoutes = []struct {
	method, path string
	inBody       bool
}{
	{http.MethodPost, "/api/v1/pages/routes", true},
	{http.MethodGet, "/api/v1/pages/routes", false},
	{http.MethodGet, "/api/v1/pages/routes/by-path", false},
	{http.MethodGet, "/api/v1/pages/routes/:id", false},
	{http.MethodPatch, "/api/v1/pages/routes/:id", false},
	{http.MethodDelete, "/api/v1/pages/routes/:id", false},
	{http.MethodPost, "/api/v1/pages/pages", true},
	{http.MethodGet, "/api/v1/pages/pages", false},
	{http.MethodGet, "/api/v1/pages/pages/:id", false},
	{http.MethodPatch, "/api/v1/pages/pages/:id", false},
	{http.MethodDelete, "/api/v1/pages/pages/:id", false},
	{http.MethodGet, "/api/v1/pages/pages/:id/revisions", false},
	{http.MethodGet, "/api/v1/pages/pages/:id/revisions/:n", false},
	{http.MethodPost, "/api/v1/pages/pages/:id/revisions/:n/restore", false},
	{http.MethodPost, "/api/v1/pages/blocks", true},
	{http.MethodGet, "/api/v1/pages/blocks", false},
	{http.MethodGet, "/api/v1/pages/blocks/:id", false},
	{http.MethodPatch, "/api/v1/pages/blocks/:id", false},
	{http.MethodDelete, "/api/v1/pages/blocks/:id", false},
	{http.MethodGet, "/api/v1/pages/blocks/:id/revisions", false},
	{http.MethodGet, "/api/v1/pages/blocks/:id/revisions/:n", false},
	{http.MethodPost, "/api/v1/pages/blocks/:id/revisions/:n/restore", false},
	// SDL-965: выкатка Компонента на выбранные страницы.
	{http.MethodPost, "/api/v1/pages/blocks/:id/publish", false},
	// SDL-772: тема сайта.
	{http.MethodGet, "/api/v1/pages/theme", false},
	{http.MethodPatch, "/api/v1/pages/theme", false},
	{http.MethodPost, "/api/v1/pages/theme/publish", false},
	{http.MethodGet, "/api/v1/pages/theme/revisions", false},
	{http.MethodGet, "/api/v1/pages/theme/revisions/:n", false},
	{http.MethodPost, "/api/v1/pages/theme/revisions/:n/restore", false},
}

// editorRequest собирает запрос к ручке в пространстве workspaceID.
func editorRequest(method, pattern string, inBody bool, workspaceID string) (path, body string) {
	path = fillParams(pattern)
	if inBody {
		return path, `{"workspace_id":"` + workspaceID + `","path":"/about"}`
	}
	return path + "?workspace_id=" + workspaceID, `{"version":1}`
}

// SDL-584 (EP-110): редакторские ручки опубликованы — после того, как шлюз
// начал сверять причастность к пространству (SDL-587, EP-121), а pages-service
// брать пространство из X-Scope-Workspace-ID (SDL-589). До этого тест стоял
// сторожем «не публиковать»; теперь он стережёт условия публикации.
//
// Своё пространство: запрос доходит до pages на тот же путь, с заголовком
// скоупа и телом без изменений. Номер ревизии приходит числом и находит
// запись реестра с литералом :param — иначе был бы fail-safe 403.
func TestPagesEditorRoutesReachUpstreamInOwnWorkspace(t *testing.T) {
	for _, rt := range editorRoutes {
		path, body := editorRequest(rt.method, rt.path, rt.inBody, ownWorkspaceID)
		w, stub := doScoped(t, rt.method, path, body, nil)
		if w.Code != http.StatusOK {
			t.Errorf("%s %s: %d, ожидался проксированный 200 (%s)", rt.method, rt.path, w.Code, w.Body.String())
			continue
		}
		calls := stub.callsTo("pages")
		if len(calls) != 1 {
			t.Errorf("%s %s: к pages ушло %d запросов, ожидался 1", rt.method, rt.path, len(calls))
			continue
		}
		c := calls[0]
		if c.method != rt.method || c.path != strings.SplitN(path, "?", 2)[0] {
			t.Errorf("%s %s: апстрим получил %s %s", rt.method, rt.path, c.method, c.path)
		}
		if got := c.headers["X-Scope-Workspace-ID"]; got != ownWorkspaceID {
			t.Errorf("%s %s: X-Scope-Workspace-ID=%q, ожидался %s", rt.method, rt.path, got, ownWorkspaceID)
		}
		if string(c.body) != body {
			t.Errorf("%s %s: тело дошло изменённым: %q", rt.method, rt.path, c.body)
		}
	}
}

// Чужое пространство — 403 до апстрима, на каждой ручке.
func TestPagesEditorRoutesForeignWorkspaceIsForbidden(t *testing.T) {
	for _, rt := range editorRoutes {
		path, body := editorRequest(rt.method, rt.path, rt.inBody, foreignWorkspaceID)
		w, stub := doScoped(t, rt.method, path, body, nil)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s: чужое пространство -> %d, ожидался 403", rt.method, rt.path, w.Code)
		}
		if n := len(stub.callsTo("pages")); n != 0 {
			t.Errorf("%s %s: чужое пространство дошло до pages (%d)", rt.method, rt.path, n)
		}
	}
}

// Без пространства — 400, без токена — 401; ни то ни другое до pages не идёт.
func TestPagesEditorRoutesNeedWorkspaceAndToken(t *testing.T) {
	for _, rt := range editorRoutes {
		path := fillParams(rt.path)
		w, stub := doScoped(t, rt.method, path, `{"version":1}`, nil)
		if w.Code != http.StatusBadRequest || len(stub.callsTo("pages")) != 0 {
			t.Errorf("%s %s: без workspace_id -> %d, к pages ушло %d; ожидался 400 и 0",
				rt.method, rt.path, w.Code, len(stub.callsTo("pages")))
		}

		r, _ := newTestRouter(t, true)
		reqPath, _ := editorRequest(rt.method, rt.path, false, ownWorkspaceID)
		if w := doRequest(r, rt.method, reqPath, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: без токена -> %d, ожидался 401", rt.method, rt.path, w.Code)
		}
	}
}

// Клиентский X-Scope-Workspace-ID не подменяет пространство: до pages доходит
// только тот, что сверил шлюз.
func TestPagesEditorForgedScopeNeverReachesUpstream(t *testing.T) {
	path := fillParams("/api/v1/pages/pages/:id") + "?workspace_id=" + ownWorkspaceID
	w, stub := doScoped(t, http.MethodGet, path, "", map[string]string{"X-Scope-Workspace-ID": foreignWorkspaceID})
	if w.Code != http.StatusOK {
		t.Fatalf("GET своей страницы -> %d", w.Code)
	}
	calls := stub.callsTo("pages")
	if len(calls) != 1 {
		t.Fatalf("к pages ушло %d запросов", len(calls))
	}
	assertNoForgedScope(t, calls[0], foreignWorkspaceID)
}

// Реестр: каждая запись /api/v1/pages/... (кроме анонимных, которых в реестре
// нет) объявляет скоуп пространства, у Create — из тела; номер ревизии записан
// литералом :param, а не именем параметра Gin.
//
// SDL-614: каждая запись — Required: true. Это не украшение: выход
// `if !routeConfig.Required { c.Next() }` в permissionMiddleware стоит ДО
// похода в user-service, и с Required: false пара «право + пространство» не
// исполнилась бы ни на одном маршруте, ради которого заведена.
func TestPagesRegistryDeclaresWorkspaceScope(t *testing.T) {
	seen := 0
	for _, rc := range config.GetRouteConfigs() {
		if !strings.HasPrefix(rc.Path, "/api/v1/pages/") {
			continue
		}
		// SDL-664: расход квот — не редакторская ручка и без права pages:*
		// в user-service; Required:false и её скоуп стережёт
		// usage_routes_test.go.
		if rc.Path == pagesUsagePath {
			continue
		}
		seen++
		if !rc.Required {
			t.Errorf("%s %s: Required:false — проверка права уровня workspace (SDL-614) на этом маршруте не исполнится", rc.Method, rc.Path)
		}
		isCreate := rc.Method == http.MethodPost && strings.Count(rc.Path, "/") == 4
		if rc.ScopeParam != "workspace_id" || rc.ScopeKind != config.ScopeWorkspace || rc.ScopeInBody != isCreate {
			t.Errorf("%s %s: скоуп {%q %q body=%v}", rc.Method, rc.Path, rc.ScopeParam, rc.ScopeKind, rc.ScopeInBody)
		}
		if strings.Contains(rc.Path, "/revisions/") && !strings.Contains(rc.Path, "/revisions/:param") {
			t.Errorf("%s %s: номер ревизии без литерала :param", rc.Method, rc.Path)
		}
	}
	if seen != len(editorRoutes) {
		t.Errorf("в реестре %d записей pages, ручек редактора %d", seen, len(editorRoutes))
	}
}

// SDL-585: спека pages-service публикуется шлюзом и НЕ требует токена — тот же
// приём, что у files (SDL-409). Роут без записи в /api/docs даёт 404, а
// требование токена — 401; на оба гард _spec_available в dev-infra
// tests/schemathesis молча скипает сервис, и ночной регресс остаётся зелёным,
// ничего не проверив.
func TestPagesSwaggerIsProxiedWithoutToken(t *testing.T) {
	r, _ := newTestRouter(t, false)

	w := doRequest(r, http.MethodGet, "/api/docs/pages/swagger/doc.json", nil)
	if w.Code == http.StatusNotFound {
		t.Fatalf("шлюз не знает маршрут спеки pages (404) — schemathesis молча скипнет сервис")
	}
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Fatalf("спека потребовала аутентификации (%d) — её читает контур фуззинга без токена", w.Code)
	}
	if strings.Contains(w.Body.String(), "Сервис не найден") {
		t.Fatalf("апстрим pages не объявлен для спеки: %s", w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// SDL-614 (EP-111): проверка права — пара «право + пространство».
//
// Гард приёмки. Он НЕ про «участник A в пространстве B → 403» — это стережёт
// слой скоупа (SDL-587) и 403 pages-service (SDL-589), и тот тест зелёный без
// SDL-614. Этот гард краснеет от того, что permissionMiddleware перестал
// слать в user-service workspace_id и workspace_role из контекста: стаб
// user-service воспроизводит контракт b371866 — право pages:* уровня
// workspace без роли не выдаётся, отката на платформенные права нет.
// ---------------------------------------------------------------------------

// expectedPermissionPath — путь, каким его видит реестр прав: UUID → :id,
// номер ревизии → :param (ровно то, что кладёт normalizePath шлюза).
func expectedPermissionPath(pattern string) string {
	return strings.ReplaceAll(strings.ReplaceAll(pattern, ":id", ":id"), ":n", ":param")
}

// Своё пространство, роль owner: на каждой ручке ровно один check-permission,
// в теле — метод, путь на языке реестра, пространство и роль, сверенные
// слоем скоупа; и он отправлен ПОСЛЕ похода за участниками (порядок слоёв
// jwt → scope → permission). Запрос доходит до pages.
func TestPagesPermissionCheckCarriesVerifiedWorkspaceRole(t *testing.T) {
	for _, rt := range editorRoutes {
		path, body := editorRequest(rt.method, rt.path, rt.inBody, ownWorkspaceID)
		w, stub := doScoped(t, rt.method, path, body, nil)
		if w.Code != http.StatusOK {
			t.Errorf("%s %s: %d, ожидался 200 — user-service не выдал право уровня workspace (%s)", rt.method, rt.path, w.Code, w.Body.String())
			continue
		}
		checks := stub.permissionChecks()
		if len(checks) != 1 {
			t.Errorf("%s %s: check-permission вызван %d раз, ожидался 1", rt.method, rt.path, len(checks))
			continue
		}
		got := checks[0]
		if got.Method != rt.method || got.Path != expectedPermissionPath(rt.path) {
			t.Errorf("%s %s: в проверку права ушло %s %s, ожидался %s %s", rt.method, rt.path, got.Method, got.Path, rt.method, expectedPermissionPath(rt.path))
		}
		if got.WorkspaceID != ownWorkspaceID {
			t.Errorf("%s %s: workspace_id в проверке права %q, ожидался сверенный %s", rt.method, rt.path, got.WorkspaceID, ownWorkspaceID)
		}
		if got.WorkspaceRole != "owner" {
			t.Errorf("%s %s: workspace_role в проверке права %q, ожидался owner из workspace_members", rt.method, rt.path, got.WorkspaceRole)
		}
		members := stub.firstCallIndex("collections", "/members")
		check := stub.firstCallIndex("user", "/check-permission")
		if members < 0 || check < 0 || members > check {
			t.Errorf("%s %s: участники (%d) должны быть спрошены раньше проверки права (%d)", rt.method, rt.path, members, check)
		}
		if n := len(stub.callsTo("pages")); n != 1 {
			t.Errorf("%s %s: к pages ушло %d запросов, ожидался 1", rt.method, rt.path, n)
		}
	}
}

// Роль member тоже уезжает в проверку права как есть: решать, что ей можно,
// — дело user-service (ws:member), а не шлюза.
func TestPagesMemberRoleReachesPermissionCheck(t *testing.T) {
	path, body := editorRequest(http.MethodPatch, "/api/v1/pages/pages/:id", false, memberWorkspaceID)
	w, stub := doScoped(t, http.MethodPatch, path, body, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("участник своего пространства -> %d (%s)", w.Code, w.Body.String())
	}
	checks := stub.permissionChecks()
	if len(checks) != 1 || checks[0].WorkspaceID != memberWorkspaceID || checks[0].WorkspaceRole != "member" {
		t.Fatalf("в проверку права ушло %+v, ожидался {workspace_id=%s role=member}", checks, memberWorkspaceID)
	}
}

// Чужое пространство отбивается слоем скоупа ДО проверки права: к
// user-service не уходит ни одного check-permission. Обратный порядок слоёв
// (permission раньше scope) отправил бы проверку с пустым пространством.
func TestPagesForeignWorkspaceNeverReachesPermissionCheck(t *testing.T) {
	for _, rt := range editorRoutes {
		path, body := editorRequest(rt.method, rt.path, rt.inBody, foreignWorkspaceID)
		w, stub := doScoped(t, rt.method, path, body, nil)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s: чужое пространство -> %d, ожидался 403", rt.method, rt.path, w.Code)
		}
		if n := len(stub.permissionChecks()); n != 0 {
			t.Errorf("%s %s: чужое пространство дошло до проверки права (%d вызовов) — слой скоупа стоит после permission", rt.method, rt.path, n)
		}
	}
}

// collections ответил 200, но актора в списке участников нет — не причастен
// (fail-closed): 403, ни проверки права, ни апстрима.
func TestPagesActorAbsentFromMembersIsForbidden(t *testing.T) {
	stub := &membershipProxy{actorAbsentFromMembers: true}
	r, token := newRouterWithProxy(t, stub)
	path, _ := editorRequest(http.MethodGet, "/api/v1/pages/pages", false, ownWorkspaceID)
	w := doRequest(r, http.MethodGet, path, map[string]string{"Authorization": "Bearer " + token})
	if w.Code != http.StatusForbidden {
		t.Fatalf("актор вне списка участников -> %d, ожидался 403", w.Code)
	}
	if n := len(stub.permissionChecks()) + len(stub.callsTo("pages")); n != 0 {
		t.Fatalf("актор вне списка участников: %d запросов ушло дальше слоя скоупа", n)
	}
}

// Отказ user-service на праве pages:* — 403 до апстрима. С Required: false
// проверка не состоялась бы вовсе, и запрос прошёл бы к pages.
func TestPagesPermissionDeniedByUserServiceIsForbidden(t *testing.T) {
	for _, rt := range editorRoutes {
		stub := &membershipProxy{denyPages: true}
		r, token := newRouterWithProxy(t, stub)
		path, body := editorRequest(rt.method, rt.path, rt.inBody, ownWorkspaceID)
		req := httptest.NewRequest(rt.method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s: отказ user-service -> %d, ожидался 403", rt.method, rt.path, w.Code)
		}
		if n := len(stub.permissionChecks()); n != 1 {
			t.Errorf("%s %s: check-permission вызван %d раз, ожидался 1 (Required: true)", rt.method, rt.path, n)
		}
		if n := len(stub.callsTo("pages")); n != 0 {
			t.Errorf("%s %s: при отказе в праве запрос дошёл до pages (%d)", rt.method, rt.path, n)
		}
	}
}

// Пространство в проверке права — только сверенное слоем скоупа, не то, что
// заявил клиент: на маршруте без скоупа ?workspace_id= в строке запроса не
// попадает в check-permission.
func TestPermissionCheckNeverTakesWorkspaceFromClientClaim(t *testing.T) {
	w, stub := doScoped(t, http.MethodGet, "/api/v1/users?workspace_id="+foreignWorkspaceID, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /users -> %d (%s)", w.Code, w.Body.String())
	}
	checks := stub.permissionChecks()
	if len(checks) != 1 {
		t.Fatalf("check-permission вызван %d раз, ожидался 1", len(checks))
	}
	if checks[0].WorkspaceID != "" || checks[0].WorkspaceRole != "" {
		t.Fatalf("заявленное клиентом пространство уехало в проверку права: %+v", checks[0])
	}
}

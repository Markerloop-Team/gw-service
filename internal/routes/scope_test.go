package routes_test

// SDL-587 (EP-121): шлюз сверяет причастность актора к объекту, названному в
// запросе, и кладёт вниз доверенный заголовок скоупа.
//
// SDL-617 G2: файлы проверяются по ПРОСТРАНСТВУ и только для владельца.
// Шлюз берёт workspace_id из строки запроса (у upload-url — из тела),
// спрашивает у collections-service роль актора по workspace_members и
// передаёт в files-service один X-Scope-Workspace-ID. К /projects/:id он
// больше не ходит — 617b эту ручку удаляет.
//
// Инварианты, которые закрывает этот файл:
//   - своё пространство (роль owner) проходит по существу на всех семи
//     маршрутах, апстрим получает только заголовок пространства, а
//     project_id в строке запроса ни на что не влияет;
//   - роль member — 403 на файлах, но 200 на pages в том же пространстве:
//     owner-only — свойство записи реестра, а не слоя;
//   - только ?project_id= — 400, ноль обращений вниз: запасного пути
//     «проект → пространство» нет;
//   - чужое пространство — 403, сбой collections — 500; до files запрос не
//     доходит ни в том, ни в другом случае;
//   - клиентские X-Scope-* не доходят до апстрима;
//   - пространство из тела upload-url приводится к нижнему регистру, тело
//     уходит байт в байт;
//   - при повторе ?workspace_id=свой&workspace_id=чужой вниз уходит первое;
//   - вопрос о роли задаётся от имени актора (X-User-ID из JWT).
//
// TestFilesScopeIsWorkspaceOwnerOnly — маркер G2 для конвейера dev-infra
// (scripts/ci/g2-invariant.sh): имя менять нельзя, не поменяв скрипт.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"gateway-service/internal/models"
)

const (
	// ownProjectID / foreignProjectID — проекты в строке запроса. После G2
	// шлюз их не читает; они здесь, чтобы доказать это.
	ownProjectID     = "aaaaaaaa-0000-4000-8000-000000000001"
	foreignProjectID = "bbbbbbbb-0000-4000-8000-000000000002"
	testFileID       = "cccccccc-0000-4000-8000-000000000003"
	// SDL-584: пространство актора для скоупа редактора pages и (с G2) файлов.
	ownWorkspaceID     = "dddddddd-0000-4000-8000-000000000004"
	foreignWorkspaceID = "eeeeeeee-0000-4000-8000-000000000005"
	// SDL-614: пространство, где актор — участник (member), а не владелец.
	memberWorkspaceID = "ffffffff-0000-4000-8000-000000000006"
	// otherUserID — чужой участник в списках workspace_members.
	otherUserID = "99999999-8888-7777-6666-555555555555"
)

type upstreamCall struct {
	service, method, path string
	headers               map[string]string
	query                 map[string]string
	body                  []byte
}

// membershipProxy — стаб апстримов. collections знает ровно один проект
// актора и два пространства: ownWorkspaceID (актор — owner) и
// memberWorkspaceID (актор — member); список участников отдаётся от имени
// актора, чужое пространство — 404. Ручка /projects/:id ОТВЕЧАЕТ на свой
// проект (с workspace_id) — чтобы запасной путь «проект → пространство»,
// появись он в шлюзе, прошёл бы и уронил тест, а не спрятался за 404.
// user-service (check-permission) воспроизводит контракт SDL-614: право
// pages:* уровня workspace выдаётся ТОЛЬКО с ролью owner|member и
// пространством в теле — без них отказ, без отката на платформенные права;
// всё остальное разрешено. Остальные апстримы отвечают 200 и запоминаются.
type membershipProxy struct {
	mu        sync.Mutex
	calls     []upstreamCall
	failCheck bool
	// actorAbsentFromMembers — collections отвечает 200 списком без актора.
	actorAbsentFromMembers bool
	// denyPages — user-service отказывает в праве pages:* даже с ролью.
	denyPages bool
}

// checkPermissionBody — тело check-permission, как его читает user-service
// (models.CheckPermissionRequest).
type checkPermissionBody struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	WorkspaceID   string `json:"workspace_id"`
	WorkspaceRole string `json:"workspace_role"`
}

func (s *membershipProxy) ProxyRequest(serviceName, method, path string, headers map[string]string, queryParams map[string]string, body []byte) (*models.ProxyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := make(map[string]string, len(headers))
	for k, v := range headers {
		h[k] = v
	}
	q := make(map[string]string, len(queryParams))
	for k, v := range queryParams {
		q[k] = v
	}
	s.calls = append(s.calls, upstreamCall{serviceName, method, path, h, q, body})

	ok := &models.ProxyResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       []byte(`{"success":true,"data":{"has_permission":true,"reason":"platform_role"}}`),
	}
	notFound := &models.ProxyResponse{StatusCode: http.StatusNotFound, Body: []byte(`{}`)}

	if serviceName == "user" && strings.Contains(path, "/check-permission") {
		var req checkPermissionBody
		_ = json.Unmarshal(body, &req)
		if !strings.HasPrefix(req.Path, "/api/v1/pages/") {
			return ok, nil
		}
		roleKnown := req.WorkspaceRole == "owner" || req.WorkspaceRole == "member"
		wsKnown := req.WorkspaceID == ownWorkspaceID || req.WorkspaceID == memberWorkspaceID
		granted := roleKnown && wsKnown && !s.denyPages
		reason := "denied"
		if granted {
			reason = "workspace_role"
		}
		return &models.ProxyResponse{
			StatusCode: http.StatusOK,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       []byte(fmt.Sprintf(`{"success":true,"data":{"has_permission":%v,"reason":%q}}`, granted, reason)),
		}, nil
	}

	if serviceName == "collections" && method == http.MethodGet && strings.HasPrefix(path, "/api/v1/workspaces/") && strings.HasSuffix(path, "/members") {
		if s.failCheck {
			return nil, errors.New("collections недоступен")
		}
		if h["X-User-ID"] != testUserID {
			return notFound, nil
		}
		var role string
		switch strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/workspaces/"), "/members") {
		case ownWorkspaceID:
			role = "owner"
		case memberWorkspaceID:
			role = "member"
		default:
			return notFound, nil
		}
		members := `{"user_id":"` + otherUserID + `","role":"member"}`
		if !s.actorAbsentFromMembers {
			members = `{"user_id":"` + testUserID + `","role":"` + role + `"},` + members
		}
		return &models.ProxyResponse{
			StatusCode: http.StatusOK,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       []byte(`{"success":true,"data":[` + members + `]}`),
		}, nil
	}

	// SDL-615 S2: исключение участника и удаление пространства от имени
	// актора — 200, чтобы слой сброса кэша (MembershipRevocation) сработал.
	if serviceName == "collections" && method == http.MethodDelete && strings.HasPrefix(path, "/api/v1/workspaces/") {
		if h["X-User-ID"] != testUserID {
			return notFound, nil
		}
		return ok, nil
	}

	// SDL-620: ветки /api/v1/projects/ у стаба нет — шлюз к ним не ходит, а
	// если пойдёт, projectCalls() поймает это на любом маршруте файлов.
	if serviceName == "collections" && strings.HasPrefix(path, "/api/v1/workspaces/") {
		if s.failCheck {
			return nil, errors.New("collections недоступен")
		}
		// SDL-664: restore и usage своего пространства — 200 от имени актора.
		own := "/api/v1/workspaces/" + ownWorkspaceID
		if (path == own || path == own+"/restore" || path == own+"/usage") && h["X-User-ID"] == testUserID {
			return ok, nil
		}
		return notFound, nil
	}
	return ok, nil
}

// permissionChecks — вызовы check-permission в user-service с разобранным
// телом, в порядке отправки.
func (s *membershipProxy) permissionChecks() []checkPermissionBody {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []checkPermissionBody
	for _, c := range s.calls {
		if c.service == "user" && strings.Contains(c.path, "/check-permission") {
			var b checkPermissionBody
			_ = json.Unmarshal(c.body, &b)
			out = append(out, b)
		}
	}
	return out
}

// firstCallIndex — позиция первого вызова апстрима serviceName, чей путь
// содержит pathPart; -1, если такого не было.
func (s *membershipProxy) firstCallIndex(serviceName, pathPart string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.calls {
		if c.service == serviceName && strings.Contains(c.path, pathPart) {
			return i
		}
	}
	return -1
}

func (s *membershipProxy) GetServiceURL(string) (string, error) { return "http://127.0.0.1:1", nil }

// callsTo — запросы к апстриму serviceName.
func (s *membershipProxy) callsTo(serviceName string) []upstreamCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []upstreamCall
	for _, c := range s.calls {
		if c.service == serviceName {
			out = append(out, c)
		}
	}
	return out
}

// projectCalls — обращения к /projects/... в collections. После G2 их должно
// быть ноль на любом маршруте файлов.
func (s *membershipProxy) projectCalls() []upstreamCall {
	var out []upstreamCall
	for _, c := range s.callsTo("collections") {
		if strings.HasPrefix(c.path, "/api/v1/projects") {
			out = append(out, c)
		}
	}
	return out
}

func doScoped(t *testing.T, method, path, body string, extra map[string]string) (*httptest.ResponseRecorder, *membershipProxy) {
	t.Helper()
	stub := &membershipProxy{}
	r, token := newRouterWithProxy(t, stub)
	var rd *bytes.Reader
	if body != "" {
		rd = bytes.NewReader([]byte(body))
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w, stub
}

func assertNoForgedScope(t *testing.T, c upstreamCall, forged string) {
	t.Helper()
	for k, v := range c.headers {
		if strings.HasPrefix(strings.ToLower(k), "x-scope-") && v == forged {
			t.Fatalf("клиентский %s=%q дошёл до апстрима %s", k, v, c.service)
		}
	}
}

// filesRoutes — шесть маршрутов файлов со скоупом в строке запроса; седьмой,
// upload-url, несёт пространство в теле и проверяется отдельно.
var filesRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/v1/files"},
	{http.MethodGet, "/api/v1/files/" + testFileID},
	{http.MethodPatch, "/api/v1/files/" + testFileID},
	{http.MethodDelete, "/api/v1/files/" + testFileID},
	{http.MethodGet, "/api/v1/files/" + testFileID + "/url"},
	{http.MethodPost, "/api/v1/files/" + testFileID + "/complete"},
}

// uploadURLBody — тело upload-url с пространством workspaceID; project_id
// чужой, чтобы доказать, что тело шлюз читает только ради workspace_id.
func uploadURLBody(workspaceID string) string {
	return `{"workspace_id":"` + workspaceID + `","project_id":"` + foreignProjectID + `","checksum":"x","size_bytes":1,"mime":"image/png"}`
}

// assertWorkspaceOnlyScope — вниз ушёл ровно один запрос к files с одним
// X-Scope-Workspace-ID = ownWorkspaceID и без проектного заголовка; в
// collections — ровно один вопрос о роли и ни одного к /projects/.
func assertWorkspaceOnlyScope(t *testing.T, label string, stub *membershipProxy) {
	t.Helper()
	files := stub.callsTo("files")
	if len(files) != 1 {
		t.Errorf("%s: к files ушло %d запросов, ожидался 1", label, len(files))
		return
	}
	if got := files[0].headers["X-Scope-Workspace-ID"]; got != ownWorkspaceID {
		t.Errorf("%s: X-Scope-Workspace-ID=%q, ожидался %s", label, got, ownWorkspaceID)
	}
	if got, ok := files[0].headers["X-Scope-Project-ID"]; ok {
		t.Errorf("%s: вниз ушёл проектный заголовок X-Scope-Project-ID=%q, после G2 его быть не должно", label, got)
	}
	coll := stub.callsTo("collections")
	if len(coll) != 1 || coll[0].method != http.MethodGet || coll[0].path != "/api/v1/workspaces/"+ownWorkspaceID+"/members" {
		t.Errorf("%s: к collections ушло %+v, ожидался один GET /api/v1/workspaces/%s/members", label, coll, ownWorkspaceID)
	}
	if n := len(stub.projectCalls()); n != 0 {
		t.Errorf("%s: шлюз спросил /projects/ %d раз — после G2 эта ручка не существует", label, n)
	}
}

// TestFilesScopeIsWorkspaceOwnerOnly — маркер G2 (SDL-617) для конвейера.
// Владелец пространства проходит на всех семи маршрутах, даже с чужим
// project_id рядом: вниз уходит только пространство, к /projects/ шлюз не
// ходит.
func TestFilesScopeIsWorkspaceOwnerOnly(t *testing.T) {
	for _, rt := range filesRoutes {
		path := rt.path + "?workspace_id=" + ownWorkspaceID + "&project_id=" + foreignProjectID
		w, stub := doScoped(t, rt.method, path, "", nil)
		if w.Code != http.StatusOK {
			t.Errorf("%s %s: %d, ожидался проксированный 200 (%s)", rt.method, path, w.Code, w.Body.String())
			continue
		}
		assertWorkspaceOnlyScope(t, rt.method+" "+rt.path, stub)
	}

	body := uploadURLBody(ownWorkspaceID)
	w, stub := doScoped(t, http.MethodPost, "/api/v1/files/upload-url", body, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("upload-url со своим пространством -> %d (%s)", w.Code, w.Body.String())
	}
	assertWorkspaceOnlyScope(t, "POST /api/v1/files/upload-url", stub)
}

// Роль member: файлы закрыты (ScopeOwnerOnly), а редактор pages в том же
// пространстве открыт — owner-only живёт в записи реестра, не в слое.
func TestFilesMemberRoleIsForbiddenButPagesStayOpen(t *testing.T) {
	for _, rt := range filesRoutes {
		path := rt.path + "?workspace_id=" + memberWorkspaceID
		w, stub := doScoped(t, rt.method, path, "", nil)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s: участник получил %d, ожидался 403", rt.method, path, w.Code)
		}
		if n := len(stub.callsTo("files")); n != 0 {
			t.Errorf("%s %s: запрос участника дошёл до files (%d)", rt.method, path, n)
		}
	}
	w, stub := doScoped(t, http.MethodPost, "/api/v1/files/upload-url", uploadURLBody(memberWorkspaceID), nil)
	if w.Code != http.StatusForbidden || len(stub.callsTo("files")) != 0 {
		t.Errorf("upload-url участника -> %d, к files ушло %d; ожидался 403 и 0", w.Code, len(stub.callsTo("files")))
	}

	w, stub = doScoped(t, http.MethodGet, "/api/v1/pages/routes?workspace_id="+memberWorkspaceID, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /pages/routes участника -> %d, ожидался 200 (%s)", w.Code, w.Body.String())
	}
	pages := stub.callsTo("pages")
	if len(pages) != 1 || pages[0].headers["X-Scope-Workspace-ID"] != memberWorkspaceID {
		t.Fatalf("к pages ушло %+v, ожидался один запрос с X-Scope-Workspace-ID=%s", pages, memberWorkspaceID)
	}
}

// Только ?project_id= (клиент до G2-0) — 400 и ни одного обращения вниз:
// запасного пути «проект → пространство» у шлюза нет.
func TestFilesProjectIDAloneIsBadRequestWithoutUpstreamCalls(t *testing.T) {
	for _, rt := range filesRoutes {
		path := rt.path + "?project_id=" + ownProjectID
		w, stub := doScoped(t, rt.method, path, "", nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s %s: %d, ожидался 400", rt.method, path, w.Code)
		}
		if n := len(stub.calls); n != 0 {
			t.Errorf("%s %s: без workspace_id ушло %d запросов вниз: %+v", rt.method, path, n, stub.calls)
		}
	}
	w, stub := doScoped(t, http.MethodPost, "/api/v1/files/upload-url",
		`{"project_id":"`+ownProjectID+`","checksum":"x","size_bytes":1,"mime":"image/png"}`, nil)
	if w.Code != http.StatusBadRequest || len(stub.calls) != 0 {
		t.Errorf("upload-url только с project_id -> %d, вниз ушло %d; ожидался 400 и 0", w.Code, len(stub.calls))
	}
}

func TestFilesMissingOrMalformedWorkspaceIsBadRequest(t *testing.T) {
	for _, path := range []string{
		"/api/v1/files",
		"/api/v1/files?workspace_id=",
		"/api/v1/files?workspace_id=not-a-uuid",
	} {
		w, stub := doScoped(t, http.MethodGet, path, "", nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("GET %s -> %d, ожидался 400", path, w.Code)
		}
		if n := len(stub.calls); n != 0 {
			t.Errorf("GET %s: без валидного параметра ушло %d запросов вниз", path, n)
		}
	}
}

// Чужое пространство — 403; сбой collections — 500. В обоих случаях files не
// видит запроса: ошибка проверки не означает «причастен».
func TestFilesForeignWorkspaceIsForbiddenAndCheckFailureIsNotAPass(t *testing.T) {
	w, stub := doScoped(t, http.MethodGet, "/api/v1/files?workspace_id="+foreignWorkspaceID, "", nil)
	if w.Code != http.StatusForbidden {
		t.Errorf("чужое пространство -> %d, ожидался 403", w.Code)
	}
	if n := len(stub.callsTo("files")); n != 0 {
		t.Errorf("чужое пространство дошло до files (%d запросов)", n)
	}

	failing := &membershipProxy{failCheck: true}
	r, token := newRouterWithProxy(t, failing)
	w = doRequest(r, http.MethodGet, "/api/v1/files?workspace_id="+ownWorkspaceID, map[string]string{"Authorization": "Bearer " + token})
	if w.Code != http.StatusInternalServerError {
		t.Errorf("недоступный collections -> %d, ожидался 500", w.Code)
	}
	if n := len(failing.callsTo("files")); n != 0 {
		t.Errorf("при сбое проверки запрос дошёл до files (%d)", n)
	}
}

func TestFilesRoleIsAskedAsActor(t *testing.T) {
	_, stub := doScoped(t, http.MethodGet, "/api/v1/files?workspace_id="+ownWorkspaceID, "", nil)
	checks := stub.callsTo("collections")
	if len(checks) != 1 {
		t.Fatalf("к collections ушло %d запросов, ожидался 1", len(checks))
	}
	if checks[0].headers["X-User-ID"] != testUserID {
		t.Fatalf("роль спрошена не от имени актора: X-User-ID=%q", checks[0].headers["X-User-ID"])
	}
}

func TestFilesForgedClientScopeHeadersNeverReachUpstream(t *testing.T) {
	forged := foreignWorkspaceID
	w, stub := doScoped(t, http.MethodGet, "/api/v1/files?workspace_id="+ownWorkspaceID, "", map[string]string{
		"X-Scope-Project-ID":   forged,
		"X-Scope-Workspace-ID": forged,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("GET /files со своим пространством -> %d", w.Code)
	}
	files := stub.callsTo("files")
	if len(files) != 1 {
		t.Fatalf("к files ушло %d запросов", len(files))
	}
	assertNoForgedScope(t, files[0], forged)
	if _, ok := files[0].headers["X-Scope-Project-ID"]; ok {
		t.Fatalf("подделанный X-Scope-Project-ID дошёл до files: %+v", files[0].headers)
	}

	// Маршрут вне скоупа: шлюз ничего не инжектит, но и чужое не пропускает.
	_, stub = doScoped(t, http.MethodGet, "/api/v1/workspaces", "", map[string]string{"X-Scope-Workspace-ID": forged})
	ws := stub.callsTo("collections")
	if len(ws) != 1 {
		t.Fatalf("GET /workspaces: к collections ушло %d запросов", len(ws))
	}
	assertNoForgedScope(t, ws[0], forged)
}

// Пространство из тела upload-url: верхний регистр приводится к нижнему в
// заголовке, тело уходит байт в байт (files-service сам читает его поля).
func TestFilesScopeFromUploadURLBodyIsLowercasedAndBodyUntouched(t *testing.T) {
	body := uploadURLBody(strings.ToUpper(ownWorkspaceID))
	w, stub := doScoped(t, http.MethodPost, "/api/v1/files/upload-url", body, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("upload-url со своим пространством в верхнем регистре -> %d (%s)", w.Code, w.Body.String())
	}
	files := stub.callsTo("files")
	if len(files) != 1 {
		t.Fatalf("к files ушло %d запросов", len(files))
	}
	if string(files[0].body) != body {
		t.Fatalf("тело upload-url дошло изменённым:\n got %s\nwant %s", files[0].body, body)
	}
	if got := files[0].headers["X-Scope-Workspace-ID"]; got != ownWorkspaceID {
		t.Fatalf("X-Scope-Workspace-ID=%q, ожидался в нижнем регистре %s", got, ownWorkspaceID)
	}

	w, stub = doScoped(t, http.MethodPost, "/api/v1/files/upload-url", uploadURLBody(foreignWorkspaceID), nil)
	if w.Code != http.StatusForbidden || len(stub.callsTo("files")) != 0 {
		t.Fatalf("upload-url с чужим пространством -> %d, к files ушло %d", w.Code, len(stub.callsTo("files")))
	}

	w, _ = doScoped(t, http.MethodPost, "/api/v1/files/upload-url", `{"checksum":"x"}`, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("upload-url без workspace_id -> %d, ожидался 400", w.Code)
	}
}

// Повтор параметра: проверяется и уходит вниз первое значение — ровно то,
// что ProxyToService кладёт в строку запроса апстрима.
func TestFilesRepeatedWorkspaceIDUsesFirstValueOnly(t *testing.T) {
	w, stub := doScoped(t, http.MethodGet, "/api/v1/files?workspace_id="+ownWorkspaceID+"&workspace_id="+foreignWorkspaceID, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /files с повтором workspace_id -> %d (%s)", w.Code, w.Body.String())
	}
	files := stub.callsTo("files")
	if len(files) != 1 {
		t.Fatalf("к files ушло %d запросов", len(files))
	}
	if got := files[0].headers["X-Scope-Workspace-ID"]; got != ownWorkspaceID {
		t.Fatalf("X-Scope-Workspace-ID=%q, ожидалось первое значение %s", got, ownWorkspaceID)
	}
	if got := files[0].query["workspace_id"]; got != ownWorkspaceID {
		t.Fatalf("в строке запроса апстрима workspace_id=%q, ожидалось первое значение %s", got, ownWorkspaceID)
	}
	coll := stub.callsTo("collections")
	if len(coll) != 1 || coll[0].path != "/api/v1/workspaces/"+ownWorkspaceID+"/members" {
		t.Fatalf("роль спрошена не по первому значению: %+v", coll)
	}

	// Чужое первым — отказ, своё вторым не спасает.
	w, stub = doScoped(t, http.MethodGet, "/api/v1/files?workspace_id="+foreignWorkspaceID+"&workspace_id="+ownWorkspaceID, "", nil)
	if w.Code != http.StatusForbidden || len(stub.callsTo("files")) != 0 {
		t.Fatalf("чужое первым -> %d, к files ушло %d; ожидался 403 и 0", w.Code, len(stub.callsTo("files")))
	}
}

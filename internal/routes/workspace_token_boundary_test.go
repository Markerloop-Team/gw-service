package routes_test

// SDL-613 S9 (EP-111): граница токена пространства на настоящем роутере
// шлюза, флаг SCOPE_REQUIRE_WORKSPACE_TOKEN включён и выключен.
//
// Инварианты (флаг включён):
//   - токен сессии на каждом маршруте со скоупом (pages, files) — 401
//     workspace_token_required, ни одного вызова вниз; флаг выключен — тот же
//     запрос проходит, как на master;
//   - токен пространства на маршрутах со скоупом — 200, collections о членстве
//     не спрошен ни разу;
//   - /workspaces/:id…: токен своего пространства проходит без /members (и на
//     DELETE участника — роль для отметки берётся из токена), чужого — 403;
//   - токен, погашенный отметкой отзыва, — 401 и вне маршрутов со скоупом;
//   - /collections: названное пространство сверяется с wsid; /collections/:id и
//     /records — проверяется только сам токен;
//   - каждый маршрут за jwtMiddleware, кроме перечисленных, отвечает токену
//     пространства 403 account_session_required, не дойдя до апстрима;
//     флаг выключен — ни одного такого ответа;
//   - /data/*: токен пространства — 403, токен сессии, mlp_-ключ и аноним
//     проходят;
//   - онбординг новым пользователем на токене сессии флаг не задевает.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"gateway-service/internal/config"

	sdkjwt "gitlab.com/markerloop/go-sdk/pkg/jwt"
	"gitlab.com/markerloop/go-sdk/pkg/wsaccess"
)

// newUserID — пользователь без единого пространства (первый вход).
const newUserID = "12121212-3434-4565-8787-909090909090"

func withRequireWorkspaceToken(on bool) func(*config.Config) {
	return func(c *config.Config) { c.Scope.RequireWorkspaceToken = on }
}

func sessionTokenFor(t *testing.T, signer *sdkjwt.JWTService, userID string) string {
	t.Helper()
	pair, err := signer.GenerateTokensWithUsername(userID, "user", "user@example.com")
	if err != nil {
		t.Fatalf("sign session token: %v", err)
	}
	return pair.AccessToken
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func errorCode(w *httptest.ResponseRecorder) string {
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return body.Error
}

func doWithBody(r *gin.Engine, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// scopedRequest — конкретный запрос к записи реестра со скоупом в
// пространстве workspaceID.
func scopedRequest(rc config.RouteConfig, workspaceID string) (path, body string) {
	path = fillParams(strings.ReplaceAll(rc.Path, "/:param", "/3"))
	if rc.ScopeInBody {
		return path, `{"workspace_id":"` + workspaceID + `"}`
	}
	return path + "?workspace_id=" + workspaceID, `{}`
}

func scopedRoutes(t *testing.T) []config.RouteConfig {
	t.Helper()
	var out []config.RouteConfig
	for _, rc := range config.GetRouteConfigs() {
		if rc.ScopeParam != "" {
			out = append(out, rc)
		}
	}
	if len(out) < 30 {
		t.Fatalf("маршрутов со скоупом %d — меньше ожидаемого, реестр не тот", len(out))
	}
	return out
}

func TestSessionTokenOnScopedRoutesIsWorkspaceTokenRequired(t *testing.T) {
	for _, rc := range scopedRoutes(t) {
		stub := &membershipProxy{}
		r, signer := newRouterWithSigner(t, stub, nil, withRequireWorkspaceToken(true))
		path, body := scopedRequest(rc, ownWorkspaceID)
		w := doWithBody(r, rc.Method, path, body, bearer(sessionTokenFor(t, signer, testUserID)))
		if w.Code != http.StatusUnauthorized || errorCode(w) != "workspace_token_required" {
			t.Errorf("флаг включён: токен сессии на %s %s -> %d %q, ожидался 401 workspace_token_required", rc.Method, path, w.Code, errorCode(w))
		}
		if n := len(stub.calls); n != 0 {
			t.Errorf("%s %s: %d вызовов вниз до отказа, ожидалось 0 (первый: %+v)", rc.Method, path, n, stub.calls[0])
		}
	}
}

// Контроль: флаг выключен — токен сессии владельца проходит, как на master.
func TestSessionTokenOnScopedRoutesPassesWhenFlagOff(t *testing.T) {
	for _, rc := range scopedRoutes(t) {
		stub := &membershipProxy{}
		r, signer := newRouterWithSigner(t, stub, nil, withRequireWorkspaceToken(false))
		path, body := scopedRequest(rc, ownWorkspaceID)
		w := doWithBody(r, rc.Method, path, body, bearer(sessionTokenFor(t, signer, testUserID)))
		if w.Code != http.StatusOK {
			t.Errorf("флаг выключен: токен сессии на %s %s -> %d (%s), ожидался 200", rc.Method, path, w.Code, w.Body.String())
		}
	}
}

func TestWorkspaceTokenOnScopedRoutesSkipsMembers(t *testing.T) {
	for _, rc := range scopedRoutes(t) {
		_, rs := newTestRedis(t)
		stub := &membershipProxy{}
		r, signer := newRouterWithSigner(t, stub, rs, withRequireWorkspaceToken(true))
		path, body := scopedRequest(rc, ownWorkspaceID)
		w := doWithBody(r, rc.Method, path, body, bearer(workspaceTokenFor(t, signer, testUserID, ownWorkspaceID, wsaccess.RoleOwner)))
		if w.Code != http.StatusOK {
			t.Errorf("флаг включён: токен пространства на %s %s -> %d (%s), ожидался 200", rc.Method, path, w.Code, w.Body.String())
		}
		if n := membersCalls(stub); n != 0 {
			t.Errorf("%s %s: collections спрошен о членстве %d раз, ожидалось 0", rc.Method, path, n)
		}
	}
}

// workspacePathRoutes — маршруты Gin под /api/v1/workspaces/:id.
func workspacePathRoutes(t *testing.T, r *gin.Engine) []gin.RouteInfo {
	t.Helper()
	var out []gin.RouteInfo
	for _, ri := range r.Routes() {
		if strings.HasPrefix(ri.Path, "/api/v1/workspaces/:id") {
			out = append(out, ri)
		}
	}
	if len(out) < 20 {
		t.Fatalf("маршрутов /workspaces/:id %d — меньше ожидаемого", len(out))
	}
	return out
}

func fillWorkspacePath(pattern, workspaceID string) string {
	parts := strings.Split(pattern, "/")
	for i, p := range parts {
		switch {
		case p == ":id":
			parts[i] = workspaceID
		case strings.HasPrefix(p, ":"):
			parts[i] = otherUserID
		}
	}
	return strings.Join(parts, "/")
}

func TestWorkspaceTokenOnOwnWorkspacePathsPassesWithoutMembers(t *testing.T) {
	probe, _ := newRouterWithSigner(t, &membershipProxy{}, nil)
	for _, ri := range workspacePathRoutes(t, probe) {
		_, rs := newTestRedis(t)
		stub := &membershipProxy{}
		r, signer := newRouterWithSigner(t, stub, rs, withRequireWorkspaceToken(true))
		path := fillWorkspacePath(ri.Path, ownWorkspaceID)
		w := doRequest(r, ri.Method, path, bearer(workspaceTokenFor(t, signer, testUserID, ownWorkspaceID, wsaccess.RoleOwner)))
		if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden || w.Code >= 500 {
			t.Errorf("токен своего пространства на %s %s -> %d (%s)", ri.Method, path, w.Code, w.Body.String())
		}
		proxied := false
		for _, c := range stub.callsTo("collections") {
			if c.method == ri.Method && c.path == path {
				proxied = true
			}
		}
		if !proxied {
			t.Errorf("%s %s не дошёл до collections", ri.Method, path)
		}
		// GET /:id/members — это сам проксируемый запрос, а не вопрос шлюза.
		want := 0
		if ri.Method == http.MethodGet && strings.HasSuffix(ri.Path, "/members") {
			want = 1
		}
		if n := membersCalls(stub); n != want {
			t.Errorf("%s %s: GET /members в collections %d раз, ожидалось %d", ri.Method, path, n, want)
		}
	}
}

func TestWorkspaceTokenOnForeignWorkspacePathsIsForbidden(t *testing.T) {
	probe, _ := newRouterWithSigner(t, &membershipProxy{}, nil)
	for _, ri := range workspacePathRoutes(t, probe) {
		_, rs := newTestRedis(t)
		stub := &membershipProxy{}
		r, signer := newRouterWithSigner(t, stub, rs, withRequireWorkspaceToken(true))
		path := fillWorkspacePath(ri.Path, memberWorkspaceID)
		w := doRequest(r, ri.Method, path, bearer(workspaceTokenFor(t, signer, testUserID, ownWorkspaceID, wsaccess.RoleOwner)))
		if w.Code != http.StatusForbidden {
			t.Errorf("токен W1 на %s %s -> %d, ожидался 403", ri.Method, path, w.Code)
		}
		if n := len(stub.callsTo("collections")); n != 0 {
			t.Errorf("%s %s: %d вызовов collections, ожидалось 0", ri.Method, path, n)
		}
	}
}

// Отметка отзыва гасит токен и вне маршрутов со скоупом: участник
// otherUserID исключён владельцем — его токен пространства на /workspaces/W1
// и на /records — 401.
func TestRevokedWorkspaceTokenIsRejectedOnUnscopedRoutes(t *testing.T) {
	for _, path := range []string{
		"/api/v1/workspaces/" + ownWorkspaceID,
		"/api/v1/records/" + testFileID,
		"/api/v1/collections?workspace_id=" + ownWorkspaceID,
	} {
		mr, rs := newTestRedis(t)
		stub := &membershipProxy{}
		r, signer := newRouterWithSigner(t, stub, rs, withRequireWorkspaceToken(true))
		member := bearer(workspaceTokenFor(t, signer, otherUserID, ownWorkspaceID, wsaccess.RoleMember))

		if w := doRequest(r, http.MethodGet, path, member); w.Code == http.StatusUnauthorized {
			t.Fatalf("до исключения %s -> 401 (%s)", path, w.Body.String())
		}
		if w := doRequest(r, http.MethodDelete, "/api/v1/workspaces/"+ownWorkspaceID+"/members/"+otherUserID,
			bearer(sessionTokenFor(t, signer, testUserID))); w.Code != http.StatusOK {
			t.Fatalf("DELETE участника -> %d (%s)", w.Code, w.Body.String())
		}
		mr.FastForward(time.Minute)
		if w := doRequest(r, http.MethodGet, path, member); w.Code != http.StatusUnauthorized {
			t.Errorf("после исключения %s -> %d, ожидался 401", path, w.Code)
		}
	}
}

func TestWorkspaceTokenOnCollectionsAndRecords(t *testing.T) {
	cases := []struct {
		method, path, body string
		want               int
	}{
		{http.MethodGet, "/api/v1/collections?workspace_id=" + ownWorkspaceID, `{}`, http.StatusOK},
		{http.MethodGet, "/api/v1/collections?workspace_id=" + strings.ToUpper(ownWorkspaceID), `{}`, http.StatusOK},
		{http.MethodGet, "/api/v1/collections?workspace_id=" + memberWorkspaceID, `{}`, http.StatusForbidden},
		{http.MethodPost, "/api/v1/collections", `{"workspace_id":"` + ownWorkspaceID + `","key":"posts","name":"Posts"}`, http.StatusOK},
		{http.MethodPost, "/api/v1/collections", `{"workspace_id":"` + memberWorkspaceID + `","key":"posts","name":"Posts"}`, http.StatusForbidden},
		{http.MethodGet, "/api/v1/collections/" + testFileID, `{}`, http.StatusOK},
		{http.MethodPost, "/api/v1/collections/" + testFileID + "/fields", `{"key":"title"}`, http.StatusOK},
		{http.MethodGet, "/api/v1/records?collection_id=" + testFileID, `{}`, http.StatusOK},
		{http.MethodPost, "/api/v1/records", `{"collection_id":"` + testFileID + `","data":{}}`, http.StatusOK},
		{http.MethodPatch, "/api/v1/records/" + testFileID, `{"data":{},"version":1}`, http.StatusOK},
		{http.MethodDelete, "/api/v1/records/" + testFileID, `{}`, http.StatusOK},
	}
	for _, tc := range cases {
		_, rs := newTestRedis(t)
		stub := &membershipProxy{}
		r, signer := newRouterWithSigner(t, stub, rs, withRequireWorkspaceToken(true))
		w := doWithBody(r, tc.method, tc.path, tc.body, bearer(workspaceTokenFor(t, signer, testUserID, ownWorkspaceID, wsaccess.RoleOwner)))
		if w.Code != tc.want {
			t.Errorf("%s %s -> %d (%s), ожидался %d", tc.method, tc.path, w.Code, w.Body.String(), tc.want)
		}
		calls := stub.callsTo("collections")
		if tc.want == http.StatusForbidden && len(calls) != 0 {
			t.Errorf("%s %s: отказ, но %d вызовов collections", tc.method, tc.path, len(calls))
		}
		if tc.want == http.StatusOK {
			if len(calls) != 1 {
				t.Fatalf("%s %s: %d вызовов collections, ожидался 1 (сам запрос)", tc.method, tc.path, len(calls))
			}
			if tc.method == http.MethodPost && string(calls[0].body) != tc.body {
				t.Errorf("%s %s: тело изменено: %s", tc.method, tc.path, calls[0].body)
			}
		}
	}
}

// boundaryAllowsWorkspaceToken — маршрут, на который токен пространства
// пускается (со своей сверкой), а не отбивается как маршрут учётки.
func boundaryAllowsWorkspaceToken(method, pattern string) bool {
	if strings.HasPrefix(pattern, "/api/v1/workspaces/:id") ||
		pattern == "/api/v1/collections" || strings.HasPrefix(pattern, "/api/v1/collections/") ||
		pattern == "/api/v1/records" || strings.HasPrefix(pattern, "/api/v1/records/") {
		return true
	}
	norm := strings.ReplaceAll(pattern, "/:n", "/:param")
	for _, rc := range config.GetRouteConfigs() {
		if rc.ScopeParam == "" || rc.Method != method {
			continue
		}
		if strings.ReplaceAll(rc.Path, "/:param", "/:n") == pattern || rc.Path == norm {
			return true
		}
	}
	return false
}

// sweepWorkspaceTokenOnJWTRoutes — каждый маршрут, который без Authorization
// отвечает 401 (стоит jwtMiddleware), с токеном пространства. Возвращает,
// сколько маршрутов учётки отбито account_session_required.
func sweepWorkspaceTokenOnJWTRoutes(t *testing.T, requireWorkspaceToken bool) (refused, accountRoutes int) {
	t.Helper()
	_, rs := newTestRedis(t)
	stub := &membershipProxy{}
	r, signer := newRouterWithSigner(t, stub, rs, withRequireWorkspaceToken(requireWorkspaceToken))
	wsToken := bearer(workspaceTokenFor(t, signer, testUserID, ownWorkspaceID, wsaccess.RoleOwner))
	wsToken["X-Service-Key"] = testServiceKey
	for _, ri := range r.Routes() {
		path := fillParams(ri.Path)
		if w := doRequest(r, ri.Method, path, map[string]string{"X-Service-Key": testServiceKey}); w.Code != http.StatusUnauthorized {
			continue
		}
		before := len(stub.calls)
		w := doRequest(r, ri.Method, path, wsToken)
		isRefused := w.Code == http.StatusForbidden && errorCode(w) == "account_session_required"
		if boundaryAllowsWorkspaceToken(ri.Method, ri.Path) {
			if isRefused {
				t.Errorf("%s %s: токен пространства отбит как на маршруте учётки", ri.Method, ri.Path)
			}
			continue
		}
		accountRoutes++
		if isRefused {
			refused++
			if after := len(stub.calls); after != before {
				t.Errorf("%s %s: отказ, но %d вызовов вниз", ri.Method, ri.Path, after-before)
			}
		} else if requireWorkspaceToken {
			t.Errorf("флаг включён: токен пространства на маршруте учётки %s %s -> %d %q, ожидался 403 account_session_required", ri.Method, ri.Path, w.Code, errorCode(w))
		}
	}
	return refused, accountRoutes
}

func TestEveryJWTRouteHasWorkspaceTokenBoundary(t *testing.T) {
	refused, accountRoutes := sweepWorkspaceTokenOnJWTRoutes(t, true)
	// /users 13, /roles 8, /permissions 5, /external-accounts 6, /users/my/access,
	// /auth 3, /oauth 5, /workspaces без id 3, /invites 2.
	if accountRoutes < 40 {
		t.Fatalf("маршрутов учётки за jwtMiddleware %d — свип ничего не проверил", accountRoutes)
	}
	if refused != accountRoutes {
		t.Fatalf("отбито %d из %d маршрутов учётки", refused, accountRoutes)
	}
}

func TestWorkspaceTokenOnAccountRoutesPassesWhenFlagOff(t *testing.T) {
	if refused, _ := sweepWorkspaceTokenOnJWTRoutes(t, false); refused != 0 {
		t.Fatalf("флаг выключен: %d маршрутов отбили токен пространства, ожидалось 0 (поведение до S9)", refused)
	}
}

// Бутстрап-тупик: всё, что нужно новому пользователю до первого обмена,
// идёт на токене сессии и с флагом не требует токена пространства.
func TestOnboardingWithSessionTokenIsUntouchedByFlag(t *testing.T) {
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/workspaces"},
		{http.MethodPost, "/api/v1/workspaces"},
		{http.MethodPost, "/api/v1/auth/token/workspace"},
		{http.MethodGet, "/api/v1/users/my"},
		{http.MethodGet, "/api/v1/users/my/access"},
		{http.MethodPost, "/api/v1/invites/preview"},
		{http.MethodPost, "/api/v1/invites/accept"},
		{http.MethodPost, "/api/v1/auth/request-email-verification"},
		{http.MethodGet, "/api/v1/oauth/grants"},
	} {
		stub := &membershipProxy{}
		r, signer := newRouterWithSigner(t, stub, nil, withRequireWorkspaceToken(true))
		w := doRequest(r, rt.method, rt.path, bearer(sessionTokenFor(t, signer, newUserID)))
		if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
			t.Errorf("флаг включён: новый пользователь на токене сессии %s %s -> %d (%s)", rt.method, rt.path, w.Code, w.Body.String())
		}
		// Ответ — апстрима (стаб), а не шлюза: запрос проксирован как есть.
		proxied := false
		for _, c := range stub.calls {
			if c.method == rt.method && c.path == rt.path {
				proxied = true
			}
		}
		if !proxied {
			t.Errorf("%s %s не проксирован", rt.method, rt.path)
		}
	}
}

func TestDataPlaneRefusesWorkspaceToken(t *testing.T) {
	for _, on := range []bool{true, false} {
		stub := &captureProxy{}
		r, signer := newRouterWithSigner(t, stub, nil, withRequireWorkspaceToken(on))
		path := "/api/v1/data/" + ownWorkspaceID + "/posts"

		w := doRequest(r, http.MethodGet, path, bearer(workspaceTokenFor(t, signer, testUserID, ownWorkspaceID, wsaccess.RoleOwner)))
		if on && (w.Code != http.StatusForbidden || errorCode(w) != "account_session_required" || stub.calls != 0) {
			t.Errorf("флаг включён: токен пространства на /data -> %d %q, вызовов %d; ожидался 403 без вызова", w.Code, errorCode(w), stub.calls)
		}
		if !on && (w.Code != http.StatusOK || stub.calls != 1) {
			t.Errorf("флаг выключен: токен пространства на /data -> %d, вызовов %d; ожидался проход", w.Code, stub.calls)
		}

		for _, auth := range []map[string]string{
			bearer(sessionTokenFor(t, signer, testUserID)),
			bearer("mlp_test_key"),
			{},
		} {
			before := stub.calls
			if w := doRequest(r, http.MethodGet, path, auth); w.Code != http.StatusOK || stub.calls != before+1 {
				t.Errorf("флаг=%v: %v на /data -> %d, ожидался проход", on, auth, w.Code)
			}
		}
	}
}

// DELETE участника владельцем на токене пространства: право на первую
// отметку отзыва берётся из wsr токена, collections о роли не спрошен.
// Флаг выключен — прежний путь через /members.
func TestMemberDeleteWithWorkspaceTokenTakesRoleFromToken(t *testing.T) {
	for _, tc := range []struct {
		on          bool
		wantMembers int
	}{{true, 0}, {false, 1}} {
		mr, rs := newTestRedis(t)
		stub := &membershipProxy{}
		r, signer := newRouterWithSigner(t, stub, rs, withRequireWorkspaceToken(tc.on))
		w := doRequest(r, http.MethodDelete, "/api/v1/workspaces/"+ownWorkspaceID+"/members/"+otherUserID,
			bearer(workspaceTokenFor(t, signer, testUserID, ownWorkspaceID, wsaccess.RoleOwner)))
		if w.Code != http.StatusOK {
			t.Fatalf("флаг=%v: DELETE участника -> %d (%s)", tc.on, w.Code, w.Body.String())
		}
		if n := membersCalls(stub); n != tc.wantMembers {
			t.Errorf("флаг=%v: GET /members %d раз, ожидалось %d", tc.on, n, tc.wantMembers)
		}
		if !mr.Exists(wsaccess.RevokedKeyPrefix + otherUserID + ":" + ownWorkspaceID) {
			t.Errorf("флаг=%v: отметки отзыва нет", tc.on)
		}
	}
}

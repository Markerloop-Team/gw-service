package routes_test

// SDL-692 (EP-20): публикация OAuth-сервера auth-service и отказ шлюза
// токенам с чужим aud.

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"gateway-service/internal/models"

	sdkjwt "gitlab.com/markerloop/go-sdk/pkg/jwt"
	"gitlab.com/markerloop/go-sdk/pkg/wsaccess"
)

// mcpTokenFor — MCP access token так, как его выпускает auth-service
// (SDL-691): тот же ключ, wsid/wsr пространства из согласия, плюс aud.
func mcpTokenFor(t *testing.T, key *rsa.PrivateKey, userID, workspaceID string, aud ...string) string {
	t.Helper()
	now := time.Now()
	claims := &sdkjwt.Claims{
		UserID:        userID,
		Username:      "member",
		WorkspaceID:   workspaceID,
		WorkspaceRole: string(wsaccess.RoleMember),
		RegisteredClaims: jwtlib.RegisteredClaims{
			Audience:  jwtlib.ClaimStrings(aud),
			IssuedAt:  jwtlib.NewNumericDate(now),
			ExpiresAt: jwtlib.NewNumericDate(now.Add(10 * time.Minute)),
			ID:        "mcp-test-jti",
		},
	}
	tok, err := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("sign MCP token: %v", err)
	}
	return tok
}

// Критерий приёмки SDL-692: MCP-токен (aud) на маршруте шлюза — 401;
// обменный токен того же пользователя — 200 на своём workspace_id и 403
// на чужом.
func TestMCPTokenIsRejectedOnGatewayRoutes(t *testing.T) {
	_, rs := newTestRedis(t)
	stub := &membershipProxy{}
	r, signer, key := newRouterWithKey(t, stub, rs)
	own := "/api/v1/pages/routes?workspace_id=" + ownWorkspaceID
	foreign := "/api/v1/pages/routes?workspace_id=" + memberWorkspaceID

	for _, aud := range [][]string{{"mcp"}, {"https://mcp.test.example.com/mcp"}} {
		mcp := map[string]string{"Authorization": "Bearer " + mcpTokenFor(t, key, otherUserID, ownWorkspaceID, aud...)}
		if w := doRequest(r, http.MethodGet, own, mcp); w.Code != http.StatusUnauthorized {
			t.Fatalf("MCP-токен aud=%v на GET %s -> %d (%s), ожидался 401", aud, own, w.Code, w.Body.String())
		}
	}

	// Без aud — тот же токен проходит: отказ держится именно на aud.
	noAud := map[string]string{"Authorization": "Bearer " + mcpTokenFor(t, key, otherUserID, ownWorkspaceID)}
	if w := doRequest(r, http.MethodGet, own, noAud); w.Code != http.StatusOK {
		t.Fatalf("контроль: тот же токен без aud -> %d (%s), ожидался 200", w.Code, w.Body.String())
	}

	exchanged := map[string]string{"Authorization": "Bearer " + workspaceTokenFor(t, signer, otherUserID, ownWorkspaceID, wsaccess.RoleMember)}
	if w := doRequest(r, http.MethodGet, own, exchanged); w.Code != http.StatusOK {
		t.Fatalf("обменный токен на своё пространство -> %d (%s), ожидался 200", w.Code, w.Body.String())
	}
	if w := doRequest(r, http.MethodGet, foreign, exchanged); w.Code != http.StatusForbidden {
		t.Fatalf("обменный токен на чужое пространство -> %d, ожидался 403", w.Code)
	}
}

// MCP-токен не открывает и маршруты без скоупа, и ручки самого шлюза для
// auth (token/workspace, согласие OAuth).
func TestMCPTokenIsRejectedEverywhereJWTIsRequired(t *testing.T) {
	stub := &stubProxy{grantPermission: true}
	r, _, key := newRouterWithKey(t, stub, nil)
	mcp := map[string]string{"Authorization": "Bearer " + mcpTokenFor(t, key, testUserID, ownWorkspaceID, "mcp")}

	for _, probe := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/users/my"},
		{http.MethodGet, "/api/v1/users/my/access"},
		{http.MethodPost, "/api/v1/auth/token/workspace"},
		{http.MethodPost, "/api/v1/oauth/authorize/approve"},
		{http.MethodGet, fillParams("/api/v1/oauth/authorize/requests/:request_id")},
		{http.MethodGet, "/api/v1/oauth/grants"},
		{http.MethodDelete, fillParams("/api/v1/oauth/grants/:grant_id")},
	} {
		if w := doRequest(r, probe.method, probe.path, mcp); w.Code != http.StatusUnauthorized {
			t.Errorf("MCP-токен на %s %s -> %d, ожидался 401", probe.method, probe.path, w.Code)
		}
	}
}

// Опубликованные ручки OAuth: анонимные отвечают без токена, ручки
// согласия требуют токен сессии.
func TestOAuthRoutesArePublished(t *testing.T) {
	r, token := newTestRouter(t, true)

	for _, probe := range []struct{ method, path string }{
		{http.MethodGet, "/.well-known/oauth-authorization-server"},
		{http.MethodGet, "/api/.well-known/oauth-authorization-server"},
		{http.MethodPost, "/api/v1/oauth/register"},
		{http.MethodPost, "/api/v1/oauth/token"},
	} {
		if w := doRequest(r, probe.method, probe.path, nil); w.Code != http.StatusOK {
			t.Errorf("%s %s без токена -> %d, ожидался 200 (анонимная ручка)", probe.method, probe.path, w.Code)
		}
	}

	for _, probe := range []struct{ method, path string }{
		{http.MethodGet, fillParams("/api/v1/oauth/authorize/requests/:request_id")},
		{http.MethodPost, "/api/v1/oauth/authorize/approve"},
		{http.MethodPost, "/api/v1/oauth/authorize/deny"},
		{http.MethodGet, "/api/v1/oauth/grants"},                          // SDL-693
		{http.MethodDelete, fillParams("/api/v1/oauth/grants/:grant_id")}, // SDL-693
	} {
		if w := doRequest(r, probe.method, probe.path, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s без токена -> %d, ожидался 401", probe.method, probe.path, w.Code)
		}
		if w := doRequest(r, probe.method, probe.path, map[string]string{"Authorization": "Bearer " + token}); w.Code != http.StatusOK {
			t.Errorf("%s %s с токеном сессии -> %d, ожидался 200", probe.method, probe.path, w.Code)
		}
	}
}

// /oauth/exchange — только X-Service-Key, шлюз его не публикует (SDL-691):
// иначе любой DCR-клиент обменял бы MCP-токен на общий токен API.
func TestOAuthExchangeIsNotPublished(t *testing.T) {
	r, token := newTestRouter(t, true)
	for _, ri := range r.Routes() {
		if ri.Path == "/api/v1/oauth/exchange" || ri.Path == "/api/v1/auth/oauth/exchange" {
			t.Fatalf("%s %s опубликован шлюзом — ручка только межсервисная", ri.Method, ri.Path)
		}
	}
	w := doRequest(r, http.MethodPost, "/api/v1/oauth/exchange", map[string]string{
		"Authorization": "Bearer " + token,
		"X-Service-Key": testServiceKey,
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("POST /api/v1/oauth/exchange -> %d, ожидался Gin 404", w.Code)
	}
}

// upstreamProxy — stubProxy, чей GetServiceURL указывает на живой
// httptest-сервер (ProxyRedirectToService ходит по сети сам).
type upstreamProxy struct {
	stubProxy
	url string
}

func (s *upstreamProxy) GetServiceURL(string) (string, error) { return s.url, nil }

// GET /oauth/authorize отвечает 302; шлюз отдаёт его браузеру как есть,
// а не идёт по Location сам.
func TestOAuthAuthorizeRedirectIsPassedThrough(t *testing.T) {
	followed := false
	var gotPath, gotQuery, gotUserID string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/consent" {
			followed = true
			w.WriteHeader(http.StatusOK)
			return
		}
		gotPath, gotQuery, gotUserID = req.URL.Path, req.URL.RawQuery, req.Header.Get("X-User-ID")
		http.Redirect(w, req, "/consent?request_id=r1", http.StatusFound)
	}))
	defer upstream.Close()

	r, _ := newRouterWithProxy(t, &upstreamProxy{url: upstream.URL})
	w := doRequest(r, http.MethodGet, "/api/v1/oauth/authorize?client_id=c1&state=s1", map[string]string{"X-User-ID": "forged"})

	if w.Code != http.StatusFound {
		t.Fatalf("GET /oauth/authorize -> %d, ожидался 302 от auth-service", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/consent?request_id=r1" {
		t.Errorf("Location = %q", loc)
	}
	if followed {
		t.Errorf("шлюз сам прошёл по редиректу")
	}
	if gotPath != "/api/v1/oauth/authorize" || gotQuery != "client_id=c1&state=s1" {
		t.Errorf("апстрим получил %s?%s", gotPath, gotQuery)
	}
	if gotUserID != "" {
		t.Errorf("клиентский X-User-ID ушёл вниз: %q", gotUserID)
	}
}

// Ревью SDL-692: /api/v1/data идёт без jwtMiddleware, Authorization уходит в
// collections, где DataPrincipal проверяет JWT go-sdk ValidateToken и принял
// бы MCP-токен как пользователя. Гард уровня роутера режет его до прокси —
// в том числе в схеме `bearer` любого регистра и с пробелами.
func TestMCPTokenIsRejectedOnDataPlane(t *testing.T) {
	stub := &stubProxy{grantPermission: true}
	r, signer, key := newRouterWithKey(t, stub, nil)
	mcp := mcpTokenFor(t, key, testUserID, ownWorkspaceID, "mcp")
	path := "/api/v1/data/" + ownWorkspaceID + "/posts"

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, header := range []string{"Bearer " + mcp, "bearer " + mcp, "  BEARER   " + mcp + "  "} {
			if w := doRequest(r, method, path, map[string]string{"Authorization": header}); w.Code != http.StatusUnauthorized {
				t.Errorf("MCP-токен (%q…) на %s %s -> %d, ожидался 401", header[:8], method, path, w.Code)
			}
		}

		// Как раньше: без токена, с токеном сессии и с mlp_-ключом /data
		// проксируется, решает collections-service.
		pair, err := signer.GenerateTokensWithUsername(testUserID, "u", "u@example.com")
		if err != nil {
			t.Fatalf("sign session: %v", err)
		}
		for name, headers := range map[string]map[string]string{
			"без токена":   nil,
			"токен сессии": {"Authorization": "Bearer " + pair.AccessToken},
			"mlp_-ключ":    {"Authorization": "Bearer mlp_test_key"},
		} {
			if w := doRequest(r, method, path, headers); w.Code != http.StatusOK {
				t.Errorf("%s на %s %s -> %d, ожидался 200 (проксирование как раньше)", name, method, path, w.Code)
			}
		}
	}
}

// authCall — один вызов апстрима, как его увидел ProxyService.
type authCall struct {
	service, method, path string
	headers               map[string]string
	query                 map[string]string
}

// recordingProxy — stubProxy, запоминающий вызовы.
type recordingProxy struct {
	stubProxy
	calls []authCall
}

func (s *recordingProxy) ProxyRequest(serviceName, method, path string, headers map[string]string, queryParams map[string]string, body []byte) (*models.ProxyResponse, error) {
	s.calls = append(s.calls, authCall{serviceName, method, path, headers, queryParams})
	return s.stubProxy.ProxyRequest(serviceName, method, path, headers, queryParams, body)
}

// SDL-693: «Connected agents» — список и отзыв своих выдач уходят в
// auth-service тем же путём, с токеном сессии (auth сам решает, чья выдача)
// и X-User-ID из токена, а не от клиента; проверки прав пространства нет.
func TestOAuthGrantRoutesProxyToAuth(t *testing.T) {
	stub := &recordingProxy{stubProxy: stubProxy{grantPermission: false}}
	r, token := newRouterWithProxy(t, stub)
	for _, probe := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/oauth/grants"},
		{http.MethodDelete, "/api/v1/oauth/grants/zK5HTY0g6Q_Ug1T1GXx50Lew"},
	} {
		stub.calls = nil
		w := doRequest(r, probe.method, probe.path, map[string]string{
			"Authorization": "Bearer " + token,
			"X-User-ID":     "forged",
		})
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s -> %d (%s), ожидался 200", probe.method, probe.path, w.Code, w.Body.String())
		}
		if len(stub.calls) != 1 {
			t.Fatalf("%s %s: вызовов апстрима %d, ожидался ровно один (без check-permission): %+v", probe.method, probe.path, len(stub.calls), stub.calls)
		}
		c := stub.calls[0]
		if c.service != "auth" || c.method != probe.method || c.path != probe.path {
			t.Errorf("апстрим получил %s %s %s, ожидался auth %s %s", c.service, c.method, c.path, probe.method, probe.path)
		}
		if c.headers["Authorization"] != "Bearer "+token {
			t.Errorf("%s %s: токен сессии не дошёл до auth-service", probe.method, probe.path)
		}
		if c.headers["X-User-ID"] != testUserID {
			t.Errorf("%s %s: X-User-ID = %q, ожидался актор из токена", probe.method, probe.path, c.headers["X-User-ID"])
		}
	}
}

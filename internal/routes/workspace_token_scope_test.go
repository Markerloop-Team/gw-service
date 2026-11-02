package routes_test

// SDL-613 S4: токен пространства на настоящем роутере шлюза — подпись тем
// же ключом, что проверяет JWTMiddleware, Redis — miniredis.
//
// Инварианты:
//   - токен пространства на своё пространство: 200, членство у collections
//     не спрашивается (стаб collections отвечает 404 всем, кроме
//     testUserID, — пропусти шлюз токен в старый путь, было бы 403);
//   - токен на одно пространство и workspace_id другого: 403;
//   - сквозной отзыв: владелец исключает участника (DELETE через шлюз), и
//     уже выпущенный токен участника отвергается 401 — и через 10 минут
//     тоже (отметка живёт wsaccess.RevocationTTL, не 70 с старого маркера).
//     Контроль: без DELETE тот же токен через те же 10 минут — 200.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	sdkjwt "gitlab.com/markerloop/go-sdk/pkg/jwt"
	"gitlab.com/markerloop/go-sdk/pkg/wsaccess"
)

// workspaceTokenFor — токен пространства для userID, выпущенный сейчас.
func workspaceTokenFor(t *testing.T, signer *sdkjwt.JWTService, userID, workspaceID string, role wsaccess.Role) string {
	t.Helper()
	session := &sdkjwt.Claims{
		UserID:   userID,
		Username: "member",
		RegisteredClaims: jwtlib.RegisteredClaims{
			ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token, _, err := signer.GenerateWorkspaceToken(session, workspaceID, role, time.Now())
	if err != nil {
		t.Fatalf("GenerateWorkspaceToken: %v", err)
	}
	return token
}

func membersCalls(stub *membershipProxy) int {
	n := 0
	for _, c := range stub.callsTo("collections") {
		if strings.HasSuffix(c.path, "/members") && c.method == http.MethodGet {
			n++
		}
	}
	return n
}

func TestWorkspaceTokenScopesPagesWithoutCollections(t *testing.T) {
	_, rs := newTestRedis(t)
	stub := &membershipProxy{}
	r, signer := newRouterWithSigner(t, stub, rs)
	token := workspaceTokenFor(t, signer, otherUserID, ownWorkspaceID, wsaccess.RoleMember)
	auth := map[string]string{"Authorization": "Bearer " + token}

	w := doRequest(r, http.MethodGet, "/api/v1/pages/routes?workspace_id="+ownWorkspaceID, auth)
	if w.Code != http.StatusOK {
		t.Fatalf("токен пространства на своё пространство -> %d (%s)", w.Code, w.Body.String())
	}
	if n := membersCalls(stub); n != 0 {
		t.Errorf("collections спрошен о членстве %d раз, ожидалось 0", n)
	}
	checks := stub.permissionChecks()
	if len(checks) == 0 || checks[len(checks)-1].WorkspaceRole != "member" || checks[len(checks)-1].WorkspaceID != ownWorkspaceID {
		t.Errorf("в проверку права ушла не роль из токена: %+v", checks)
	}

	w = doRequest(r, http.MethodGet, "/api/v1/pages/routes?workspace_id="+memberWorkspaceID, auth)
	if w.Code != http.StatusForbidden {
		t.Fatalf("токен на %s и workspace_id=%s -> %d, ожидался 403", ownWorkspaceID, memberWorkspaceID, w.Code)
	}
}

// runRemovedMemberWorkspaceToken: участник otherUserID держит токен
// пространства ownWorkspaceID; владелец testUserID (токен сессии) его
// исключает (revoke=true) или нет; через 10 минут участник идёт с тем же
// токеном.
func runRemovedMemberWorkspaceToken(t *testing.T, revoke bool) int {
	t.Helper()
	mr, rs := newTestRedis(t)
	stub := &membershipProxy{}
	r, signer := newRouterWithSigner(t, stub, rs)
	ownerPair, err := signer.GenerateTokensWithUsername(testUserID, "owner", "owner@example.com")
	if err != nil {
		t.Fatalf("sign owner token: %v", err)
	}
	memberAuth := map[string]string{"Authorization": "Bearer " + workspaceTokenFor(t, signer, otherUserID, ownWorkspaceID, wsaccess.RoleMember)}
	scoped := "/api/v1/pages/routes?workspace_id=" + ownWorkspaceID

	if w := doRequest(r, http.MethodGet, scoped, memberAuth); w.Code != http.StatusOK {
		t.Fatalf("до исключения -> %d (%s)", w.Code, w.Body.String())
	}
	if revoke {
		w := doRequest(r, http.MethodDelete, "/api/v1/workspaces/"+ownWorkspaceID+"/members/"+otherUserID,
			map[string]string{"Authorization": "Bearer " + ownerPair.AccessToken})
		if w.Code != http.StatusOK {
			t.Fatalf("DELETE участника -> %d (%s)", w.Code, w.Body.String())
		}
	}
	mr.FastForward(10 * time.Minute)
	return doRequest(r, http.MethodGet, scoped, memberAuth).Code
}

func TestRemovedMemberWorkspaceTokenIsRejected(t *testing.T) {
	if code := runRemovedMemberWorkspaceToken(t, true); code != http.StatusUnauthorized {
		t.Fatalf("токен исключённого участника через 10 минут -> %d, ожидался 401", code)
	}
}

func TestWorkspaceTokenLivesWithoutRemoval(t *testing.T) {
	if code := runRemovedMemberWorkspaceToken(t, false); code != http.StatusOK {
		t.Fatalf("контроль: без исключения токен через 10 минут -> %d, ожидался 200", code)
	}
}

// runWorkspaceTokenOnForeignWorkspaceDelete: владелец testUserID с токеном
// пространства W1 (ownWorkspaceID) удаляет W2 (memberWorkspaceID) — маршрут
// без скоупа в реестре. Возвращает код и дошёл ли DELETE W2 до collections.
func runWorkspaceTokenOnForeignWorkspaceDelete(t *testing.T, requireWorkspaceToken bool) (int, bool) {
	t.Helper()
	_, rs := newTestRedis(t)
	stub := &membershipProxy{}
	r, signer := newRouterWithSigner(t, stub, rs, withRequireWorkspaceToken(requireWorkspaceToken))
	auth := map[string]string{"Authorization": "Bearer " + workspaceTokenFor(t, signer, testUserID, ownWorkspaceID, wsaccess.RoleOwner)}

	w := doRequest(r, http.MethodDelete, "/api/v1/workspaces/"+memberWorkspaceID, auth)
	proxied := false
	for _, c := range stub.callsTo("collections") {
		if c.method == http.MethodDelete && c.path == "/api/v1/workspaces/"+memberWorkspaceID {
			proxied = true
		}
	}
	return w.Code, proxied
}

// SDL-613 S9 перевернул предел S4: с флагом SCOPE_REQUIRE_WORKSPACE_TOKEN
// токен пространства — граница и на маршрутах без скоупа. Токен W1 на
// DELETE /workspaces/W2 — 403, до collections запрос не доходит.
func TestWorkspaceTokenIsABoundaryOnUnscopedRoutes(t *testing.T) {
	code, proxied := runWorkspaceTokenOnForeignWorkspaceDelete(t, true)
	if code != http.StatusForbidden {
		t.Fatalf("флаг включён: токен W1 на DELETE /workspaces/W2 -> %d, ожидался 403", code)
	}
	if proxied {
		t.Fatalf("флаг включён: DELETE W2 дошёл до collections")
	}
}

// Контроль: флаг выключен — поведение до S9 (как на master и на проде, пока
// оверлей не включил флаг): токен W1 проходит на DELETE /workspaces/W2, решает
// collections по X-User-ID.
func TestWorkspaceTokenIsNotABoundaryWhenFlagOff(t *testing.T) {
	code, proxied := runWorkspaceTokenOnForeignWorkspaceDelete(t, false)
	if code != http.StatusOK {
		t.Fatalf("флаг выключен: токен W1 на DELETE /workspaces/W2 -> %d, ожидался 200 (поведение до S9)", code)
	}
	if !proxied {
		t.Fatalf("флаг выключен: DELETE W2 не дошёл до collections")
	}
}

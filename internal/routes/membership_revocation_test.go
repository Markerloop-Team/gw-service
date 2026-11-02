package routes_test

// SDL-615 S2: исключение участника кончает его доступ на следующем запросе.
// Настоящий роутер шлюза + miniredis: слой MembershipRevocation должен быть
// ПРИВЯЗАН к DELETE /workspaces/:id/members/:user_id и DELETE /workspaces/:id
// (unit-тесты в internal/middleware вешают его сами и привязку не докажут).
//
// Инварианты:
//   - после 2xx на DELETE участника роль в кэше снята, маркер стоит;
//   - после 2xx на DELETE пространства стоит маркер workspace_gone;
//   - UPPER-case UUID в пути настоящего роутера бьют по нижнерегистровым
//     ключам;
//   - сквозной: роль закэширована первым скоупленным запросом; после
//     исключения тот же запрос (collections уже без актора) — 403, и роль в
//     кэш не вернулась. Контроль: без исключения тот же сценарий отдаёт 200
//     из кэша — то есть 403 обеспечивает именно слой сброса.

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"

	sdkredis "gitlab.com/markerloop/go-sdk/pkg/redis"
)

const (
	// Ключи — как их пишет internal/middleware (scope.go / revocation.go).
	// Литералы намеренно: тест внешнего пакета сторожит и сам формат ключа,
	// который SDL-613 будет читать из другого места.
	roleKeyPrefix    = "workspace_role:"
	revokedKeyPrefix = "workspace_revoked:"
	goneKeyPrefix    = "workspace_gone:"
)

func newTestRedis(t *testing.T) (*miniredis.Miniredis, *sdkredis.RedisService) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return mr, sdkredis.NewRedisServiceWithClient(client, logger)
}

func TestMemberDeleteRouteRevokesCachedRole(t *testing.T) {
	mr, rs := newTestRedis(t)
	r, token := newRouterWithProxyAndRedis(t, &stubProxy{grantPermission: true}, rs)
	roleKey := roleKeyPrefix + otherUserID + ":" + ownWorkspaceID
	mr.Set(roleKey, "member")

	w := doRequest(r, http.MethodDelete, "/api/v1/workspaces/"+ownWorkspaceID+"/members/"+otherUserID,
		map[string]string{"Authorization": "Bearer " + token})
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE участника -> %d (%s)", w.Code, w.Body.String())
	}
	if mr.Exists(roleKey) {
		t.Errorf("роль %s осталась в кэше: слой сброса не привязан к маршруту", roleKey)
	}
	if !mr.Exists(revokedKeyPrefix + otherUserID + ":" + ownWorkspaceID) {
		t.Errorf("маркер исключения не поставлен; ключи: %v", mr.Keys())
	}
}

func TestWorkspaceDeleteRouteSetsGoneMarker(t *testing.T) {
	mr, rs := newTestRedis(t)
	r, token := newRouterWithProxyAndRedis(t, &stubProxy{grantPermission: true}, rs)
	w := doRequest(r, http.MethodDelete, "/api/v1/workspaces/"+ownWorkspaceID,
		map[string]string{"Authorization": "Bearer " + token})
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE пространства -> %d (%s)", w.Code, w.Body.String())
	}
	if !mr.Exists(goneKeyPrefix + ownWorkspaceID) {
		t.Errorf("маркер удаления пространства не поставлен; ключи: %v", mr.Keys())
	}
}

func TestMemberDeleteRouteUpperCaseIDsHitLowerCaseKeys(t *testing.T) {
	mr, rs := newTestRedis(t)
	r, token := newRouterWithProxyAndRedis(t, &stubProxy{grantPermission: true}, rs)
	roleKey := roleKeyPrefix + otherUserID + ":" + ownWorkspaceID
	mr.Set(roleKey, "member")

	w := doRequest(r, http.MethodDelete,
		"/api/v1/workspaces/"+strings.ToUpper(ownWorkspaceID)+"/members/"+strings.ToUpper(otherUserID),
		map[string]string{"Authorization": "Bearer " + token})
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE участника (UPPER) -> %d (%s)", w.Code, w.Body.String())
	}
	if mr.Exists(roleKey) {
		t.Errorf("роль %s осталась: DEL по UPPER-case пути промахнулся", roleKey)
	}
	if !mr.Exists(revokedKeyPrefix + otherUserID + ":" + ownWorkspaceID) {
		t.Errorf("маркер не под нижнерегистровым ключом; ключи: %v", mr.Keys())
	}
}

// Сквозной сценарий на настоящем роутере. revoke=true — участника
// исключают между запросами; revoke=false — контроль, что без исключения
// кэш отдаёт роль даже когда collections актора уже не видит.
func runMemberAccessAfterRemoval(t *testing.T, revoke bool) (code int, roleCached bool) {
	t.Helper()
	mr, rs := newTestRedis(t)
	stub := &membershipProxy{}
	r, token := newRouterWithProxyAndRedis(t, stub, rs)
	auth := map[string]string{"Authorization": "Bearer " + token}
	scoped := "/api/v1/pages/routes?workspace_id=" + memberWorkspaceID
	roleKey := roleKeyPrefix + testUserID + ":" + memberWorkspaceID

	if w := doRequest(r, http.MethodGet, scoped, auth); w.Code != http.StatusOK {
		t.Fatalf("первый скоупленный запрос -> %d (%s)", w.Code, w.Body.String())
	}
	if got, _ := mr.Get(roleKey); got != "member" {
		t.Fatalf("роль после первого запроса в кэше = %q, ожидалось member", got)
	}

	if revoke {
		if w := doRequest(r, http.MethodDelete, "/api/v1/workspaces/"+memberWorkspaceID+"/members/"+testUserID, auth); w.Code != http.StatusOK {
			t.Fatalf("DELETE участника -> %d (%s)", w.Code, w.Body.String())
		}
	}
	// Членство в collections уже снято.
	stub.mu.Lock()
	stub.actorAbsentFromMembers = true
	stub.mu.Unlock()

	w := doRequest(r, http.MethodGet, scoped, auth)
	return w.Code, mr.Exists(roleKey)
}

func TestRemovedMemberIsForbiddenOnNextRequest(t *testing.T) {
	code, cached := runMemberAccessAfterRemoval(t, true)
	if code != http.StatusForbidden {
		t.Fatalf("запрос исключённого участника -> %d, ожидался 403 на следующем же запросе", code)
	}
	if cached {
		t.Errorf("роль вернулась в кэш после исключения")
	}
}

func TestCachedRoleOutlivesRemovalWithoutRevocationLayer(t *testing.T) {
	code, cached := runMemberAccessAfterRemoval(t, false)
	if code != http.StatusOK || !cached {
		t.Fatalf("контроль: без исключения ожидался 200 из кэша и живая роль, получено %d / cached=%v", code, cached)
	}
}

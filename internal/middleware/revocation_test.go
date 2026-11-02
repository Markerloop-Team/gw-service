package middleware

// SDL-615 S2: сброс кэша роли после исключения участника / удаления
// пространства. Redis — miniredis через go-sdk NewRedisServiceWithClient,
// без сети и без окружения.
//
// Инварианты:
//   - 2xx на DELETE участника — роль из кэша удалена, маркер
//     workspace_revoked поставлен с TTL revocationMarkerTTL;
//   - 4xx/5xx — ни удаления, ни маркера;
//   - 2xx на DELETE пространства — маркер workspace_gone;
//   - UPPER-case UUID в пути бьют по тем же (нижнерегистровым) ключам, что
//     пишет ScopeMiddleware;
//   - гонка: роль, записанная в кэш ПОСЛЕ DEL при живом маркере, не
//     читается — resolveWorkspaceRole идёт вживую и в кэш не пишет;
//   - без маркеров кэш работает как раньше (контроль, что инвариант выше
//     держит именно маркер).

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"

	sdkredis "gitlab.com/markerloop/go-sdk/pkg/redis"
)

const (
	revokeTestUserID    = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	revokeTestWorkspace = "12345678-1234-4123-8123-123456789abc"
)

// newTestRedis — miniredis, обёрнутый в go-sdk RedisService.
func newTestRedis(t *testing.T) (*miniredis.Miniredis, *sdkredis.RedisService) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return mr, sdkredis.NewRedisServiceWithClient(client, logger)
}

// revocationConfig — конфиг слоя с miniredis и стабом collections.
func revocationConfig(rs *sdkredis.RedisService, p *collectionsProxy) PermissionMiddlewareConfig {
	cfg := scopeStubConfig(p)
	cfg.RedisService = rs
	return cfg
}

// newRevocationRouter — голый gin с теми же шаблонами маршрутов, что у
// шлюза, и обработчиком, отвечающим заданным статусом.
func newRevocationRouter(cfg PermissionMiddlewareConfig, upstreamStatus int) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	handler := func(c *gin.Context) { c.Status(upstreamStatus) }
	r.DELETE(memberDeleteRoutePattern, MembershipRevocation(cfg), handler)
	r.DELETE(workspaceDeleteRoutePattern, MembershipRevocation(cfg), handler)
	return r
}

func doDelete(r *gin.Engine, path string) int {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, path, nil))
	return w.Code
}

func TestMembershipRevocationMemberDelete2xxDropsRoleAndSetsMarker(t *testing.T) {
	mr, rs := newTestRedis(t)
	roleKey := workspaceRoleCacheKey(revokeTestUserID, revokeTestWorkspace)
	markerKey := workspaceRevokedMarkerKey(revokeTestUserID, revokeTestWorkspace)
	mr.Set(roleKey, "member")

	r := newRevocationRouter(revocationConfig(rs, &collectionsProxy{}), http.StatusNoContent)
	if code := doDelete(r, "/api/v1/workspaces/"+revokeTestWorkspace+"/members/"+revokeTestUserID); code != http.StatusNoContent {
		t.Fatalf("DELETE участника -> %d, ожидался 204 (слой не должен менять ответ)", code)
	}
	if mr.Exists(roleKey) {
		t.Errorf("роль %s осталась в кэше после исключения", roleKey)
	}
	if !mr.Exists(markerKey) {
		t.Fatalf("маркер %s не поставлен", markerKey)
	}
	if ttl := mr.TTL(markerKey); ttl != revocationMarkerTTL {
		t.Errorf("TTL маркера = %v, ожидался %v", ttl, revocationMarkerTTL)
	}
	if revocationMarkerTTL <= membershipCacheTTL {
		t.Errorf("revocationMarkerTTL (%v) обязан быть больше membershipCacheTTL (%v): иначе роль, записанная после DEL, переживёт маркер", revocationMarkerTTL, membershipCacheTTL)
	}
	if mr.Exists(workspaceGoneMarkerKey(revokeTestWorkspace)) {
		t.Errorf("исключение участника поставило маркер удаления пространства")
	}
}

func TestMembershipRevocationNon2xxLeavesCacheAlone(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		mr, rs := newTestRedis(t)
		roleKey := workspaceRoleCacheKey(revokeTestUserID, revokeTestWorkspace)
		mr.Set(roleKey, "member")

		r := newRevocationRouter(revocationConfig(rs, &collectionsProxy{}), status)
		doDelete(r, "/api/v1/workspaces/"+revokeTestWorkspace+"/members/"+revokeTestUserID)
		doDelete(r, "/api/v1/workspaces/"+revokeTestWorkspace)
		if !mr.Exists(roleKey) {
			t.Errorf("статус %d: роль удалена из кэша, хотя апстрим отказал", status)
		}
		if mr.Exists(workspaceRevokedMarkerKey(revokeTestUserID, revokeTestWorkspace)) {
			t.Errorf("статус %d: поставлен маркер исключения", status)
		}
		if mr.Exists(workspaceGoneMarkerKey(revokeTestWorkspace)) {
			t.Errorf("статус %d: поставлен маркер удаления пространства", status)
		}
	}
}

func TestMembershipRevocationWorkspaceDelete2xxSetsGoneMarker(t *testing.T) {
	mr, rs := newTestRedis(t)
	r := newRevocationRouter(revocationConfig(rs, &collectionsProxy{}), http.StatusOK)
	doDelete(r, "/api/v1/workspaces/"+revokeTestWorkspace)
	goneKey := workspaceGoneMarkerKey(revokeTestWorkspace)
	if !mr.Exists(goneKey) {
		t.Fatalf("маркер %s не поставлен", goneKey)
	}
	if ttl := mr.TTL(goneKey); ttl != revocationMarkerTTL {
		t.Errorf("TTL маркера = %v, ожидался %v", ttl, revocationMarkerTTL)
	}
}

// UPPER-case UUID в пути: ScopeMiddleware пишет ключ роли по
// strings.ToLower(id), значит DEL и маркеры обязаны бить по тем же ключам.
func TestMembershipRevocationUpperCaseIDsHitLowerCaseKeys(t *testing.T) {
	mr, rs := newTestRedis(t)
	roleKey := workspaceRoleCacheKey(revokeTestUserID, revokeTestWorkspace)
	mr.Set(roleKey, "owner")
	upperWS, upperUser := strings.ToUpper(revokeTestWorkspace), strings.ToUpper(revokeTestUserID)

	r := newRevocationRouter(revocationConfig(rs, &collectionsProxy{}), http.StatusOK)
	doDelete(r, "/api/v1/workspaces/"+upperWS+"/members/"+upperUser)
	if mr.Exists(roleKey) {
		t.Errorf("роль %s осталась в кэше: DEL по UPPER-case id промахнулся", roleKey)
	}
	if !mr.Exists(workspaceRevokedMarkerKey(revokeTestUserID, revokeTestWorkspace)) {
		t.Errorf("маркер исключения не лёг под нижнерегистровый ключ; ключи: %v", mr.Keys())
	}
	doDelete(r, "/api/v1/workspaces/"+upperWS)
	if !mr.Exists(workspaceGoneMarkerKey(revokeTestWorkspace)) {
		t.Errorf("маркер удаления не лёг под нижнерегистровый ключ; ключи: %v", mr.Keys())
	}
	for _, k := range mr.Keys() {
		if k != strings.ToLower(k) {
			t.Errorf("ключ %q содержит верхний регистр", k)
		}
	}
}

// user_id из токена может прийти в верхнем регистре: ключ роли и маркер
// обязаны лечь под тот же нижнерегистровый ключ, что DEL из MembershipRevocation.
func TestUpperCaseTokenUserIDHitsLowerCaseRoleKeyAndMarker(t *testing.T) {
	mr, rs := newTestRedis(t)
	upperUser, upperWS := strings.ToUpper(revokeTestUserID), strings.ToUpper(revokeTestWorkspace)
	roleKey := workspaceRoleCachePrefix + revokeTestUserID + ":" + revokeTestWorkspace

	stub := &collectionsProxy{status: http.StatusOK, body: membersBody(`{"user_id":"` + revokeTestUserID + `","role":"member"}`)}
	if role, err := resolveWorkspaceRole(revocationConfig(rs, stub), upperUser, upperWS); err != nil || role != "member" {
		t.Fatalf("resolveWorkspaceRole(UPPER) = (%q, %v)", role, err)
	}
	if got, _ := mr.Get(roleKey); got != "member" {
		t.Fatalf("роль по UPPER user_id легла не под %s; ключи: %v", roleKey, mr.Keys())
	}

	// Исключение по нижнерегистровому пути должно попасть в тот же ключ.
	r := newRevocationRouter(revocationConfig(rs, &collectionsProxy{}), http.StatusOK)
	doDelete(r, "/api/v1/workspaces/"+revokeTestWorkspace+"/members/"+revokeTestUserID)
	if mr.Exists(roleKey) {
		t.Errorf("роль, записанная по UPPER user_id, пережила исключение")
	}
	// И наоборот: маркер, поставленный по нижнему регистру, виден резолву с UPPER.
	stub = &collectionsProxy{status: http.StatusNotFound, body: `{}`}
	if role, _ := resolveWorkspaceRole(revocationConfig(rs, stub), upperUser, upperWS); role != "" || stub.path == "" {
		t.Errorf("резолв с UPPER id не увидел маркер: role=%q, collections спрошен=%v", role, stub.path != "")
	}
	for _, k := range mr.Keys() {
		if k != strings.ToLower(k) {
			t.Errorf("ключ %q содержит верхний регистр", k)
		}
	}
}

// membersBody — ответ collections со списком участников.
func membersBody(members ...string) string {
	return `{"success":true,"data":[` + strings.Join(members, ",") + `]}`
}

// Гонка: маркер стоит, а роль вернулась в кэш (запрос исключённого, начатый
// до удаления, дописал её после DEL). Следующий resolveWorkspaceRole обязан
// не поверить кэшу — спросить collections — и не положить роль обратно.
func TestResolveWorkspaceRoleGoesLiveWhileRevokedMarkerLives(t *testing.T) {
	mr, rs := newTestRedis(t)
	roleKey := workspaceRoleCacheKey(revokeTestUserID, revokeTestWorkspace)
	mr.Set(workspaceRevokedMarkerKey(revokeTestUserID, revokeTestWorkspace), "1")
	mr.Set(roleKey, "member") // stale: записана после DEL

	// collections: актора в списке больше нет.
	stub := &collectionsProxy{status: http.StatusOK, body: membersBody(`{"user_id":"99999999-8888-7777-6666-555555555555","role":"owner"}`)}
	role, err := resolveWorkspaceRole(revocationConfig(rs, stub), revokeTestUserID, revokeTestWorkspace)
	if err != nil || role != "" {
		t.Fatalf("resolveWorkspaceRole = (%q, %v), ожидалась пустая роль: кэшу при маркере верить нельзя", role, err)
	}
	if stub.path != "/api/v1/workspaces/"+revokeTestWorkspace+"/members" {
		t.Fatalf("collections не спрошен (path=%q): роль взята из кэша", stub.path)
	}

	// Роль ещё есть в collections (удаление не докатилось) — вернуть её
	// можно, но в кэш класть нельзя.
	mr.Del(roleKey)
	stub = &collectionsProxy{status: http.StatusOK, body: membersBody(`{"user_id":"` + revokeTestUserID + `","role":"member"}`)}
	role, err = resolveWorkspaceRole(revocationConfig(rs, stub), revokeTestUserID, revokeTestWorkspace)
	if err != nil || role != "member" {
		t.Fatalf("resolveWorkspaceRole = (%q, %v), ожидалось member вживую", role, err)
	}
	if mr.Exists(roleKey) {
		t.Errorf("роль записана в кэш при живом маркере исключения")
	}
}

func TestResolveWorkspaceRoleGoesLiveWhileWorkspaceGoneMarkerLives(t *testing.T) {
	mr, rs := newTestRedis(t)
	roleKey := workspaceRoleCacheKey(revokeTestUserID, revokeTestWorkspace)
	mr.Set(workspaceGoneMarkerKey(revokeTestWorkspace), "1")
	mr.Set(roleKey, "owner")

	stub := &collectionsProxy{status: http.StatusNotFound, body: `{}`}
	role, err := resolveWorkspaceRole(revocationConfig(rs, stub), revokeTestUserID, revokeTestWorkspace)
	if err != nil || role != "" {
		t.Fatalf("resolveWorkspaceRole = (%q, %v), ожидалась пустая роль: пространство удалено", role, err)
	}
	if stub.path == "" {
		t.Fatalf("collections не спрошен: роль взята из кэша при маркере удаления пространства")
	}
}

// Контроль: без маркеров кэш читается и пополняется как до S2 — иначе
// тесты выше проходили бы и при выключенном кэше вовсе.
func TestResolveWorkspaceRoleTrustsCacheWithoutMarkers(t *testing.T) {
	mr, rs := newTestRedis(t)
	roleKey := workspaceRoleCacheKey(revokeTestUserID, revokeTestWorkspace)
	mr.Set(roleKey, "member")

	stub := &collectionsProxy{status: http.StatusNotFound, body: `{}`}
	role, err := resolveWorkspaceRole(revocationConfig(rs, stub), revokeTestUserID, revokeTestWorkspace)
	if err != nil || role != "member" {
		t.Fatalf("resolveWorkspaceRole = (%q, %v), ожидалось member из кэша", role, err)
	}
	if stub.path != "" {
		t.Fatalf("collections спрошен при валидном кэше без маркеров")
	}

	mr.Del(roleKey)
	stub = &collectionsProxy{status: http.StatusOK, body: membersBody(`{"user_id":"` + revokeTestUserID + `","role":"owner"}`)}
	if role, err = resolveWorkspaceRole(revocationConfig(rs, stub), revokeTestUserID, revokeTestWorkspace); err != nil || role != "owner" {
		t.Fatalf("resolveWorkspaceRole = (%q, %v), ожидалось owner вживую", role, err)
	}
	if got, _ := rs.Get(context.Background(), roleKey); got != "owner" {
		t.Errorf("роль не записана в кэш без маркеров: %q", got)
	}
	if ttl := mr.TTL(roleKey); ttl != membershipCacheTTL {
		t.Errorf("TTL роли = %v, ожидался %v", ttl, membershipCacheTTL)
	}
}

// Маркер живёт дольше роли: после истечения membershipCacheTTL маркер ещё
// стоит, после revocationMarkerTTL — снят, и кэш снова доверенный.
func TestRevocationMarkerOutlivesRoleCache(t *testing.T) {
	mr, rs := newTestRedis(t)
	r := newRevocationRouter(revocationConfig(rs, &collectionsProxy{}), http.StatusOK)
	doDelete(r, "/api/v1/workspaces/"+revokeTestWorkspace+"/members/"+revokeTestUserID)

	cfg := revocationConfig(rs, &collectionsProxy{})
	mr.FastForward(membershipCacheTTL + time.Second)
	if roleCacheTrusted(context.Background(), cfg, revokeTestUserID, revokeTestWorkspace) {
		t.Fatalf("через %v маркер уже снят — роль, записанная после DEL, дожила бы до чтения", membershipCacheTTL)
	}
	mr.FastForward(revocationMarkerTTL - membershipCacheTTL)
	if !roleCacheTrusted(context.Background(), cfg, revokeTestUserID, revokeTestWorkspace) {
		t.Fatalf("через %v маркер всё ещё стоит", revocationMarkerTTL+time.Second)
	}
}

// Без Redis слой и резолв — no-op, как и кэш роли до S2.
func TestMembershipRevocationWithoutRedisIsNoop(t *testing.T) {
	stub := &collectionsProxy{status: http.StatusOK, body: membersBody(`{"user_id":"` + revokeTestUserID + `","role":"owner"}`)}
	cfg := scopeStubConfig(stub)
	r := newRevocationRouter(cfg, http.StatusOK)
	if code := doDelete(r, "/api/v1/workspaces/"+revokeTestWorkspace+"/members/"+revokeTestUserID); code != http.StatusOK {
		t.Fatalf("DELETE без Redis -> %d", code)
	}
	if role, err := resolveWorkspaceRole(cfg, revokeTestUserID, revokeTestWorkspace); err != nil || role != "owner" {
		t.Fatalf("resolveWorkspaceRole без Redis = (%q, %v)", role, err)
	}
}

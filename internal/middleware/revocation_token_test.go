package middleware

// SDL-613 S4: двойная отметка отзыва токенов пространства на DELETE
// участника / пространства.
//
// Инварианты:
//   - владелец удаляет участника — отметка wsrev:v1 стоит УЖЕ в момент,
//     когда апстрим обрабатывает удаление, значение — unix-время, TTL —
//     wsaccess.RevocationTTL;
//   - после 2xx отметка поставлена заново (снятую в обработчике — вернули);
//   - запись отметки до удаления упала — 503, удаление не проксировано;
//   - актор, которого шлюз не считает владельцем, первой отметки не ставит
//     (иначе любой гасил бы чужие токены), вторая — только после 2xx;
//   - удаление пространства — wsgone:v1 до и после.

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"gitlab.com/markerloop/go-sdk/pkg/wsaccess"
)

const revokeTestOwnerID = "0a0a0a0a-0b0b-4c0c-8d0d-0e0e0e0e0e0e"

// newTokenRevocationRouter — DELETE-маршруты шлюза с актором actorID в
// контексте; upstream — обработчик вместо collections.
func newTokenRevocationRouter(cfg PermissionMiddlewareConfig, actorID string, upstream gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	actor := func(c *gin.Context) { c.Set("user_id", actorID) }
	r.DELETE(memberDeleteRoutePattern, actor, MembershipRevocation(cfg), upstream)
	r.DELETE(workspaceDeleteRoutePattern, actor, MembershipRevocation(cfg), upstream)
	return r
}

// ownerMembers — collections: revokeTestOwnerID владелец revokeTestWorkspace.
func ownerMembers() *collectionsProxy {
	return &collectionsProxy{status: http.StatusOK, body: membersBody(
		`{"user_id":"`+revokeTestOwnerID+`","role":"owner"}`,
		`{"user_id":"`+revokeTestUserID+`","role":"member"}`)}
}

func TestMemberDeleteMarksTokenRevocationBeforeAndAfter(t *testing.T) {
	mr, rs := newTestRedis(t)
	revKey := wsaccess.RevokedKeyPrefix + revokeTestUserID + ":" + revokeTestWorkspace
	var seenDuringDelete string
	upstream := func(c *gin.Context) {
		seenDuringDelete, _ = mr.Get(revKey)
		mr.Del(revKey) // вторая отметка обязана вернуть ключ
		c.Status(http.StatusNoContent)
	}
	before := time.Now().Unix()
	r := newTokenRevocationRouter(revocationConfig(rs, ownerMembers()), revokeTestOwnerID, upstream)
	if code := doDelete(r, "/api/v1/workspaces/"+revokeTestWorkspace+"/members/"+revokeTestUserID); code != http.StatusNoContent {
		t.Fatalf("DELETE -> %d", code)
	}
	if seenDuringDelete == "" {
		t.Fatalf("отметки %s не было, пока апстрим удалял участника", revKey)
	}
	if n, err := strconv.ParseInt(seenDuringDelete, 10, 64); err != nil || n < before {
		t.Errorf("значение отметки %q — не unix-время отзыва", seenDuringDelete)
	}
	if !mr.Exists(revKey) {
		t.Fatalf("после 2xx отметка не поставлена заново")
	}
	if ttl := mr.TTL(revKey); ttl != wsaccess.RevocationTTL {
		t.Errorf("TTL отметки = %v, ожидался %v", ttl, wsaccess.RevocationTTL)
	}
	// Старый путь жив: маркер "1" и сброс кэша роли — как до S4.
	if !mr.Exists(workspaceRevokedMarkerKey(revokeTestUserID, revokeTestWorkspace)) {
		t.Errorf("старый маркер workspace_revoked не поставлен")
	}
}

func TestMemberDeletePreMarkFailureIs503AndNotProxied(t *testing.T) {
	mr, rs := newTestRedis(t)
	proxied := false
	upstream := func(c *gin.Context) { proxied = true; c.Status(http.StatusNoContent) }
	r := newTokenRevocationRouter(revocationConfig(rs, ownerMembers()), revokeTestOwnerID, upstream)
	mr.Close() // Redis лёг: отметку не записать

	for _, path := range []string{
		"/api/v1/workspaces/" + revokeTestWorkspace + "/members/" + revokeTestUserID,
		"/api/v1/workspaces/" + revokeTestWorkspace,
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, path, nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s -> %d, ожидался 503", path, w.Code)
		}
		if proxied {
			t.Fatalf("%s: удаление проксировано, хотя отметка отзыва не записана", path)
		}
	}
}

func TestNonOwnerDeleteDoesNotPreMark(t *testing.T) {
	mr, rs := newTestRedis(t)
	revKey := wsaccess.RevokedKeyPrefix + revokeTestOwnerID + ":" + revokeTestWorkspace
	goneKey := wsaccess.GoneKeyPrefix + revokeTestWorkspace
	upstream := func(c *gin.Context) {
		if mr.Exists(revKey) || mr.Exists(goneKey) {
			t.Errorf("не-владелец поставил отметку до удаления; ключи: %v", mr.Keys())
		}
		c.Status(http.StatusForbidden) // collections отказал
	}
	// revokeTestUserID — member, пытается исключить владельца и удалить пространство.
	r := newTokenRevocationRouter(revocationConfig(rs, ownerMembers()), revokeTestUserID, upstream)
	doDelete(r, "/api/v1/workspaces/"+revokeTestWorkspace+"/members/"+revokeTestOwnerID)
	doDelete(r, "/api/v1/workspaces/"+revokeTestWorkspace)
	if mr.Exists(revKey) || mr.Exists(goneKey) {
		t.Errorf("отметка осталась после отказа апстрима; ключи: %v", mr.Keys())
	}
}

// Участник уходит сам — отметку до удаления ставит без вопроса к collections.
func TestSelfLeavePreMarks(t *testing.T) {
	mr, rs := newTestRedis(t)
	revKey := wsaccess.RevokedKeyPrefix + revokeTestUserID + ":" + revokeTestWorkspace
	stub := &collectionsProxy{status: http.StatusNotFound, body: `{}`}
	upstream := func(c *gin.Context) {
		if !mr.Exists(revKey) {
			t.Errorf("отметки нет во время удаления")
		}
		c.Status(http.StatusNoContent)
	}
	r := newTokenRevocationRouter(revocationConfig(rs, stub), revokeTestUserID, upstream)
	doDelete(r, "/api/v1/workspaces/"+revokeTestWorkspace+"/members/"+revokeTestUserID)
	if stub.path != "" {
		t.Errorf("collections спрошен при уходе самого участника: %s", stub.path)
	}
}

func TestWorkspaceDeleteMarksGoneBeforeAndAfter(t *testing.T) {
	mr, rs := newTestRedis(t)
	goneKey := wsaccess.GoneKeyPrefix + revokeTestWorkspace
	var during bool
	upstream := func(c *gin.Context) {
		during = mr.Exists(goneKey)
		mr.Del(goneKey)
		c.Status(http.StatusOK)
	}
	r := newTokenRevocationRouter(revocationConfig(rs, ownerMembers()), revokeTestOwnerID, upstream)
	doDelete(r, "/api/v1/workspaces/"+revokeTestWorkspace)
	if !during {
		t.Errorf("отметки wsgone не было во время удаления пространства")
	}
	if !mr.Exists(goneKey) || mr.TTL(goneKey) != wsaccess.RevocationTTL {
		t.Errorf("после 2xx отметка wsgone не поставлена с TTL %v; ключи: %v", wsaccess.RevocationTTL, mr.Keys())
	}
}

// Неканонический id на DELETE — 400 до проксирования, с Redis и без: под
// таким id отметку отзыва не поставить, а collections удаление принял бы.
func TestDeleteWithNonCanonicalIDIs400NotProxied(t *testing.T) {
	noDash := strings.ReplaceAll(revokeTestWorkspace, "-", "")
	for _, withRedis := range []bool{true, false} {
		_, rs := newTestRedis(t)
		cfg := revocationConfig(rs, ownerMembers())
		if !withRedis {
			cfg.RedisService = nil
		}
		proxied := false
		r := newTokenRevocationRouter(cfg, revokeTestOwnerID, func(c *gin.Context) { proxied = true; c.Status(http.StatusNoContent) })
		for _, path := range []string{
			"/api/v1/workspaces/" + noDash,
			"/api/v1/workspaces/%7B" + revokeTestWorkspace + "%7D",
			"/api/v1/workspaces/urn:uuid:" + revokeTestWorkspace,
			"/api/v1/workspaces/" + noDash + "/members/" + revokeTestUserID,
			"/api/v1/workspaces/" + revokeTestWorkspace + "/members/" + strings.ReplaceAll(revokeTestUserID, "-", ""),
		} {
			if code := doDelete(r, path); code != http.StatusBadRequest {
				t.Errorf("redis=%v %s -> %d, ожидался 400", withRedis, path, code)
			}
		}
		if proxied {
			t.Errorf("redis=%v: неканонический id проксирован в collections", withRedis)
		}
	}
}

// Сетевая ошибка collections при проверке права на первую отметку — 503,
// удаление не проксируется.
func TestPreMarkRoleLookupFailureIs503(t *testing.T) {
	_, rs := newTestRedis(t)
	proxied := false
	stub := &collectionsProxy{err: errors.New("collections недоступен")}
	r := newTokenRevocationRouter(revocationConfig(rs, stub), revokeTestOwnerID, func(c *gin.Context) { proxied = true; c.Status(http.StatusNoContent) })
	for _, path := range []string{
		"/api/v1/workspaces/" + revokeTestWorkspace + "/members/" + revokeTestUserID,
		"/api/v1/workspaces/" + revokeTestWorkspace,
	} {
		if code := doDelete(r, path); code != http.StatusServiceUnavailable {
			t.Errorf("%s -> %d, ожидался 503", path, code)
		}
	}
	if proxied {
		t.Fatalf("удаление проксировано, хотя право на отметку не проверено")
	}
}

// Сбой второй отметки (после 2xx) — только лог: удаление уже состоялось,
// ответ апстрима клиенту не меняется.
func TestPostMarkFailureIsLoggedAndResponseStays2xx(t *testing.T) {
	mr, rs := newTestRedis(t)
	cfg := revocationConfig(rs, ownerMembers())
	var logs bytes.Buffer
	cfg.Logger.SetOutput(&logs)
	upstream := func(c *gin.Context) {
		mr.Close() // Redis лёг между первой и второй отметкой
		c.Status(http.StatusNoContent)
	}
	r := newTokenRevocationRouter(cfg, revokeTestOwnerID, upstream)
	if code := doDelete(r, "/api/v1/workspaces/"+revokeTestWorkspace+"/members/"+revokeTestUserID); code != http.StatusNoContent {
		t.Fatalf("DELETE -> %d, ожидался 204 апстрима", code)
	}
	if !strings.Contains(logs.String(), "отметку отзыва после удаления") {
		t.Errorf("сбой второй отметки не залогирован: %q", logs.String())
	}
}

package middleware

// SDL-615 S2: исключение участника из пространства должно кончать его доступ
// на СЛЕДУЮЩЕМ запросе, а не через membershipCacheTTL. Роль актора в
// пространстве шлюз кэширует в Redis (scope.go); collections-service, где
// живёт workspace_members, о кэше шлюза не знает и сбросить его не может.
// Поэтому сброс делает сам шлюз — ПОСЛЕ успешного проксирования удаления:
//
//   - DELETE /api/v1/workspaces/:id/members/:user_id, 2xx → DEL роли этого
//     пользователя в этом пространстве + маркер workspace_revoked;
//   - DELETE /api/v1/workspaces/:id, 2xx → маркер workspace_gone.
//
// Одного DEL мало: запрос исключаемого, начатый до удаления, может положить
// роль обратно уже после DEL. Маркер живёт revocationMarkerTTL (70 с) —
// дольше роли (60 с) — и пока он жив, resolveWorkspaceRole кэш не читает и
// не пишет (см. roleCacheTrusted). Не-2xx апстрима — ничего не делаем:
// членство не изменилось, и сбрасывать нечего.
//
// SDL-613 S4: токен пространства несёт роль сам и живёт до 15 минут, поэтому
// на тех же двух DELETE шлюз ставит отметку отзыва wsaccess (wsrev:v1 /
// wsgone:v1, значение — время отзыва, TTL wsaccess.RevocationTTL) ДВАЖДЫ:
//
//   - ДО проксирования: с этой секунды токены, выпущенные раньше, гашены.
//     Не записалась — 503, удаление не проксируется: удалить членство и не
//     погасить токен значит оставить исключённому доступ до 15 минут;
//   - ПОСЛЕ 2xx: обмен, прочитавший членство до коммита удаления, мог
//     выпустить токен уже после первой отметки — вторая, свежее, гасит и его.
//     Сбой здесь только в лог: удаление уже состоялось.
//
// Первую отметку ставит только тот, кто по мнению шлюза вправе удалять:
// владелец пространства или (для участника) сам исключаемый. Иначе любой
// вошедший, дёргая DELETE на чужой id, раз за разом гасил бы все токены
// пространства. Вторая отметка — после 2xx от collections, он и есть судья.

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"gitlab.com/markerloop/go-sdk/pkg/response"
	"gitlab.com/markerloop/go-sdk/pkg/wsaccess"
)

const (
	// memberDeleteRoutePattern / workspaceDeleteRoutePattern — Gin-шаблоны
	// маршрутов шлюза, после которых сбрасывается кэш. Сверяются с
	// c.FullPath(): шаблон, а не путь, поэтому регистр и форма id не
	// влияют на совпадение.
	memberDeleteRoutePattern    = "/api/v1/workspaces/:id/members/:user_id"
	workspaceDeleteRoutePattern = "/api/v1/workspaces/:id"
)

// revocationTarget — что гасит удаление: участника (userID непуст) или всё
// пространство.
type revocationTarget struct {
	workspaceID string
	userID      string
}

// markTokenRevocation ставит отметку отзыва токенов пространства.
func markTokenRevocation(ctx context.Context, store *wsaccess.Store, t revocationTarget) error {
	if t.userID != "" {
		return store.MarkRevoked(ctx, t.userID, t.workspaceID)
	}
	return store.MarkGone(ctx, t.workspaceID)
}

// mayPreMark — вправе ли актор, по мнению шлюза, удалить цель: владелец
// пространства, либо сам исключаемый. tokenRole — роль из токена
// пространства, уже сверенного WorkspaceTokenBoundary на это пространство
// (SDL-613 S9); пусто — роль тем же путём, что у скоупа для токена сессии
// (кэш + живой collections).
func mayPreMark(cfg PermissionMiddlewareConfig, actorID string, t revocationTarget, tokenRole string) (bool, error) {
	if actorID == "" {
		return false, nil
	}
	if t.userID != "" && strings.EqualFold(actorID, t.userID) {
		return true, nil
	}
	if tokenRole != "" {
		return tokenRole == string(wsaccess.RoleOwner), nil
	}
	role, err := resolveWorkspaceRole(cfg, actorID, t.workspaceID)
	if err != nil {
		return false, err
	}
	return role == string(wsaccess.RoleOwner), nil
}

// canonicalTarget — id цели DELETE в канонической форме UUID (регистр не
// важен: CanonicalID приводит к нижнему). На member-маршруте — оба id.
func canonicalTarget(fullPath string, t revocationTarget) bool {
	if _, err := wsaccess.CanonicalID(t.workspaceID); err != nil {
		return false
	}
	if fullPath == memberDeleteRoutePattern {
		if _, err := wsaccess.CanonicalID(t.userID); err != nil {
			return false
		}
	}
	return true
}

// MembershipRevocation — middleware для маршрутов удаления участника и
// пространства. Без Redis — no-op, как и кэш роли: без Redis и токен
// пространства проверяется у живого collections (wstoken.go).
func MembershipRevocation(cfg PermissionMiddlewareConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodDelete {
			c.Next()
			return
		}
		target := revocationTarget{workspaceID: c.Param("id")}
		if c.FullPath() == memberDeleteRoutePattern {
			target.userID = c.Param("user_id")
		}
		// Неканонический id — 400 до проксирования. collections принимает и
		// 32 hex без дефисов, и {…}, и urn:uuid:, а отметку отзыва под таким
		// id не поставить: удаление прошло бы, а токен исключённого — нет.
		if !canonicalTarget(c.FullPath(), target) {
			response.BadRequest(c, "Идентификатор должен быть UUID в канонической форме")
			c.Abort()
			return
		}
		if cfg.RedisService == nil {
			c.Next()
			return
		}
		ctx := context.Background()
		store := wsaccess.NewStore(cfg.RedisService)

		// Отметка ДО удаления.
		preMarked := false
		actorID, _ := c.Get("user_id")
		actor, _ := actorID.(string)
		allowed, err := mayPreMark(cfg, actor, target, workspaceTokenRoleFor(c, target.workspaceID))
		if err != nil {
			cfg.Logger.Errorf("Не удалось проверить право на удаление workspace=%s user=%s: %v", target.workspaceID, target.userID, err)
			response.Error(c, http.StatusServiceUnavailable, "Не удалось проверить доступ, повторите позже", "SERVICE_UNAVAILABLE")
			c.Abort()
			return
		}
		if allowed {
			if err := markTokenRevocation(ctx, store, target); err != nil {
				cfg.Logger.Errorf("Не удалось поставить отметку отзыва до удаления workspace=%s user=%s: %v", target.workspaceID, target.userID, err)
				response.Error(c, http.StatusServiceUnavailable, "Не удалось отозвать доступ, удаление не выполнено", "SERVICE_UNAVAILABLE")
				c.Abort()
				return
			}
			preMarked = true
		}

		c.Next()

		status := c.Writer.Status()
		if status < 200 || status > 299 {
			return
		}
		// Регистр id нормализуют сами построители ключей (scope.go:
		// workspaceRoleCacheKey и маркеры) — одно место на оба слоя, иначе
		// DEL по UPPER-case id промахнулся бы мимо ключа роли.
		workspaceID := target.workspaceID
		if workspaceID == "" {
			return
		}
		// Отметка ПОСЛЕ 2xx — для токена, выпущенного между первой отметкой
		// и коммитом удаления (и для удаления, которое шлюз первой отметкой
		// не счёл вправе).
		if err := markTokenRevocation(ctx, store, target); err != nil {
			cfg.Logger.Errorf("Не удалось поставить отметку отзыва после удаления workspace=%s user=%s (до удаления: %v): %v", workspaceID, target.userID, preMarked, err)
		}
		switch c.FullPath() {
		case memberDeleteRoutePattern:
			userID := target.userID
			if userID == "" {
				return
			}
			// Сбой здесь — событие безопасности: исключённый сохраняет
			// доступ до membershipCacheTTL. Поэтому Error, с обоими id.
			if err := cfg.RedisService.Set(ctx, workspaceRevokedMarkerKey(userID, workspaceID), "1", revocationMarkerTTL); err != nil {
				cfg.Logger.Errorf("Не удалось поставить маркер исключения user=%s workspace=%s: %v", userID, workspaceID, err)
			}
			if err := cfg.RedisService.Del(ctx, workspaceRoleCacheKey(userID, workspaceID)); err != nil {
				cfg.Logger.Errorf("Не удалось сбросить кэш роли user=%s workspace=%s: %v", userID, workspaceID, err)
			}
		case workspaceDeleteRoutePattern:
			if err := cfg.RedisService.Set(ctx, workspaceGoneMarkerKey(workspaceID), "1", revocationMarkerTTL); err != nil {
				cfg.Logger.Errorf("Не удалось поставить маркер удаления пространства workspace=%s: %v", workspaceID, err)
			}
		}
	}
}

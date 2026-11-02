package config

import "regexp"

// RouteConfig представляет конфигурацию маршрута с требуемым разрешением
type RouteConfig struct {
	Method     string // HTTP метод (GET, POST, PUT, DELETE)
	Path       string // Путь маршрута (может содержать плейсхолдеры :id, :email и т.д.)
	Permission string // Код разрешения (например, "users:read:all")
	Required   bool   // true = обязательно проверять, false = опционально

	// Скоуп объекта (SDL-587, EP-121). Пустой ScopeParam — маршрут вне
	// скоупа, ScopeMiddleware его пропускает. Непустой — шлюз сверяет, что
	// актор причастен к названному пространству, и инжектит вниз
	// X-Scope-Workspace-ID. Права (Permission) отвечают на «можно ли дёргать
	// маршрут», скоуп — на «твой ли объект».
	ScopeParam  string    // имя параметра с UUID пространства
	ScopeKind   ScopeKind // род объекта: единственный род — ScopeWorkspace
	ScopeInBody bool      // true — поле JSON-тела, false — параметр строки запроса
	// ScopeOwnerOnly (SDL-617 G2) — причастности мало, нужна роль owner в
	// пространстве. Файлы объявлены с ним, потому что до G2 их пускала
	// проверка «владелец проекта», а владелец проекта — это
	// workspaces.owner_user_id; открыть файлы участникам — отдельное
	// продуктовое решение, не этот флаг.
	ScopeOwnerOnly bool
}

// ScopeKind — род объекта, к которому проверяется причастность актора.
//
// SDL-620: род один — пространство. Проектный род (ScopeProject) снят вместе
// с группой /api/v1/projects: после SDL-617b проект не самостоятельная
// сущность («workspace = проект»), collections-service такие пути не
// обслуживает, и шлюз к /projects/:id не ходит. Запись с любым другим
// родом — красная в TestScopeDeclarationsAreConsistent, а ScopeMiddleware
// на ней отвечает 500, не пропуск.
type ScopeKind string

const (
	ScopeWorkspace ScopeKind = "workspace"
)

// placeholderRe matches any ":name" segment in a URL pattern.
var placeholderRe = regexp.MustCompile(`:[A-Za-z_][A-Za-z0-9_]*`)

// normalizeConfigPath приводит имена плейсхолдеров к тем, что генерирует
// middleware.normalizePath (:id / :email / :username / :param).
// Любое другое имя (:user_id, :role_id, ...) трактуется как :id —
// нормализатор запроса превращает UUID в :id вне зависимости от того,
// как параметр назван в Gin-роуте.
func normalizeConfigPath(path string) string {
	return placeholderRe.ReplaceAllStringFunc(path, func(m string) string {
		switch m {
		case ":id", ":email", ":username", ":param":
			return m
		default:
			return ":id"
		}
	})
}

// GetRouteConfigs возвращает конфигурацию всех защищенных маршрутов
func GetRouteConfigs() []RouteConfig {
	return []RouteConfig{
		// Users маршруты
		{Method: "GET", Path: "/api/v1/users", Permission: "users:read:all", Required: true},
		{Method: "POST", Path: "/api/v1/users", Permission: "users:create", Required: true},
		{Method: "GET", Path: "/api/v1/users/:id", Permission: "users:read:one", Required: true},
		{Method: "PUT", Path: "/api/v1/users/:id", Permission: "users:update:one", Required: true},
		{Method: "DELETE", Path: "/api/v1/users/:id", Permission: "users:delete", Required: true},
		{Method: "GET", Path: "/api/v1/users/email/:email", Permission: "users:read:by_email", Required: true},
		{Method: "GET", Path: "/api/v1/users/username/:username", Permission: "users:read:one", Required: true},
		{Method: "GET", Path: "/api/v1/users/my", Permission: "users:read:own", Required: true},
		{Method: "PUT", Path: "/api/v1/users/my", Permission: "users:update:own", Required: true},
		// SDL-742: самоудаление аккаунта. Запись, поэтому ":own" не замыкается
		// (замыкание — только GET): право users:delete:own проверяет
		// user-service, у роли user оно есть. Без этой записи DELETE /users/my
		// совпал бы с DELETE /users/:id (users:delete, право администратора).
		{Method: "DELETE", Path: "/api/v1/users/my", Permission: "users:delete:own", Required: true},
		// Журнал принятий правил (SDL-752). Своё — как GET /users/my: код с
		// ":own" и GET на сегменте "my" замыкаются в permission middleware без
		// похода в user-service (читать свои принятия можно и без ролей).
		// Чужое — только право администратора: у user-service на этой ручке
		// своей проверки прав НЕТ, шлюз — единственная защита.
		{Method: "GET", Path: "/api/v1/users/my/policy-acceptances", Permission: "users:read:own", Required: true},
		{Method: "GET", Path: "/api/v1/users/:id/policy-acceptances", Permission: "users:read:policy_acceptances", Required: true},
		// Журнал принятий поперёк людей и сводка по редакциям (SDL-752, экран
		// Policy acceptances админки) — то же право администратора; своей
		// проверки у user-service нет и здесь.
		{Method: "GET", Path: "/api/v1/policy-acceptances", Permission: "users:read:policy_acceptances", Required: true},
		{Method: "GET", Path: "/api/v1/policy-acceptances/summary", Permission: "users:read:policy_acceptances", Required: true},
		// User roles маршруты
		{Method: "GET", Path: "/api/v1/users/:id/roles", Permission: "users:read:roles", Required: true},
		{Method: "POST", Path: "/api/v1/users/:id/roles", Permission: "users:assign:role", Required: true},
		{Method: "DELETE", Path: "/api/v1/users/:id/roles/:role_id", Permission: "users:remove:role", Required: true},
		{Method: "GET", Path: "/api/v1/users/:id/permissions", Permission: "users:read:permissions", Required: true},

		// Roles маршруты
		{Method: "GET", Path: "/api/v1/roles", Permission: "roles:read:all", Required: true},
		{Method: "POST", Path: "/api/v1/roles", Permission: "roles:create", Required: true},
		{Method: "GET", Path: "/api/v1/roles/:id", Permission: "roles:read:one", Required: true},
		{Method: "PUT", Path: "/api/v1/roles/:id", Permission: "roles:update", Required: true},
		{Method: "DELETE", Path: "/api/v1/roles/:id", Permission: "roles:delete", Required: true},
		{Method: "GET", Path: "/api/v1/roles/:id/permissions", Permission: "roles:read:permissions", Required: true},
		{Method: "POST", Path: "/api/v1/roles/:id/permissions", Permission: "roles:assign:permission", Required: true},
		{Method: "DELETE", Path: "/api/v1/roles/:id/permissions/:permission_id", Permission: "roles:remove:permission", Required: true},

		// Permissions маршруты
		{Method: "GET", Path: "/api/v1/permissions", Permission: "permissions:read:all", Required: true},
		{Method: "POST", Path: "/api/v1/permissions", Permission: "permissions:create", Required: true},
		{Method: "GET", Path: "/api/v1/permissions/:id", Permission: "permissions:read:one", Required: true},
		{Method: "PUT", Path: "/api/v1/permissions/:id", Permission: "permissions:update", Required: true},
		{Method: "DELETE", Path: "/api/v1/permissions/:id", Permission: "permissions:delete", Required: true},

		// External accounts маршруты (если они будут добавлены в gateway)
		{Method: "POST", Path: "/api/v1/external-accounts", Permission: "external_accounts:create", Required: true},
		{Method: "GET", Path: "/api/v1/external-accounts/:id", Permission: "external_accounts:read:one", Required: true},
		{Method: "PUT", Path: "/api/v1/external-accounts/:id", Permission: "external_accounts:update", Required: true},
		{Method: "DELETE", Path: "/api/v1/external-accounts/:id", Permission: "external_accounts:delete", Required: true},
		{Method: "GET", Path: "/api/v1/external-accounts/user/:user_id", Permission: "external_accounts:read:by_user", Required: true},
		{Method: "POST", Path: "/api/v1/external-accounts/link", Permission: "external_accounts:link", Required: true},

		// Collections layer (EP-13 / SDL-166) — all Required:false: the
		// gateway authenticates and injects X-User-ID, while ownership
		// (workspace → collection → record) is enforced by
		// collections-service. There is no /api/v1/projects group any more
		// (SDL-620): "workspace = project" since SDL-617b, and a route
		// without a registry entry answers 403 by design — the absence of
		// entries IS the closed surface (TestRegistryHasNoProjectsEntries). Entries still MUST exist: permissionMiddleware
		// answers 403 fail-safe for any route missing from this registry.
		// Placeholder names here are irrelevant (normalizeConfigPath folds
		// them to :id); they matter only in the Gin routes themselves.
		{Method: "GET", Path: "/api/v1/workspaces", Permission: "collections:ws:read", Required: false},
		{Method: "POST", Path: "/api/v1/workspaces", Permission: "collections:ws:create", Required: false},
		// Проверка адреса пространства (SDL-758, EP-155): нужна до создания
		// первого пространства, когда у пользователя ещё нет ни роли, ни
		// workspace, — поэтому Required:false (bootstrap-deadlock).
		{Method: "GET", Path: "/api/v1/workspaces/name-check", Permission: "collections:ws:name-check", Required: false},
		{Method: "GET", Path: "/api/v1/workspaces/:id", Permission: "collections:ws:read:one", Required: false},
		{Method: "PATCH", Path: "/api/v1/workspaces/:id", Permission: "collections:ws:update", Required: false},
		{Method: "DELETE", Path: "/api/v1/workspaces/:id", Permission: "collections:ws:delete", Required: false},
		// Корзина (SDL-660): восстановление удалённого пространства. Без
		// ScopeKind: выдача участников для пространства в корзине отвечает
		// 404, и скоуп дал бы 403 всегда. Владельца проверяет collections.
		{Method: "POST", Path: "/api/v1/workspaces/:id/restore", Permission: "collections:ws:restore", Required: false},
		// Расход счётных лимитов пространства (SDL-661, публикация SDL-664).
		// Как GET /workspaces/:id: без ScopeKind, причастность проверяет
		// collections (виден любому участнику, чужой — 404).
		{Method: "GET", Path: "/api/v1/workspaces/:id/usage", Permission: "collections:ws:usage", Required: false},
		// Переход пространства на Pro через Paddle Checkout (SDL-748, EP-146).
		// Как /members: без ScopeKind, владельца проверяет collections (не
		// владелец — 403, посторонний — 404). Required:false — у владельца нет
		// такого права в реестре user-service, true дало бы 403 всем.
		{Method: "POST", Path: "/api/v1/workspaces/:id/billing/checkout", Permission: "collections:ws:billing:checkout", Required: false},
		// Состояние оплаты для экрана тарифа (SDL-748): читает любой
		// участник, чужой — 404 от collections. Как checkout и /usage: без
		// ScopeKind, Required:false — бутстрап-юзер без прав не получит 403.
		{Method: "GET", Path: "/api/v1/workspaces/:id/billing", Permission: "collections:ws:billing:read", Required: false},
		// Портал покупателя Paddle (SDL-749): отмена, смена карты, счета.
		// Как checkout: без ScopeKind, владельца проверяет collections (не
		// владелец — 403, посторонний — 404), Required:false — права в
		// реестре user-service у владельца нет.
		{Method: "POST", Path: "/api/v1/workspaces/:id/billing/portal", Permission: "collections:ws:billing:portal", Required: false},
		// Участники workspace (SDL-609). Без ScopeKind, как и остальные /workspaces: причастность и роль
		// owner проверяет сам collections-service (чужой — 404, участник
		// без owner на запись — 403).
		{Method: "GET", Path: "/api/v1/workspaces/:id/members", Permission: "collections:ws:members:read", Required: false},
		{Method: "PUT", Path: "/api/v1/workspaces/:id/members", Permission: "collections:ws:members:put", Required: false},
		{Method: "DELETE", Path: "/api/v1/workspaces/:id/members/:user_id", Permission: "collections:ws:members:delete", Required: false},
		// Приглашения в workspace (SDL-615 S6). Четыре ручки владельца — без
		// ScopeKind, как members: посторонний получает 404, участник 403 от
		// самого collections-service. Две ручки получателя (/invites/preview,
		// /invites/accept) — для любого вошедшего: до принятия у него нет ни
		// одной роли в пространстве, поэтому Required:true или ScopeKind здесь
		// = тупик первого входа (стерегут bootstrap-тесты в routes_test.go).
		{Method: "GET", Path: "/api/v1/workspaces/:id/invites", Permission: "collections:ws:invites:read", Required: false},
		{Method: "POST", Path: "/api/v1/workspaces/:id/invites", Permission: "collections:ws:invites:create", Required: false},
		{Method: "POST", Path: "/api/v1/workspaces/:id/invites/:invite_id/resend", Permission: "collections:ws:invites:resend", Required: false},
		{Method: "DELETE", Path: "/api/v1/workspaces/:id/invites/:invite_id", Permission: "collections:ws:invites:revoke", Required: false},
		{Method: "POST", Path: "/api/v1/invites/preview", Permission: "collections:invites:preview", Required: false},
		{Method: "POST", Path: "/api/v1/invites/accept", Permission: "collections:invites:accept", Required: false},
		// Роли и токены на уровне workspace (SDL-617a/SDL-620a): после
		// SDL-617b это единственные пути к ролям и токенам, бывшие
		// /projects/:id/{roles,tokens} сняты (SDL-620). Без ScopeKind —
		// причастность проверяет сервис.
		{Method: "GET", Path: "/api/v1/workspaces/:id/roles", Permission: "collections:ws:roles:read", Required: false},
		{Method: "POST", Path: "/api/v1/workspaces/:id/roles", Permission: "collections:ws:roles:create", Required: false},
		{Method: "PATCH", Path: "/api/v1/workspaces/:id/roles/:role_id", Permission: "collections:ws:roles:update", Required: false},
		{Method: "DELETE", Path: "/api/v1/workspaces/:id/roles/:role_id", Permission: "collections:ws:roles:delete", Required: false},
		{Method: "GET", Path: "/api/v1/workspaces/:id/tokens", Permission: "collections:ws:tokens:read", Required: false},
		{Method: "POST", Path: "/api/v1/workspaces/:id/tokens", Permission: "collections:ws:tokens:create", Required: false},
		{Method: "POST", Path: "/api/v1/workspaces/:id/tokens/:token_id/rotate", Permission: "collections:ws:tokens:rotate", Required: false},
		{Method: "DELETE", Path: "/api/v1/workspaces/:id/tokens/:token_id", Permission: "collections:ws:tokens:revoke", Required: false},
		// Файлы (EP-25 Ф7, SDL-359). Required: false по той же причине, что и
		// у коллекций: права на маршрут тут ни при чём, шлюз маршрутизирует и
		// инжектит актора.
		// Записи всё равно ОБЯЗАНЫ быть: permissionMiddleware, не найдя
		// маршрута в реестре, отвечает 403 независимо от прав вызывающего.
		//
		// Скоуп (SDL-587, EP-121; по пространству — SDL-617 G2): предикат в
		// files-service — это скоуп, а не проверка, он не знает, твоё ли
		// пространство. Причастность актора сверяет шлюз на каждом маршруте:
		// workspace_id из строки запроса (у upload-url — из тела), роль актора
		// в пространстве — по workspace_members collections-service. Вниз
		// уходит только X-Scope-Workspace-ID; проектного заголовка и
		// проектного рода скоупа больше нет (SDL-620).
		//
		// ScopeOwnerOnly: до G2 файлы пускала проверка «владелец проекта»,
		// и это ровно workspaces.owner_user_id. Скоуп по пространству без
		// флага пустил бы и роль member — права менялись бы молча. Открыть
		// файлы участникам — отдельное продуктовое решение, в G2 его нет.
		{Method: "POST", Path: "/api/v1/files/upload-url", Permission: "files:upload:url", Required: false, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace, ScopeInBody: true, ScopeOwnerOnly: true},
		{Method: "POST", Path: "/api/v1/files/:id/complete", Permission: "files:upload:complete", Required: false, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace, ScopeOwnerOnly: true},
		{Method: "GET", Path: "/api/v1/files", Permission: "files:read", Required: false, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace, ScopeOwnerOnly: true},
		{Method: "GET", Path: "/api/v1/files/:id", Permission: "files:read:one", Required: false, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace, ScopeOwnerOnly: true},
		{Method: "PATCH", Path: "/api/v1/files/:id", Permission: "files:update", Required: false, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace, ScopeOwnerOnly: true},
		{Method: "DELETE", Path: "/api/v1/files/:id", Permission: "files:delete", Required: false, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace, ScopeOwnerOnly: true},
		{Method: "GET", Path: "/api/v1/files/:id/url", Permission: "files:url", Required: false, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace, ScopeOwnerOnly: true},
		// Где используется файл (SDL-649): чтение, тот же скоуп и та же
		// owner-only проверка, что у остальных ручек файлов.
		{Method: "GET", Path: "/api/v1/files/:id/links", Permission: "files:links", Required: false, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace, ScopeOwnerOnly: true},
		// Заменить файл во всех живых местах (SDL-651): оркестратор в
		// files-service, тот же скоуп и та же owner-only проверка.
		{Method: "POST", Path: "/api/v1/files/:id/replace", Permission: "files:replace", Required: false, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace, ScopeOwnerOnly: true},
		// Расход квот файлов пространства (SDL-663, публикация SDL-664): тот
		// же скоуп и та же owner-only проверка, что у остальных ручек файлов.
		{Method: "GET", Path: "/api/v1/files/usage", Permission: "files:usage", Required: false, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace, ScopeOwnerOnly: true},
		{Method: "GET", Path: "/api/v1/collections", Permission: "collections:read", Required: false},
		{Method: "POST", Path: "/api/v1/collections", Permission: "collections:create", Required: false},
		{Method: "GET", Path: "/api/v1/collections/:id", Permission: "collections:read:one", Required: false},
		{Method: "PATCH", Path: "/api/v1/collections/:id", Permission: "collections:update", Required: false},
		{Method: "DELETE", Path: "/api/v1/collections/:id", Permission: "collections:delete", Required: false},
		{Method: "GET", Path: "/api/v1/collections/:id/fields", Permission: "collections:fields:read", Required: false},
		{Method: "POST", Path: "/api/v1/collections/:id/fields", Permission: "collections:fields:create", Required: false},
		{Method: "PATCH", Path: "/api/v1/collections/:id/fields/:field_id", Permission: "collections:fields:update", Required: false},
		{Method: "DELETE", Path: "/api/v1/collections/:id/fields/:field_id", Permission: "collections:fields:delete", Required: false},
		{Method: "GET", Path: "/api/v1/collections/:id/indexes", Permission: "collections:indexes:read", Required: false},
		{Method: "POST", Path: "/api/v1/collections/:id/indexes", Permission: "collections:indexes:create", Required: false},
		{Method: "DELETE", Path: "/api/v1/collections/:id/indexes/:index_id", Permission: "collections:indexes:delete", Required: false},
		{Method: "GET", Path: "/api/v1/collections/:id/grants", Permission: "collections:grants:read", Required: false},
		{Method: "POST", Path: "/api/v1/collections/:id/grants", Permission: "collections:grants:create", Required: false},
		{Method: "PATCH", Path: "/api/v1/collections/:id/grants/:grant_id", Permission: "collections:grants:update", Required: false},
		{Method: "DELETE", Path: "/api/v1/collections/:id/grants/:grant_id", Permission: "collections:grants:delete", Required: false},
		{Method: "GET", Path: "/api/v1/records", Permission: "collections:records:read", Required: false},
		{Method: "POST", Path: "/api/v1/records", Permission: "collections:records:create", Required: false},
		{Method: "GET", Path: "/api/v1/records/:id", Permission: "collections:records:read:one", Required: false},
		{Method: "PATCH", Path: "/api/v1/records/:id", Permission: "collections:records:update", Required: false},
		{Method: "DELETE", Path: "/api/v1/records/:id", Permission: "collections:records:delete", Required: false},
		// Редактор pages (SDL-584, EP-110). Причастность актора к пространству
		// сверяет шлюз (SDL-587, EP-121) и кладёт вниз X-Scope-Workspace-ID;
		// pages-service отвечает 403 на workspace_id, расходящийся с ним
		// (SDL-589). Create несёт workspace_id в теле, остальные — в строке
		// запроса.
		//
		// Required: true (SDL-614, EP-111) — единственная группа, где право
		// проверяется парой «право + пространство»: 29 прав pages:* (22 + 6 темы, SDL-772, + publish блока, SDL-965) в
		// user-service несут scope=workspace, а роль актора в пространстве
		// (owner | member) шлюз резолвит по workspace_members и отдаёт в
		// check-permission вместе с workspace_id. Без Required: true
		// permissionMiddleware выходит до похода в user-service, и вся пара —
		// мёртвый код. Порядок слоёв в группе — jwt → scope → permission
		// (routes.go), иначе в проверку уехало бы незаверенное пространство.
		// Номер ревизии — литерал :param: normalizePath сворачивает числовой
		// сегмент в :param, а normalizeConfigPath любое другое имя (:n) — в :id,
		// и запись с :n не нашлась бы никогда (fail-safe 403).
		{Method: "POST", Path: "/api/v1/pages/routes", Permission: "pages:routes:create", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace, ScopeInBody: true},
		{Method: "GET", Path: "/api/v1/pages/routes", Permission: "pages:routes:read", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "GET", Path: "/api/v1/pages/routes/by-path", Permission: "pages:routes:read:by_path", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "GET", Path: "/api/v1/pages/routes/:id", Permission: "pages:routes:read:one", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "PATCH", Path: "/api/v1/pages/routes/:id", Permission: "pages:routes:update", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "DELETE", Path: "/api/v1/pages/routes/:id", Permission: "pages:routes:delete", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "POST", Path: "/api/v1/pages/pages", Permission: "pages:pages:create", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace, ScopeInBody: true},
		{Method: "GET", Path: "/api/v1/pages/pages", Permission: "pages:pages:read", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "GET", Path: "/api/v1/pages/pages/:id", Permission: "pages:pages:read:one", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "PATCH", Path: "/api/v1/pages/pages/:id", Permission: "pages:pages:update", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "DELETE", Path: "/api/v1/pages/pages/:id", Permission: "pages:pages:delete", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "GET", Path: "/api/v1/pages/pages/:id/revisions", Permission: "pages:pages:revisions:read", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "GET", Path: "/api/v1/pages/pages/:id/revisions/:param", Permission: "pages:pages:revisions:read:one", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "POST", Path: "/api/v1/pages/pages/:id/revisions/:param/restore", Permission: "pages:pages:revisions:restore", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "POST", Path: "/api/v1/pages/blocks", Permission: "pages:blocks:create", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace, ScopeInBody: true},
		{Method: "GET", Path: "/api/v1/pages/blocks", Permission: "pages:blocks:read", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "GET", Path: "/api/v1/pages/blocks/:id", Permission: "pages:blocks:read:one", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "PATCH", Path: "/api/v1/pages/blocks/:id", Permission: "pages:blocks:update", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "DELETE", Path: "/api/v1/pages/blocks/:id", Permission: "pages:blocks:delete", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "GET", Path: "/api/v1/pages/blocks/:id/revisions", Permission: "pages:blocks:revisions:read", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "GET", Path: "/api/v1/pages/blocks/:id/revisions/:param", Permission: "pages:blocks:revisions:read:one", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "POST", Path: "/api/v1/pages/blocks/:id/revisions/:param/restore", Permission: "pages:blocks:revisions:restore", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		// Выкатка правки Компонента на выбранные опубликованные страницы
		// (SDL-965). Право проверяет user-service по методу и пути, поэтому у
		// ручки свой код pages:blocks:publish: переиспользовать код
		// pages:routes:update нельзя — сид user-service ищет право по коду и
		// переписал бы им путь PATCH /routes/:id. Роли те же, что у публикации
		// страницы (ws:owner и ws:member получают все pages:*). Шлюз выкатывать
		// ПОСЛЕ сида user-service, иначе check-permission отказывает всем.
		{Method: "POST", Path: "/api/v1/pages/blocks/:id/publish", Permission: "pages:blocks:publish", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		// Тема сайта (SDL-772): черновик, publish, журнал и restore — та же
		// пара «право + пространство», что у остальных редакторских ручек.
		// Права pages:theme:* заводит seed user-service (по методу и пути):
		// без них check-permission отказал бы любому актору — шлюз выкатывать
		// ПОСЛЕ user-service.
		{Method: "GET", Path: "/api/v1/pages/theme", Permission: "pages:theme:read", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "PATCH", Path: "/api/v1/pages/theme", Permission: "pages:theme:update", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "POST", Path: "/api/v1/pages/theme/publish", Permission: "pages:theme:publish", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "GET", Path: "/api/v1/pages/theme/revisions", Permission: "pages:theme:revisions:read", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "GET", Path: "/api/v1/pages/theme/revisions/:param", Permission: "pages:theme:revisions:read:one", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		{Method: "POST", Path: "/api/v1/pages/theme/revisions/:param/restore", Permission: "pages:theme:revisions:restore", Required: true, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
		// Расход квот pages (SDL-662, публикация SDL-664) — единственная
		// запись группы с Required: false. Права pages:usage в user-service
		// нет (29 прав pages:* — только редакторские), и с Required: true
		// check-permission отказал бы любому актору. Причастность к
		// пространству (owner | member) сверяет скоуп — ровно та же пара ролей,
		// которой user-service выдаёт редакторские права; чужое — 403 до
		// апстрима.
		{Method: "GET", Path: "/api/v1/pages/usage", Permission: "pages:usage", Required: false, ScopeParam: "workspace_id", ScopeKind: ScopeWorkspace},
	}
}

// FindRouteConfig находит конфигурацию маршрута по методу и нормализованному пути
func FindRouteConfig(method, normalizedPath string) *RouteConfig {
	configs := GetRouteConfigs()
	for _, config := range configs {
		if config.Method == method && normalizeConfigPath(config.Path) == normalizedPath {
			return &config
		}
	}
	return nil
}

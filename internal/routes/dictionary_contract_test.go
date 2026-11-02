package routes_test

// SDL-315: соответствие набора роутов шлюза набору роутов апстрима
// (dictionary-service).
//
// Класс дефекта, который закрывает этот файл, шире, чем «нет записи в
// реестре разрешений» (его ловит TestEveryGinRouteIsCoveredByPermissionRegistry
// в routes_test.go). Шлюз может зарегистрировать путь ДРУГИМ методом, чем
// апстрим, и тогда эндпоинт недостижим ни одним способом, причём молча:
//   - правильный метод -> шлюз отвечает своим Gin-дефолтом 404;
//   - метод шлюза      -> шлюз проксирует, а апстрим отвечает своим 404.
// Оба ответа выглядят как «эндпоинта не существует», а не как поломка
// конфигурации. Именно так /v1/dictionary/cities пролежал недоступным на
// обоих контурах: шлюз держал POST, dictionary-service — GET.
//
// Тест офлайновый и детерминированный: живой сервис не опрашивается,
// сравнивается реальный роутер шлюза с таблицей-зеркалом апстрима ниже.

import (
	"net/http"
	"sort"
	"strings"
	"testing"
)

// dictionaryPrefix — путь группы словаря на шлюзе.
const dictionaryPrefix = "/api/v1/dictionary"

// upstreamRoute — одна строка контракта dictionary-service.
type upstreamRoute struct {
	Method string
	Path   string // относительно /api/v1/dictionary
	// ViaGateway=false означает «апстрим этот роут отдаёт, но наружу через
	// шлюз он сознательно не публикуется» (service-to-service поверхность).
	ViaGateway bool
}

// dictionaryUpstreamRoutes — зеркало таблицы роутов dictionary-service
// (dictionary-service/internal/routes/routes.go, группа /api/v1/dictionary).
//
// Зеркало не гниёт молча: в dictionary-service лежит парный тест
// TestDictionaryRouteTableMatchesContract с тем же самым списком, и он
// сверяет список с ФАКТИЧЕСКИМ роутером сервиса. Поэтому любое изменение
// роутов апстрима сначала роняет тест в dictionary-service, который прямо
// говорит обновить обе копии. Общий пакет под эту таблицу не заводится
// намеренно: он потребовал бы релиза go-sdk и синхронного бампа версии в
// двух репозиториях на каждую правку роута — дороже, чем два зеркала со
// встречными проверками.
var dictionaryUpstreamRoutes = []upstreamRoute{
	{http.MethodPost, "/error", true},
	{http.MethodGet, "/errors", true},
	{http.MethodPost, "/translations", true},
	// Алиас для go-sdk: сервисы ходят в dictionary-service напрямую,
	// наружу через шлюз не публикуется.
	{http.MethodPost, "/words", false},
	{http.MethodGet, "/countries", true},
	{http.MethodGet, "/cities", true},
	{http.MethodGet, "/languages", true},
}

// notPathForwarded — роуты шлюза под /api/v1/dictionary, которые НЕ
// проксируют собственный путь и потому вне контракта путей.
//
// /dictionary/health обслуживается ProxyHealthCheck, который жёстко ходит
// на корневой /health сервиса независимо от пути запроса (см.
// handlers.ProxyHealthCheck и SDL-206), поэтому пары «такой же путь у
// апстрима» для него не существует. Все остальные роуты группы идут через
// ProxyToService, который передаёт EscapedPath как есть — для них
// совпадение метода и пути со стороной сервиса обязательно.
var notPathForwarded = map[string]bool{
	"/health": true,
}

// gatewayDictionaryRoutes — фактические роуты шлюза под /api/v1/dictionary,
// которые проксируют свой путь в апстрим, в виде map[path]set(methods).
func gatewayDictionaryRoutes(t *testing.T) map[string]map[string]bool {
	t.Helper()
	r, _ := newTestRouter(t, true)

	got := make(map[string]map[string]bool)
	for _, ri := range r.Routes() {
		if !strings.HasPrefix(ri.Path, dictionaryPrefix+"/") {
			continue
		}
		path := strings.TrimPrefix(ri.Path, dictionaryPrefix)
		if notPathForwarded[path] {
			continue
		}
		if got[path] == nil {
			got[path] = make(map[string]bool)
		}
		got[path][ri.Method] = true
	}
	return got
}

func methodList(set map[string]bool) string {
	out := make([]string, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// TestGatewayDictionaryRoutesMatchUpstream — контракт слева направо:
// каждый публикуемый роут апстрима должен быть на шлюзе, и ровно тем же
// методом. Расхождение метода (SDL-315) и пропавший роут ловятся здесь.
func TestGatewayDictionaryRoutesMatchUpstream(t *testing.T) {
	got := gatewayDictionaryRoutes(t)

	for _, want := range dictionaryUpstreamRoutes {
		methods, registered := got[want.Path]

		if !want.ViaGateway {
			if registered {
				t.Errorf("шлюз публикует %s %s%s, хотя этот роут апстрима помечен как service-to-service (ViaGateway:false)",
					methodList(methods), dictionaryPrefix, want.Path)
			}
			continue
		}

		if !registered {
			t.Errorf("апстрим отдаёт %s %s, но шлюз не регистрирует этот путь вовсе — эндпоинт недостижим через %s%s",
				want.Method, want.Path, dictionaryPrefix, want.Path)
			continue
		}

		if !methods[want.Method] {
			t.Errorf("расхождение методов на %s%s: шлюз регистрирует %s, dictionary-service отдаёт %s — эндпоинт недостижим ни одним способом (правильный метод даёт 404 на шлюзе, метод шлюза — 404 от сервиса)",
				dictionaryPrefix, want.Path, methodList(methods), want.Method)
		}
	}
}

// TestGatewayDictionaryRoutesHaveNoDeadSurface — контракт справа налево:
// на шлюзе не должно быть роутов словаря, которых апстрим не отдаёт.
// Такой роут проксируется и всегда получает 404 от сервиса — мёртвая
// публичная поверхность.
func TestGatewayDictionaryRoutesHaveNoDeadSurface(t *testing.T) {
	expected := make(map[string]bool)
	for _, u := range dictionaryUpstreamRoutes {
		if u.ViaGateway {
			expected[u.Method+" "+u.Path] = true
		}
	}

	for path, methods := range gatewayDictionaryRoutes(t) {
		for method := range methods {
			if !expected[method+" "+path] {
				t.Errorf("шлюз публикует %s %s%s, но dictionary-service такой роут не отдаёт — запрос уйдёт в апстрим и вернётся 404 (обнови зеркало dictionaryUpstreamRoutes, если роут появился в сервисе)",
					method, dictionaryPrefix, path)
			}
		}
	}
}

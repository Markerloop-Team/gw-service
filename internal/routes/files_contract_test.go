package routes_test

// EP-25 Ф7 (SDL-359): что шлюз обязан отдавать files-service, и — важнее —
// чего он отдавать НЕ должен.
//
// Управляющую плоскость (метаданные, ссылки, CRUD) проверяет общий свип
// TestEveryGinRouteIsCoveredByPermissionRegistry. Здесь фиксируются два
// решения EP-25, которые общий свип поймать не может, потому что они про
// ОТСУТСТВИЕ маршрутов:
//
//  1. байты не ходят через шлюз (PUT идёт по presigned-ссылке прямо в бакет:
//     потолок тела на ingress — 1 MiB, а gw читает тело в память);
//  2. публичная плоскость выдачи /files/:id не ходит через шлюз (она
//     cache-friendly и адресуется отдельно; иначе шлюз становится узким
//     местом на трафике картинок).
//
// Оба легко «починить» одной строкой в routes.go и не заметить, что ты
// только что вернул узкое место. Тест существует, чтобы такая строка падала.

import (
	"net/http"
	"strings"
	"testing"
)

func TestFilesControlPlaneIsProxied(t *testing.T) {
	r, token := newTestRouter(t, true)
	headers := map[string]string{"Authorization": "Bearer " + token}

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/files/upload-url"},
		{http.MethodPost, "/api/v1/files/" + testUserID + "/complete"},
		{http.MethodGet, "/api/v1/files"},
		{http.MethodGet, "/api/v1/files/" + testUserID},
		{http.MethodPatch, "/api/v1/files/" + testUserID},
		{http.MethodDelete, "/api/v1/files/" + testUserID},
		{http.MethodGet, "/api/v1/files/" + testUserID + "/url"},
		{http.MethodGet, "/api/v1/files/" + testUserID + "/links"},
	} {
		w := doRequest(r, tc.method, tc.path, headers)
		if w.Code == http.StatusNotFound {
			t.Errorf("%s %s: шлюз не знает маршрут (404)", tc.method, tc.path)
		}
		if w.Code == http.StatusForbidden {
			t.Errorf("%s %s: 403 — нет записи в реестре прав", tc.method, tc.path)
		}
	}
}

// Здоровье апстрима обязано быть доступно без токена: проброс здоровья
// ходит на "/health" апстрима и не должен требовать аутентификации.
func TestFilesHealthIsPublic(t *testing.T) {
	r, _ := newTestRouter(t, false)
	if w := doRequest(r, http.MethodGet, "/api/v1/files/health", nil); w.Code == http.StatusUnauthorized {
		t.Fatalf("health апстрима не должен требовать токен, пришло %d", w.Code)
	}
}

// Плоскость выдачи и межсервисная ручка через шлюз НЕ публикуются.
func TestFilesDeliveryAndInternalAreNotProxied(t *testing.T) {
	r, token := newTestRouter(t, true)
	headers := map[string]string{"Authorization": "Bearer " + token}

	for _, path := range []string{
		"/files/" + testUserID,                  // публичная выдача — своим ingress, мимо gw
		"/api/v1/files/" + testUserID + "/data", // её же форма под /api — тоже не наша
		"/internal/v1/files/links",              // межсервисная ручка (прецедент SDL-323)
	} {
		w := doRequest(r, http.MethodGet, path, headers)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: шлюз не должен знать этот путь, пришло %d — "+
				"плоскость выдачи обязана идти мимо gw (EP-25 Ф4)", path, w.Code)
		}
	}
}

// Загрузка байтов через шлюз не публикуется ни в каком виде: PUT идёт по
// presigned-ссылке прямо в бакет.
func TestFilesBytesDoNotGoThroughGateway(t *testing.T) {
	r, token := newTestRouter(t, true)
	headers := map[string]string{"Authorization": "Bearer " + token}

	for _, tc := range []struct{ method, path string }{
		{http.MethodPut, "/api/v1/files/" + testUserID},
		{http.MethodPut, "/api/v1/files/" + testUserID + "/content"},
		{http.MethodPost, "/api/v1/files"},
	} {
		w := doRequest(r, tc.method, tc.path, headers)
		if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: байты не должны ходить через шлюз, пришло %d",
				tc.method, tc.path, w.Code)
		}
	}
}

// Апстрим объявлен в карте сервисов: маршрут, зарегистрированный в Gin без
// записи в ServicesConfig, отвечает «сервис не найден» уже в рантайме.
func TestFilesUpstreamIsDeclared(t *testing.T) {
	r, token := newTestRouter(t, true)
	w := doRequest(r, http.MethodGet, "/api/v1/files", map[string]string{"Authorization": "Bearer " + token})
	if strings.Contains(w.Body.String(), "Сервис не найден") {
		t.Fatalf("апстрим files не объявлен в ServicesConfig: %s", w.Body.String())
	}
}

// SDL-409: спека files-service публикуется шлюзом и НЕ требует токена.
//
// Оба свойства нужны контуру фуззинга dev-infra, и оба ломаются молча. Роут
// без записи в /api/docs даёт 404, а гард _spec_available в conftest на 404
// просто скипает сервис — ночной регресс остаётся зелёным, ничего не
// проверив. Требование токена даст 401 и ровно тот же скип.
func TestFilesSwaggerIsProxiedWithoutToken(t *testing.T) {
	r, _ := newTestRouter(t, false)

	w := doRequest(r, http.MethodGet, "/api/docs/files/swagger/doc.json", nil)
	if w.Code == http.StatusNotFound {
		t.Fatalf("шлюз не знает маршрут спеки files (404) — schemathesis молча скипнет сервис")
	}
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Fatalf("спека потребовала аутентификации (%d) — её читает контур фуззинга без токена", w.Code)
	}
}

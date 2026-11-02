package config_test

// SDL-175: the gateway's service map used to be hand-written in
// cmd/server/main.go, one line per upstream. Adding an upstream therefore
// took three edits that had to agree — a field on ServicesConfig, a
// getEnvRequired call, and a line in that map. Missing the third produced a
// route that registers in Gin, passes the router sweep in
// internal/routes/routes_test.go (which runs on a proxy stub) and only fails
// in production with "сервис не найден".
//
// ServicesConfig.URLMap now derives the map from the struct, and these tests
// pin that behaviour: every declared upstream must appear, and none may
// appear under an empty key.

import (
	"reflect"
	"testing"

	"gateway-service/internal/config"
)

// TestURLMapCoversEveryDeclaredService walks ServicesConfig by reflection,
// gives every field a distinct URL, and requires URLMap to surface all of
// them. A new field added without a Name would silently vanish from the map;
// this fails instead.
func TestURLMapCoversEveryDeclaredService(t *testing.T) {
	var svcs config.ServicesConfig

	v := reflect.ValueOf(&svcs).Elem()
	typ := v.Type()
	want := make(map[string]string, v.NumField())

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if field.Type() != reflect.TypeOf(config.ServiceConfig{}) {
			t.Fatalf("ServicesConfig.%s is not a ServiceConfig — URLMap assumes every field is one", typ.Field(i).Name)
		}
		// Name mirrors what the production loader sets; the URL is made
		// unique so a map that collapses two services is detectable.
		name := typ.Field(i).Name
		url := "http://" + name + ".test:80"
		field.Set(reflect.ValueOf(config.ServiceConfig{Name: name, URL: url}))
		want[name] = url
	}

	got := svcs.URLMap()

	if len(got) != len(want) {
		t.Errorf("URLMap returned %d entries, ServicesConfig declares %d: %v", len(got), len(want), got)
	}
	for name, url := range want {
		actual, ok := got[name]
		if !ok {
			t.Errorf("service %q declared on ServicesConfig but absent from URLMap", name)
			continue
		}
		if actual != url {
			t.Errorf("service %q mapped to %q, want %q", name, actual, url)
		}
	}
}

// routeHandlerUpstreams — exactly the names routes.go hands to
// ProxyHealthCheck/ProxyToService/ProxySwagger. These strings are the join
// between routes.go and the service map; a rename on one side without the
// other is a runtime 502, so the set is spelled out rather than derived.
//
// SDL-572: "files" used to be missing from this list even though routes.go
// has proxied it since SDL-359. The literal in
// TestURLMapNamesMatchRouteHandlers simply left the field zero-valued, so
// both sides of the length check stayed at six and the drift cancelled
// itself out. Forgetting this list when adding an upstream is precisely what
// the length check exists to catch, so the list is now the full set.
var routeHandlerUpstreams = []string{
	"auth", "user", "notification", "dictionary", "telegram-bot",
	"collections", "files", "pages",
}

// TestURLMapNamesMatchRouteHandlers pins the service names the router passes
// to ProxyHealthCheck/ProxyToService against a hand-built ServicesConfig:
// dropping a field from the struct stops this file from compiling, and
// dropping it from the literal alone breaks the length check.
func TestURLMapNamesMatchRouteHandlers(t *testing.T) {
	svcs := config.ServicesConfig{
		Auth:         config.ServiceConfig{Name: "auth", URL: "http://auth"},
		User:         config.ServiceConfig{Name: "user", URL: "http://user"},
		Notification: config.ServiceConfig{Name: "notification", URL: "http://notification"},
		Dictionary:   config.ServiceConfig{Name: "dictionary", URL: "http://dictionary"},
		TelegramBot:  config.ServiceConfig{Name: "telegram-bot", URL: "http://bot"},
		Collections:  config.ServiceConfig{Name: "collections", URL: "http://collections"},
		Files:        config.ServiceConfig{Name: "files", URL: "http://files"},
		Pages:        config.ServiceConfig{Name: "pages", URL: "http://pages"},
	}

	wantNames := routeHandlerUpstreams

	got := svcs.URLMap()
	for _, name := range wantNames {
		if _, ok := got[name]; !ok {
			t.Errorf("route handlers proxy to %q, but URLMap has no such key — GetServiceURL would fail at runtime", name)
		}
	}
	if len(got) != len(wantNames) {
		t.Errorf("URLMap has %d entries, routes reference %d — update whichever side drifted: %v", len(got), len(wantNames), got)
	}
}

// TestURLMapSkipsUnnamedServices guards the loader's failure mode: a
// ServiceConfig left zero-valued (variable never wired up) must not land in
// the map under the empty key, where GetServiceURL("") would answer with a
// blank URL instead of a clear not-found error.
func TestURLMapSkipsUnnamedServices(t *testing.T) {
	svcs := config.ServicesConfig{
		Auth: config.ServiceConfig{Name: "auth", URL: "http://auth"},
		// everything else zero-valued
	}

	got := svcs.URLMap()

	if _, ok := got[""]; ok {
		t.Error(`URLMap contains an entry under the empty key — an unwired ServiceConfig leaked into the service map`)
	}
	if len(got) != 1 {
		t.Errorf("URLMap returned %d entries for one named service: %v", len(got), got)
	}
}

// TestLoadWiresEveryRouteHandlerUpstream closes the gap the two tests above
// leave open (SDL-572): both build a ServicesConfig by hand, so a field that
// exists on the struct but is never filled in by Load — the exact shape of
// "upstream declared, variable never wired" — passes them and then answers
// «Сервис не найден» in production. This one runs the real loader.
//
// Only the variables Load treats as required are set; files and pages are
// deliberately left unset, because their getEnv defaults are part of what is
// being pinned (an upstream must not need a ConfigMap key to exist).
func TestLoadWiresEveryRouteHandlerUpstream(t *testing.T) {
	for k, v := range map[string]string{
		"AUTH_SERVICE_URL":         "http://auth",
		"USER_SERVICE_URL":         "http://user",
		"NOTIFICATION_SERVICE_URL": "http://notification",
		"DICTIONARY_SERVICE_URL":   "http://dictionary",
		"TELEGRAM_BOT_SERVICE_URL": "http://bot",
		"COLLECTIONS_SERVICE_URL":  "http://collections",
		"JWT_PUBLIC_KEY":           "-----BEGIN PUBLIC KEY-----\nnot-parsed-by-Load\n-----END PUBLIC KEY-----",
		"SERVICE_KEY":              "test-service-key",
	} {
		t.Setenv(k, v)
	}

	got := config.Load().Services.URLMap()

	for _, name := range routeHandlerUpstreams {
		url, ok := got[name]
		if !ok {
			t.Errorf("Load() produced no upstream %q — routes.go proxies to it, GetServiceURL would answer «Сервис не найден»", name)
			continue
		}
		if url == "" {
			t.Errorf("upstream %q loaded with an empty URL", name)
		}
	}
	if len(got) != len(routeHandlerUpstreams) {
		t.Errorf("Load() produced %d upstreams, routes reference %d: %v", len(got), len(routeHandlerUpstreams), got)
	}
}

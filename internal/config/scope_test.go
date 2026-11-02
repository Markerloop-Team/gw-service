package config_test

// SDL-613 S9: флаг границы токена пространства. Выключен по умолчанию —
// прод не меняется, пока в оверлей не придёт SCOPE_REQUIRE_WORKSPACE_TOKEN.

import (
	"testing"

	"gateway-service/internal/config"
)

func setRequiredEnv(t *testing.T) {
	t.Helper()
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
}

func TestScopeRequireWorkspaceTokenFlag(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"", false},
		{"false", false},
		{"true", true},
		{"1", true},
		{"yes", false}, // не bool для strconv.ParseBool — остаётся выключенным
	} {
		setRequiredEnv(t)
		t.Setenv("SCOPE_REQUIRE_WORKSPACE_TOKEN", tc.value)
		if got := config.Load().Scope.RequireWorkspaceToken; got != tc.want {
			t.Errorf("SCOPE_REQUIRE_WORKSPACE_TOKEN=%q -> %v, ожидалось %v", tc.value, got, tc.want)
		}
	}
}

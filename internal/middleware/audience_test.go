package middleware

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	sdkjwt "gitlab.com/markerloop/go-sdk/pkg/jwt"
)

// unsignedJWT — JWT с произвольным payload: гард читает claims без подписи.
func unsignedJWT(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc([]byte(payload)) + ".c2ln"
}

func TestTokenHasAudience(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   bool
	}{
		{"aud строкой", "Bearer " + unsignedJWT(`{"aud":"mcp"}`), true},
		{"aud массивом", "Bearer " + unsignedJWT(`{"aud":["https://mcp.test.example.com/mcp"]}`), true},
		{"aud число", "Bearer " + unsignedJWT(`{"aud":42}`), true},
		{"aud массив не строк", "Bearer " + unsignedJWT(`{"aud":[1,2]}`), true},
		{"схема bearer строчными", "bearer " + unsignedJWT(`{"aud":"mcp"}`), true},
		{"схема с пробелами", "  BEARER   " + unsignedJWT(`{"aud":"mcp"}`) + "  ", true},
		{"без aud", "Bearer " + unsignedJWT(`{"user_id":"u"}`), false},
		{"aud пустая строка", "Bearer " + unsignedJWT(`{"aud":""}`), true},
		{"aud пустой массив", "Bearer " + unsignedJWT(`{"aud":[]}`), false},
		{"aud null", "Bearer " + unsignedJWT(`{"aud":null}`), false},
		{"aud массив из пустой строки", "Bearer " + unsignedJWT(`{"aud":[""]}`), true},
		{"aud массив с пустой и непустой", "Bearer " + unsignedJWT(`{"aud":["","x"]}`), true},
		{"aud пустой массив с пробелами", "Bearer " + unsignedJWT(`{"aud": [ ] }`), false},
		{"aud null с пробелами", "Bearer " + unsignedJWT(`{"aud" : null }`), false},
		{"mlp_-ключ", "Bearer mlp_abc", false},
		{"мусор", "Bearer not-a-jwt", false},
		{"пусто", "", false},
		{"другая схема", "Basic " + unsignedJWT(`{"aud":"mcp"}`), false},
	}
	for _, tc := range cases {
		if got := tokenHasAudience(tc.header); got != tc.want {
			t.Errorf("%s: tokenHasAudience = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestAudienceIsSetMatchesSDK — гард шлюза и go-sdk v0.36.0 одинаково
// решают, есть ли у токена `aud` (замечание ревью SDL-692, раунд 2: раньше
// гард считал "" и [""] пустыми, а go-sdk их отвергал). Эталон — разбор
// payload в sdkjwt.Claims и sdkjwt.RejectAudience: ошибка разбора тоже
// отказ (ValidateToken такой токен не примет).
func TestAudienceIsSetMatchesSDK(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    bool
	}{
		{"нет aud", `{"user_id":"u"}`, false},
		{"null", `{"aud":null}`, false},
		{"пустой массив", `{"aud":[]}`, false},
		{"пустая строка", `{"aud":""}`, true},
		{"массив из пустой строки", `{"aud":[""]}`, true},
		{"строка", `{"aud":"x"}`, true},
		{"массив из строки", `{"aud":["x"]}`, true},
		{"массив из двух", `{"aud":["","x"]}`, true},
		{"число", `{"aud":42}`, true},
		{"объект", `{"aud":{"a":"b"}}`, true},
		{"массив не строк", `{"aud":[1]}`, true},
	}
	for _, tc := range cases {
		var claims map[string]json.RawMessage
		if err := json.Unmarshal([]byte(tc.payload), &claims); err != nil {
			t.Fatalf("%s: bad payload: %v", tc.name, err)
		}
		got := audienceIsSet(claims["aud"])

		var sdk sdkjwt.Claims
		sdkRejects := json.Unmarshal([]byte(tc.payload), &sdk) != nil || sdkjwt.RejectAudience(&sdk) != nil

		if got != tc.want {
			t.Errorf("%s: audienceIsSet = %v, want %v", tc.name, got, tc.want)
		}
		if got != sdkRejects {
			t.Errorf("%s: audienceIsSet = %v, go-sdk rejects = %v", tc.name, got, sdkRejects)
		}
	}
}

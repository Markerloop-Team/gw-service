package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// buildUpstreamHeaders mirrors what ProxyToService does: collect the client headers,
// sanitize them, then inject the identity derived from the verified JWT (if any).
// Keeping the order here identical to the handler is the whole point of the test —
// sanitizing after injection would delete the trusted value instead of the spoofed one.
func buildUpstreamHeaders(c *gin.Context) map[string]string {
	headers := make(map[string]string)
	for key, values := range c.Request.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	sanitizeUpstreamHeaders(headers)

	if userID, exists := c.Get("user_id"); exists {
		if userIDStr, ok := userID.(string); ok {
			headers["X-User-ID"] = userIDStr
		}
	}

	return headers
}

func TestSanitizeUpstreamHeadersDropsClientIdentity(t *testing.T) {
	cases := []struct {
		name   string
		header string
	}{
		{"canonical casing", "X-User-ID"},
		{"lowercase", "x-user-id"},
		{"mixed casing", "X-uSeR-Id"},
		{"internal prefix", "X-ML-Tenant"},
		{"internal prefix lowercase", "x-ml-role"},
		// SDL-587: скоуп, сверенный шлюзом, подделать снаружи нельзя.
		{"scope project", "X-Scope-Project-ID"},
		{"scope workspace lowercase", "x-scope-workspace-id"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{tc.header: "attacker-value"}

			sanitizeUpstreamHeaders(headers)

			if len(headers) != 0 {
				t.Fatalf("header %q must not reach upstream, got %v", tc.header, headers)
			}
		})
	}
}

func TestSanitizeUpstreamHeadersKeepsUnrelatedHeaders(t *testing.T) {
	// X-Service-Key is a legitimate credential: the gateway validates it at the
	// boundary (ServiceToServiceAuth on /notifications and the telegram group) and
	// the upstream service may validate it again, so it must survive sanitization.
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer token",
		"X-Service-Key": "internal-key",
		"X-Request-Id":  "req-1",
	}

	sanitizeUpstreamHeaders(headers)

	for _, k := range []string{"Content-Type", "Authorization", "X-Service-Key", "X-Request-Id"} {
		if _, ok := headers[k]; !ok {
			t.Errorf("header %q must be forwarded upstream, but was dropped", k)
		}
	}
}

func TestSanitizeUpstreamHeadersStillDropsBrowserHeaders(t *testing.T) {
	headers := map[string]string{
		"Origin":         "https://markerloop.com",
		"Referer":        "https://markerloop.com/users",
		"Sec-Fetch-Mode": "cors",
		"Sec-Ch-Ua":      "\"Chromium\";v=\"120\"",
		"Priority":       "u=1, i",
	}

	sanitizeUpstreamHeaders(headers)

	if len(headers) != 0 {
		t.Fatalf("browser-only headers must not reach upstream, got %v", headers)
	}
}

func TestUpstreamIdentityComesFromContextNotClient(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/api/v1/users/my", nil)
	c.Request.Header.Set("X-User-ID", "victim-user-id")
	c.Set("user_id", "actor-from-jwt")

	headers := buildUpstreamHeaders(c)

	if got := headers["X-User-ID"]; got != "actor-from-jwt" {
		t.Fatalf("upstream identity = %q, want the JWT actor %q", got, "actor-from-jwt")
	}
}

func TestUnauthenticatedRequestForwardsNoIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// No user_id in context: the route is not behind jwtMiddleware. A spoofed header
	// must not be promoted into an identity just because nothing overwrote it.
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/api/v1/users/my", nil)
	c.Request.Header.Set("X-User-ID", "attacker-supplied")

	headers := buildUpstreamHeaders(c)

	if _, ok := headers["X-User-ID"]; ok {
		t.Fatalf("X-User-ID must be absent without a verified actor, got %q", headers["X-User-ID"])
	}
}

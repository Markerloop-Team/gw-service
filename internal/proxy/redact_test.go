package proxy

import (
	"bytes"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

const piiEmail = "pii-gw738@example.com"

func TestRedactURLError(t *testing.T) {
	cause := errors.New("connection refused")
	in := &url.Error{Op: "Get", URL: "http://user-service:8082/api/v1/users/email/" + piiEmail + "?search=" + piiEmail, Err: cause}
	out := RedactURLError(in)
	if strings.Contains(out.Error(), "@") || strings.Contains(out.Error(), "pii-gw738") {
		t.Fatalf("redacted error still has personal data: %q", out.Error())
	}
	if !strings.Contains(out.Error(), "user-service:8082") || !errors.Is(out, cause) {
		t.Fatalf("host or cause lost: %q", out.Error())
	}
	plain := errors.New("plain")
	if RedactURLError(plain) != plain {
		t.Fatal("non-url error must pass unchanged")
	}
	if RedactURLError(nil) != nil {
		t.Fatal("nil must stay nil")
	}
}

// SDL-738: ни ошибка наверх, ни журнал шлюза не несут путь/query с почтой,
// когда апстрим недоступен или путь не собирается в URL.
func TestProxyRequest_ErrorsCarryNoPersonalData(t *testing.T) {
	var buf bytes.Buffer
	log := logrus.New()
	log.SetOutput(&buf)
	ps := NewProxyService(map[string]string{"user": "http://127.0.0.1:1"}, time.Second, log)

	cases := map[string]string{
		"upstream down": "/api/v1/users/email/" + piiEmail,
		"invalid path":  "/api/v1/users/email/" + piiEmail + "\x7f",
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			buf.Reset()
			_, err := ps.ProxyRequest("user", "GET", path, nil, map[string]string{"search": piiEmail}, nil)
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, s := range []string{err.Error(), buf.String()} {
				if strings.Contains(s, "@") || strings.Contains(s, "pii-gw738") {
					t.Fatalf("personal data leaked: %q", s)
				}
			}
		})
	}
}

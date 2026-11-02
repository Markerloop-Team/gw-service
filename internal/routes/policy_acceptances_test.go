package routes_test

// SDL-752: the policy-acceptance journal of user-service.
//
// user-service serves two read endpoints:
//   - GET /users/my/policy-acceptances  — the caller's own rows (X-User-ID);
//   - GET /users/:id/policy-acceptances — anyone's rows, for an administrator.
//
// The second one has NO permission check of its own in user-service: the
// gateway is the only thing between a signed-in user and somebody else's
// IP addresses and user agents. So these tests pin three things per route:
// it is published (not a Gin 404), it sits behind JWT (401 without a token),
// and the foreign one is refused (403) when the permission check says no.
// Removing either registry entry in internal/config/routes.go turns the
// proxy-reaches-upstream cases red: an unregistered route fails closed (403).

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"gateway-service/internal/config"
	"gateway-service/internal/models"
)

const (
	policyAcceptancesOwnPath = "/api/v1/users/my/policy-acceptances"
	policyJournalOtherUserID = "99999999-8888-7777-6666-555555555555"
)

var policyAcceptancesForeignPath = "/api/v1/users/" + policyJournalOtherUserID + "/policy-acceptances"

// policyJournalProxy answers check-permission with grant and records every
// other proxied call so the test can see what reached user-service.
type policyJournalProxy struct {
	grant bool

	mu          sync.Mutex
	checks      int
	upstream    []string
	upstreamQry []map[string]string
}

func (p *policyJournalProxy) ProxyRequest(serviceName, method, path string, headers map[string]string, queryParams map[string]string, body []byte) (*models.ProxyResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if strings.Contains(path, "/check-permission") {
		p.checks++
		payload, _ := json.Marshal(map[string]any{
			"data": map[string]any{"has_permission": p.grant},
		})
		return &models.ProxyResponse{
			StatusCode: http.StatusOK,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       payload,
		}, nil
	}
	p.upstream = append(p.upstream, serviceName+" "+method+" "+path)
	p.upstreamQry = append(p.upstreamQry, queryParams)
	return &models.ProxyResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       []byte(`{"success":true,"data":[]}`),
	}, nil
}

func (p *policyJournalProxy) GetServiceURL(serviceName string) (string, error) {
	return "http://127.0.0.1:1", nil
}

func TestPolicyAcceptancesRoutesRequireToken(t *testing.T) {
	r, _ := newRouterWithProxy(t, &policyJournalProxy{grant: true})

	for _, path := range []string{policyAcceptancesOwnPath, policyAcceptancesForeignPath} {
		w := doRequest(r, http.MethodGet, path, nil)
		if w.Code == http.StatusNotFound {
			t.Errorf("GET %s -> 404: the gateway does not publish the route (user-service serves it)", path)
			continue
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without a token -> %d, want 401", path, w.Code)
		}
	}
}

// The caller's own journal is a read of "my" data, like GET /users/my: the
// ":own" short-circuit lets it through without asking user-service, so a
// fresh account without any role still reads its own acceptances.
func TestOwnPolicyAcceptancesShortCircuitWithoutRole(t *testing.T) {
	stub := &policyJournalProxy{grant: false}
	r, token := newRouterWithProxy(t, stub)

	w := doRequest(r, http.MethodGet, policyAcceptancesOwnPath+"?limit=10", map[string]string{
		"Authorization": "Bearer " + token,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s with a token and no role -> %d, want 200; body: %s", policyAcceptancesOwnPath, w.Code, w.Body.String())
	}
	if stub.checks != 0 {
		t.Errorf("own journal asked user-service for a permission %d time(s); the :own read must short-circuit", stub.checks)
	}
	if len(stub.upstream) != 1 || stub.upstream[0] != "user GET "+policyAcceptancesOwnPath {
		t.Fatalf("upstream calls = %v, want exactly [user GET %s]", stub.upstream, policyAcceptancesOwnPath)
	}
	if got := stub.upstreamQry[0]["limit"]; got != "10" {
		t.Errorf("limit query forwarded as %q, want \"10\"", got)
	}
}

// Somebody else's journal: without the administrator permission the gateway
// answers 403 and user-service is never reached.
func TestForeignPolicyAcceptancesDeniedWithoutPermission(t *testing.T) {
	stub := &policyJournalProxy{grant: false}
	r, token := newRouterWithProxy(t, stub)

	w := doRequest(r, http.MethodGet, policyAcceptancesForeignPath, map[string]string{
		"Authorization": "Bearer " + token,
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET %s without the permission -> %d, want 403", policyAcceptancesForeignPath, w.Code)
	}
	if len(stub.upstream) != 0 {
		t.Errorf("a refused request reached user-service: %v", stub.upstream)
	}
}

func TestForeignPolicyAcceptancesProxiedWithPermission(t *testing.T) {
	stub := &policyJournalProxy{grant: true}
	r, token := newRouterWithProxy(t, stub)

	w := doRequest(r, http.MethodGet, policyAcceptancesForeignPath+"?limit=200", map[string]string{
		"Authorization": "Bearer " + token,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s with the permission -> %d, want 200; body: %s", policyAcceptancesForeignPath, w.Code, w.Body.String())
	}
	if stub.checks != 1 {
		t.Errorf("permission checks = %d, want 1: the foreign journal must be checked in user-service", stub.checks)
	}
	if len(stub.upstream) != 1 || stub.upstream[0] != "user GET "+policyAcceptancesForeignPath {
		t.Fatalf("upstream calls = %v, want exactly [user GET %s]", stub.upstream, policyAcceptancesForeignPath)
	}
	if got := stub.upstreamQry[0]["limit"]; got != "200" {
		t.Errorf("limit query forwarded as %q, want \"200\"", got)
	}
}

// Registry side: the foreign route must never become Required:false or an
// ":own" code — either would skip the only permission check it has.
func TestPolicyAcceptancesRegistryEntries(t *testing.T) {
	own := config.FindRouteConfig(http.MethodGet, policyAcceptancesOwnPath)
	if own == nil || !own.Required || !strings.Contains(own.Permission, ":own") {
		t.Errorf("own journal registry entry = %+v, want Required:true with an :own permission", own)
	}
	foreign := config.FindRouteConfig(http.MethodGet, "/api/v1/users/:id/policy-acceptances")
	if foreign == nil {
		t.Fatal("foreign journal has no registry entry")
	}
	if !foreign.Required || strings.Contains(foreign.Permission, ":own") {
		t.Errorf("foreign journal registry entry = %+v, want Required:true and a non-:own administrator permission", foreign)
	}
	if foreign.ScopeKind != "" {
		t.Errorf("foreign journal is platform-level, got ScopeKind %q", foreign.ScopeKind)
	}
}

// SDL-752, экран журнала в админке: журнал поперёк людей и сводка по
// редакциям. Обе ручки — только право администратора, как чужой журнал:
// у user-service своей проверки на них нет.
const (
	policyJournalListPath    = "/api/v1/policy-acceptances"
	policyJournalSummaryPath = "/api/v1/policy-acceptances/summary"
)

func TestPolicyJournalListRoutesRequireToken(t *testing.T) {
	r, _ := newRouterWithProxy(t, &policyJournalProxy{grant: true})
	for _, path := range []string{policyJournalListPath, policyJournalSummaryPath} {
		w := doRequest(r, http.MethodGet, path, nil)
		if w.Code == http.StatusNotFound {
			t.Errorf("GET %s -> 404: the gateway does not publish the route (user-service serves it)", path)
			continue
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without a token -> %d, want 401", path, w.Code)
		}
	}
}

func TestPolicyJournalListDeniedWithoutPermission(t *testing.T) {
	for _, path := range []string{policyJournalListPath, policyJournalSummaryPath} {
		stub := &policyJournalProxy{grant: false}
		r, token := newRouterWithProxy(t, stub)
		w := doRequest(r, http.MethodGet, path+"?search=alice", map[string]string{
			"Authorization": "Bearer " + token,
		})
		if w.Code != http.StatusForbidden {
			t.Errorf("GET %s without the permission -> %d, want 403", path, w.Code)
		}
		if stub.checks != 1 {
			t.Errorf("GET %s: permission checks = %d, want 1", path, stub.checks)
		}
		if len(stub.upstream) != 0 {
			t.Errorf("a refused request reached user-service: %v", stub.upstream)
		}
	}
}

func TestPolicyJournalListProxiedWithPermission(t *testing.T) {
	stub := &policyJournalProxy{grant: true}
	r, token := newRouterWithProxy(t, stub)

	w := doRequest(r, http.MethodGet, policyJournalListPath+"?search=ali&current_edition=2026-10-01&page=2&limit=50", map[string]string{
		"Authorization": "Bearer " + token,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s with the permission -> %d, want 200; body: %s", policyJournalListPath, w.Code, w.Body.String())
	}
	w = doRequest(r, http.MethodGet, policyJournalSummaryPath, map[string]string{
		"Authorization": "Bearer " + token,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s with the permission -> %d, want 200; body: %s", policyJournalSummaryPath, w.Code, w.Body.String())
	}
	want := []string{"user GET " + policyJournalListPath, "user GET " + policyJournalSummaryPath}
	if len(stub.upstream) != 2 || stub.upstream[0] != want[0] || stub.upstream[1] != want[1] {
		t.Fatalf("upstream calls = %v, want %v", stub.upstream, want)
	}
	q := stub.upstreamQry[0]
	if q["search"] != "ali" || q["current_edition"] != "2026-10-01" || q["page"] != "2" || q["limit"] != "50" {
		t.Errorf("query forwarded as %v", q)
	}
	if stub.checks != 2 {
		t.Errorf("permission checks = %d, want 2 (one per request)", stub.checks)
	}
}

func TestPolicyJournalListRegistryEntries(t *testing.T) {
	for _, path := range []string{policyJournalListPath, policyJournalSummaryPath} {
		rc := config.FindRouteConfig(http.MethodGet, path)
		if rc == nil {
			t.Errorf("%s has no registry entry", path)
			continue
		}
		if rc.Permission != "users:read:policy_acceptances" || !rc.Required || rc.ScopeKind != "" {
			t.Errorf("%s registry entry = %+v, want users:read:policy_acceptances, Required:true, no scope", path, rc)
		}
	}
}

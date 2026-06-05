package osint

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestShodanClient_NoKeyIsAvailableFalse — without an API key, the
// client advertises itself as unavailable so the recon agent skips it
// gracefully. The one-command invariant requires this: a fresh user
// who hasn't configured Shodan still gets a working scan.
func TestShodanClient_NoKeyIsAvailableFalse(t *testing.T) {
	c := NewShodanClient(ShodanConfig{})
	if c.IsAvailable() {
		t.Fatal("IsAvailable should be false without an API key")
	}
}

// TestShodanClient_LookupWithoutKeyReturnsActionableError — explicit
// guard: Lookup should never silently succeed when unconfigured, and
// the error message has to tell the user exactly what to do (matches
// the CONTRIBUTING.md §3 error-message rule).
func TestShodanClient_LookupWithoutKeyReturnsActionableError(t *testing.T) {
	c := NewShodanClient(ShodanConfig{})
	_, err := c.Lookup(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error when no API key configured")
	}
	if !strings.Contains(err.Error(), "PENTESTSWARM_SHODAN_API_KEY") {
		t.Errorf("error should mention the env var to set: %v", err)
	}
}

// TestShodanClient_LookupHappyPath — verifies the request shape (path,
// key in query, hostname filter) and the response → Asset translation
// (one "service" asset per match, dedup'd "subdomain" assets across
// hostnames).
func TestShodanClient_LookupHappyPath(t *testing.T) {
	var capturedPath, capturedKey, capturedQuery string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedKey = r.URL.Query().Get("key")
		capturedQuery = r.URL.Query().Get("query")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(shodanHostSearch{
			Total: 2,
			Matches: []shodanHostHit{
				{
					IPStr:     "1.2.3.4",
					Port:      443,
					Hostnames: []string{"api.example.com", "www.example.com"},
					Product:   "nginx",
					Version:   "1.24",
				},
				{
					IPStr:     "5.6.7.8",
					Port:      22,
					Hostnames: []string{"api.example.com"}, // dup — should not double-count
					Product:   "OpenSSH",
				},
			},
		})
	}))
	defer server.Close()

	c := NewShodanClient(ShodanConfig{APIKey: "test-key", Endpoint: server.URL})

	assets, err := c.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if capturedPath != "/shodan/host/search" {
		t.Errorf("path = %q, want /shodan/host/search", capturedPath)
	}
	if capturedKey != "test-key" {
		t.Errorf("key = %q, want test-key", capturedKey)
	}
	if capturedQuery != "hostname:example.com" {
		t.Errorf("query = %q, want hostname:example.com", capturedQuery)
	}

	// 2 services + 2 unique subdomains (api + www, not 3 — api was dup)
	if len(assets) != 4 {
		t.Fatalf("expected 4 assets (2 services + 2 unique subdomains), got %d (%+v)", len(assets), assets)
	}

	var services, subdomains int
	for _, a := range assets {
		switch a.Type {
		case "service":
			services++
			if a.Source != "shodan" {
				t.Errorf("service source = %q", a.Source)
			}
		case "subdomain":
			subdomains++
		}
	}
	if services != 2 {
		t.Errorf("services = %d, want 2", services)
	}
	if subdomains != 2 {
		t.Errorf("subdomains = %d, want 2 (api.example.com + www.example.com, deduplicated)", subdomains)
	}
}

// TestShodanClient_Lookup401 — invalid key surfaces a clear error
// that names the console URL.
func TestShodanClient_Lookup401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	c := NewShodanClient(ShodanConfig{APIKey: "bad-key", Endpoint: server.URL})
	_, err := c.Lookup(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "account.shodan.io") {
		t.Errorf("error should point at the console URL: %v", err)
	}
}

// TestShodanClient_LookupEmptyMatches — Shodan returns an empty
// matches array when nothing matches; the client must produce no
// assets (and no error) so the recon merger sees a clean nil/empty
// result.
func TestShodanClient_LookupEmptyMatches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total":0,"matches":[]}`))
	}))
	defer server.Close()

	c := NewShodanClient(ShodanConfig{APIKey: "k", Endpoint: server.URL})
	assets, err := c.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets; got %d", len(assets))
	}
}

// TestShodanToAssets_PreservesMetadata — direct test of the conversion
// helper so we don't need an HTTP roundtrip to verify metadata fields
// are wired through.
func TestShodanToAssets_PreservesMetadata(t *testing.T) {
	doc := shodanHostSearch{
		Matches: []shodanHostHit{{
			IPStr: "10.0.0.1", Port: 80, Product: "Apache", Version: "2.4", Transport: "tcp",
			Hostnames: []string{"x.example.com"}, Org: "ExampleCorp",
		}},
	}
	assets := shodanToAssets(doc)
	if len(assets) != 2 { // 1 service + 1 subdomain
		t.Fatalf("expected 2 assets, got %d", len(assets))
	}
	svc := assets[0]
	if svc.Type != "service" || svc.Value != "10.0.0.1:80" {
		t.Errorf("service shape wrong: %+v", svc)
	}
	if svc.Metadata["product"] != "Apache" || svc.Metadata["org"] != "ExampleCorp" {
		t.Errorf("metadata not preserved: %+v", svc.Metadata)
	}
}

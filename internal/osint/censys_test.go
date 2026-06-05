package osint

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCensysClient_RequiresBothCredentials — Censys v2 needs both
// halves; either being empty makes the client unavailable so the
// recon agent skips it cleanly.
func TestCensysClient_RequiresBothCredentials(t *testing.T) {
	cases := []struct {
		name           string
		cfg            CensysConfig
		wantAvailable  bool
	}{
		{"both missing", CensysConfig{}, false},
		{"id only", CensysConfig{APIID: "x"}, false},
		{"secret only", CensysConfig{APISecret: "y"}, false},
		{"both", CensysConfig{APIID: "x", APISecret: "y"}, true},
	}
	for _, c := range cases {
		got := NewCensysClient(c.cfg).IsAvailable()
		if got != c.wantAvailable {
			t.Errorf("%s: IsAvailable = %v, want %v", c.name, got, c.wantAvailable)
		}
	}
}

// TestCensysClient_LookupWithoutCredentialsActionableError — error
// message must mention both env vars so the researcher knows what to
// set without leaving the terminal.
func TestCensysClient_LookupWithoutCredentialsActionableError(t *testing.T) {
	_, err := NewCensysClient(CensysConfig{}).Lookup(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"PENTESTSWARM_CENSYS_API_ID", "PENTESTSWARM_CENSYS_API_SECRET"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s: %v", want, err)
		}
	}
}

// TestCensysClient_LookupHappyPath — verifies the request shape
// (path, Basic auth header with id:secret base64-encoded, JSON body
// with the dns.names query) and the response → Asset translation
// (1 host + 1 service per port + dedup'd subdomains).
func TestCensysClient_LookupHappyPath(t *testing.T) {
	var capturedAuth, capturedPath string
	var capturedBody censysSearchRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&capturedBody)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(censysSearchResponse{
			Code: 200,
			Result: struct {
				Total int          `json:"total"`
				Hits  []censysHost `json:"hits"`
			}{
				Total: 1,
				Hits: []censysHost{{
					IP:   "10.20.30.40",
					Name: "host.example.com",
					Services: []censysSvc{
						{Port: 443, ServiceName: "HTTPS", TransportProtocol: "TCP"},
						{Port: 22, ServiceName: "SSH", TransportProtocol: "TCP"},
					},
					DNS: &censysDNS{
						Names: []string{"api.example.com", "www.example.com", "api.example.com"}, // dup → dedup
					},
				}},
			},
		})
	}))
	defer server.Close()

	c := NewCensysClient(CensysConfig{APIID: "id1", APISecret: "sec1", Endpoint: server.URL})
	assets, err := c.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if capturedPath != "/v2/hosts/search" {
		t.Errorf("path = %q", capturedPath)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("id1:sec1"))
	if capturedAuth != wantAuth {
		t.Errorf("Authorization = %q, want %q", capturedAuth, wantAuth)
	}
	if capturedBody.Q != "dns.names:example.com" {
		t.Errorf("query body q = %q", capturedBody.Q)
	}

	// 1 host + 2 services + 2 unique subdomains
	if len(assets) != 5 {
		t.Fatalf("expected 5 assets, got %d (%+v)", len(assets), assets)
	}

	var hosts, services, subs int
	for _, a := range assets {
		switch a.Type {
		case "host":
			hosts++
		case "service":
			services++
		case "subdomain":
			subs++
		}
	}
	if hosts != 1 || services != 2 || subs != 2 {
		t.Errorf("breakdown wrong: hosts=%d services=%d subs=%d (want 1/2/2)", hosts, services, subs)
	}
}

// TestCensysClient_Lookup401 — bad credentials surface a clear error
// pointing at the console URL.
func TestCensysClient_Lookup401(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()

			c := NewCensysClient(CensysConfig{APIID: "bad", APISecret: "bad", Endpoint: server.URL})
			_, err := c.Lookup(context.Background(), "example.com")
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "search.censys.io/account/api") {
				t.Errorf("error should point at the console: %v", err)
			}
		})
	}
}

// TestCensysClient_LookupEmpty — empty hits → no assets, no error.
func TestCensysClient_LookupEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"result":{"total":0,"hits":[]}}`))
	}))
	defer server.Close()

	c := NewCensysClient(CensysConfig{APIID: "x", APISecret: "y", Endpoint: server.URL})
	assets, err := c.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets, got %d", len(assets))
	}
}

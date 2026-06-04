package recon

import (
	"testing"
)

// TestParseAttackSurface_StrictShape is the happy path: a frontier-API
// (Claude / GPT-4) response that honors the spec'd JSON shape end-to-end.
func TestParseAttackSurface_StrictShape(t *testing.T) {
	raw := `{
		"target": "example.com",
		"subdomains": [
			{"domain": "api.example.com", "ip": "1.2.3.4", "source": "subfinder"}
		],
		"hosts": [{"ip": "1.2.3.4", "hostnames": ["api.example.com"], "open_ports": [443]}],
		"endpoints": [{"url": "https://api.example.com/v1/users", "method": "GET"}],
		"technologies": {"nginx": "1.24", "express": "4.18"}
	}`

	s, err := ParseAttackSurface(raw)
	if err != nil {
		t.Fatalf("strict parse failed: %v", err)
	}
	if len(s.Subdomains) != 1 || s.Subdomains[0].Domain != "api.example.com" {
		t.Fatalf("subdomains not parsed strictly: %+v", s.Subdomains)
	}
	if s.Subdomains[0].Source != "subfinder" {
		t.Fatalf("source should come from input, not fallback marker; got %q", s.Subdomains[0].Source)
	}
	if s.Technologies["nginx"] != "1.24" {
		t.Fatalf("technologies map not parsed: %+v", s.Technologies)
	}
}

// TestParseAttackSurface_OllamaFlatStrings covers the #16 report: local
// Ollama models emit subdomains/hosts/endpoints as flat string arrays
// instead of object arrays. We promote each string into a record stamped
// with the fallback source marker so downstream code can see it was a
// degraded parse.
func TestParseAttackSurface_OllamaFlatStrings(t *testing.T) {
	raw := `{
		"target": "mydomain.com",
		"subdomains": ["hub.mydomain.com", "ss.mydomain.com"],
		"hosts": ["10.0.0.1", "10.0.0.2"],
		"endpoints": ["https://hub.mydomain.com/admin", "https://hub.mydomain.com/api"]
	}`

	s, err := ParseAttackSurface(raw)
	if err != nil {
		t.Fatalf("flat-string parse failed: %v", err)
	}
	if len(s.Subdomains) != 2 || s.Subdomains[0].Domain != "hub.mydomain.com" {
		t.Fatalf("flat subdomains not promoted: %+v", s.Subdomains)
	}
	if s.Subdomains[0].Source != fallbackSource {
		t.Fatalf("fallback source marker missing: %+v", s.Subdomains[0])
	}
	if len(s.Hosts) != 2 || s.Hosts[0].IP != "10.0.0.1" {
		t.Fatalf("flat hosts not promoted: %+v", s.Hosts)
	}
	if len(s.Endpoints) != 2 || s.Endpoints[0].URL != "https://hub.mydomain.com/admin" {
		t.Fatalf("flat endpoints not promoted: %+v", s.Endpoints)
	}
}

// TestParseAttackSurface_TechnologiesAsArray covers the same family as
// #7: model returns technologies as a flat list instead of a map. We
// keep the names; versions are stamped empty.
func TestParseAttackSurface_TechnologiesAsArray(t *testing.T) {
	raw := `{
		"target": "example.com",
		"technologies": ["nginx", "express", "react"]
	}`

	s, err := ParseAttackSurface(raw)
	if err != nil {
		t.Fatalf("array-technologies parse failed: %v", err)
	}
	if len(s.Technologies) != 3 {
		t.Fatalf("expected 3 technologies; got %d (%+v)", len(s.Technologies), s.Technologies)
	}
	if _, ok := s.Technologies["nginx"]; !ok {
		t.Fatalf("nginx not present in technologies map: %+v", s.Technologies)
	}
	if s.Technologies["nginx"] != "" {
		t.Fatalf("array fallback should leave versions empty; got %q", s.Technologies["nginx"])
	}
}

// TestParseAttackSurface_SingleObject covers the rarer drift where the
// model returns a single record instead of a one-element array.
func TestParseAttackSurface_SingleObject(t *testing.T) {
	raw := `{
		"target": "example.com",
		"subdomains": {"domain": "api.example.com", "source": "manual"}
	}`

	s, err := ParseAttackSurface(raw)
	if err != nil {
		t.Fatalf("single-object parse failed: %v", err)
	}
	if len(s.Subdomains) != 1 || s.Subdomains[0].Domain != "api.example.com" {
		t.Fatalf("single object not wrapped into array: %+v", s.Subdomains)
	}
}

// TestParseAttackSurface_MarkdownFenced covers the common case where the
// LLM wraps its JSON in a ```json fence.
func TestParseAttackSurface_MarkdownFenced(t *testing.T) {
	raw := "```json\n{\"target\": \"example.com\", \"subdomains\": [\"a.example.com\"]}\n```"
	s, err := ParseAttackSurface(raw)
	if err != nil {
		t.Fatalf("fenced parse failed: %v", err)
	}
	if s.Target != "example.com" {
		t.Fatalf("target lost in fence stripping: %q", s.Target)
	}
}

// TestParseAttackSurface_EmptyRejects ensures we still return a clear
// error on empty / whitespace-only input rather than a confusing nil.
func TestParseAttackSurface_EmptyRejects(t *testing.T) {
	if _, err := ParseAttackSurface(""); err == nil {
		t.Fatal("expected error on empty input")
	}
	if _, err := ParseAttackSurface("   \n  "); err == nil {
		t.Fatal("expected error on whitespace-only input")
	}
}

// TestParseAttackSurface_MissingFieldsAreNil — partial responses should
// not crash. The fields the model didn't include just come back nil.
func TestParseAttackSurface_MissingFieldsAreNil(t *testing.T) {
	raw := `{"target": "example.com"}`
	s, err := ParseAttackSurface(raw)
	if err != nil {
		t.Fatalf("minimal parse failed: %v", err)
	}
	if s.Subdomains != nil || s.Hosts != nil || s.Endpoints != nil || s.Technologies != nil {
		t.Fatalf("missing fields should be nil; got s=%+v", s)
	}
}

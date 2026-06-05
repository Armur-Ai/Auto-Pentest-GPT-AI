package tools

import "testing"

func TestTestSSLTool_Name(t *testing.T) {
	if n := NewTestSSLTool().Name(); n != "testssl" {
		t.Errorf("Name() = %q, want \"testssl\"", n)
	}
}

func TestTestSSLTool_IsAvailable(t *testing.T) { _ = NewTestSSLTool().IsAvailable() }

// TestParseTestSSLJSON_FiltersBySeverity — testssl's JSON contains
// hundreds of OK/INFO entries documenting what was *not* found; we
// only want HIGH / MEDIUM / LOW / WARN / CRITICAL to survive into
// findings, so the LLM doesn't drown in benign "TLS 1.2 supported"
// entries.
func TestParseTestSSLJSON_FiltersBySeverity(t *testing.T) {
	input := []byte(`[
		{"id": "TLS1_2", "ip": "1.2.3.4/443", "port": "443", "severity": "OK", "finding": "offered"},
		{"id": "BEAST", "ip": "1.2.3.4/443", "port": "443", "severity": "MEDIUM", "finding": "vulnerable, no workaround"},
		{"id": "HSTS", "ip": "1.2.3.4/443", "port": "443", "severity": "INFO", "finding": "long enough"},
		{"id": "ROBOT", "ip": "1.2.3.4/443", "port": "443", "severity": "HIGH", "finding": "vulnerable, MEDIUM cipher"},
		{"id": "RANDOM", "ip": "1.2.3.4/443", "port": "443", "severity": "WARN", "finding": "warning"}
	]`)
	findings := parseTestSSLJSON(input)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings (MEDIUM/HIGH/WARN), got %d (%+v)", len(findings), findings)
	}
	for _, f := range findings {
		sev := f["severity"]
		if sev == "OK" || sev == "INFO" {
			t.Errorf("benign severity leaked through: %v", f)
		}
		if f["tool"] != "testssl" {
			t.Errorf("tool = %v, want testssl", f["tool"])
		}
	}
}

func TestParseTestSSLJSON_MalformedReturnsNil(t *testing.T) {
	cases := [][]byte{nil, []byte(""), []byte("{not json}"), []byte("not even close")}
	for _, c := range cases {
		if got := parseTestSSLJSON(c); got != nil {
			t.Errorf("input %q should produce nil, got %v", c, got)
		}
	}
}

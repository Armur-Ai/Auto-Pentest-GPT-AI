package tools

import "testing"

// TestArjunTool_Name — name matches the upstream binary and plan id.
func TestArjunTool_Name(t *testing.T) {
	if n := NewArjunTool().Name(); n != "arjun" {
		t.Errorf("Name() = %q, want \"arjun\"", n)
	}
}

func TestArjunTool_IsAvailable(t *testing.T) {
	_ = NewArjunTool().IsAvailable()
}

// TestParseArjunJSON_ValidObject — arjun -oJ writes
// {"<url>": {"params": [...], "method": "...", ...}}. The parser
// flattens that into one finding per discovered parameter so the
// downstream API agent can iterate without re-keying the URL.
func TestParseArjunJSON_ValidObject(t *testing.T) {
	input := []byte(`{
		"https://target.example.com/api/v1/user": {
			"method": "GET",
			"params": ["id", "user", "redirect"],
			"headers": {},
			"stable": true
		}
	}`)
	findings := parseArjunJSON(input)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
	seen := map[string]bool{}
	for _, f := range findings {
		if f["url"] != "https://target.example.com/api/v1/user" {
			t.Errorf("url = %v", f["url"])
		}
		if f["method"] != "GET" {
			t.Errorf("method = %v", f["method"])
		}
		seen[f["parameter"].(string)] = true
	}
	for _, p := range []string{"id", "user", "redirect"} {
		if !seen[p] {
			t.Errorf("expected parameter %q in findings", p)
		}
	}
}

// TestParseArjunJSON_EmptyParams — arjun ran but found nothing.
// Parser produces an empty/nil slice; no panic.
func TestParseArjunJSON_EmptyParams(t *testing.T) {
	input := []byte(`{"https://target.example.com/": {"method": "GET", "params": [], "headers": {}, "stable": true}}`)
	if got := parseArjunJSON(input); len(got) != 0 {
		t.Errorf("empty params should produce no findings; got %d", len(got))
	}
}

// TestParseArjunJSON_MalformedReturnsNil — broken JSON returns nil
// rather than crashing the campaign.
func TestParseArjunJSON_MalformedReturnsNil(t *testing.T) {
	cases := []string{"", "{not json}", "truncated [", "null"}
	for _, c := range cases {
		if got := parseArjunJSON([]byte(c)); got != nil {
			t.Errorf("input %q should produce nil, got %v", c, got)
		}
	}
}

// TestParseArjunJSON_MultipleURLs — arjun can be run against several
// targets in one invocation; the parser must handle each URL bucket
// independently.
func TestParseArjunJSON_MultipleURLs(t *testing.T) {
	input := []byte(`{
		"https://a.example.com/": {"method": "GET", "params": ["x"], "stable": true},
		"https://b.example.com/": {"method": "POST", "params": ["y", "z"], "stable": false}
	}`)
	findings := parseArjunJSON(input)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings across both URLs, got %d", len(findings))
	}
}

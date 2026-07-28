package tools

import "testing"

func TestNiktoTool_Name(t *testing.T) {
	if n := NewNiktoTool().Name(); n != "nikto" {
		t.Errorf("Name() = %q, want \"nikto\"", n)
	}
}

func TestNiktoTool_IsAvailable(t *testing.T) { _ = NewNiktoTool().IsAvailable() }

// TestParseNiktoJSON_VulnerabilitiesEmitted — nikto emits a flat
// vulnerabilities array with no per-item severity. Parser carries
// each entry through as a "low" severity finding.
func TestParseNiktoJSON_VulnerabilitiesEmitted(t *testing.T) {
	input := []byte(`{
		"host": "target.example.com",
		"ip": "203.0.113.10",
		"port": "443",
		"banner": "Apache/2.4.41",
		"vulnerabilities": [
			{
				"id": "999100",
				"method": "GET",
				"url": "/",
				"msg": "The X-Content-Type-Options header is not set.",
				"references": "https://example.com/x-content-type-options"
			},
			{
				"id": "999109",
				"method": "GET",
				"url": "/admin/",
				"msg": "Admin login page/section found."
			}
		]
	}`)
	findings := parseNiktoJSON(input)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f["tool"] != "nikto" {
			t.Errorf("tool = %v", f["tool"])
		}
		if f["severity"] != "low" {
			t.Errorf("severity = %v, want \"low\"", f["severity"])
		}
		if f["host"] != "target.example.com" || f["port"] != "443" {
			t.Errorf("host/port not carried through: %+v", f)
		}
	}
	if findings[0]["id"] != "999100" || findings[0]["url"] != "/" {
		t.Errorf("first finding shape wrong: %+v", findings[0])
	}
	if findings[1]["title"] != "Admin login page/section found." {
		t.Errorf("second finding title wrong: %+v", findings[1])
	}
}

// TestParseNiktoJSON_EmptyVulns — nikto ran but found nothing; parser
// produces no findings and never panics.
func TestParseNiktoJSON_EmptyVulns(t *testing.T) {
	input := []byte(`{"host": "target.example.com", "vulnerabilities": []}`)
	if got := parseNiktoJSON(input); len(got) != 0 {
		t.Errorf("empty vulns should produce no findings; got %d", len(got))
	}
}

func TestParseNiktoJSON_MalformedReturnsNil(t *testing.T) {
	for _, c := range [][]byte{nil, []byte(""), []byte("{not json"), []byte("garbage")} {
		if got := parseNiktoJSON(c); got != nil {
			t.Errorf("input %q should produce nil, got %v", c, got)
		}
	}
}

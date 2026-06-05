package tools

import "testing"

func TestWPScanTool_Name(t *testing.T) {
	if n := NewWPScanTool().Name(); n != "wpscan" {
		t.Errorf("Name() = %q, want \"wpscan\"", n)
	}
}

func TestWPScanTool_IsAvailable(t *testing.T) { _ = NewWPScanTool().IsAvailable() }

// TestParseWPScanJSON_CoreThemePluginVulns — wpscan emits CVEs across
// core/theme/plugin slots; each must produce one HIGH finding tagged
// with the right component so the classifier can prioritise.
func TestParseWPScanJSON_CoreThemePluginVulns(t *testing.T) {
	input := []byte(`{
		"version": {
			"number": "5.0",
			"status": "outdated",
			"vulnerabilities": [
				{"title": "WP Core <5.0.1: XSS", "fixed_in": "5.0.1", "references": {"cve": ["2018-9999"], "url": ["https://wpscan.com/v/1"]}}
			]
		},
		"plugins": {
			"contact-form-7": {
				"slug": "contact-form-7",
				"vulnerabilities": [
					{"title": "CF7 <5.0: File upload bypass", "fixed_in": "5.0.1", "references": {"cve": ["2020-1234"]}}
				]
			}
		},
		"themes": {
			"twentytwenty": {
				"slug": "twentytwenty",
				"vulnerabilities": [
					{"title": "Twenty Twenty <1.1: stored XSS", "references": {}}
				]
			}
		}
	}`)
	findings := parseWPScanJSON(input)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d (%+v)", len(findings), findings)
	}
	components := map[string]int{}
	for _, f := range findings {
		components[f["component"].(string)]++
		if f["severity"] != "high" {
			t.Errorf("severity = %v", f["severity"])
		}
	}
	for _, c := range []string{"core", "plugin", "theme"} {
		if components[c] != 1 {
			t.Errorf("expected 1 finding for %s, got %d", c, components[c])
		}
	}
}

// TestParseWPScanJSON_DisclosureSlots — empty user/config-backup
// slots produce no extra findings; populated ones produce one
// low-severity (users) or high-severity (config backups) finding.
func TestParseWPScanJSON_DisclosureSlots(t *testing.T) {
	input := []byte(`{
		"users": {"admin": {"id": 1}, "editor": {"id": 2}},
		"config_backups": {"/wp-config.php.bak": {"found_by": "Direct Access"}}
	}`)
	findings := parseWPScanJSON(input)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (users + config), got %d", len(findings))
	}
	var sawUsers, sawBackups bool
	for _, f := range findings {
		switch f["component"] {
		case "users":
			sawUsers = true
			if f["severity"] != "low" {
				t.Errorf("users severity should be low; got %v", f["severity"])
			}
		case "config_backups":
			sawBackups = true
			if f["severity"] != "high" {
				t.Errorf("config_backups severity should be high; got %v", f["severity"])
			}
		}
	}
	if !sawUsers || !sawBackups {
		t.Errorf("missing component: users=%v backups=%v", sawUsers, sawBackups)
	}
}

func TestParseWPScanJSON_MalformedReturnsNil(t *testing.T) {
	for _, c := range [][]byte{nil, []byte(""), []byte("{not json"), []byte("[]")} {
		// Empty array is valid JSON but doesn't match our object shape —
		// expect nil (or possibly empty slice, but we've coded for nil).
		got := parseWPScanJSON(c)
		if got != nil && len(got) != 0 {
			t.Errorf("input %q should produce nil/empty, got %v", c, got)
		}
	}
}

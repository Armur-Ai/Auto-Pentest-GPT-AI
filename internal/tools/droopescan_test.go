package tools

import "testing"

func TestDroopescanTool_Name(t *testing.T) {
	if n := NewDroopescanTool().Name(); n != "droopescan" {
		t.Errorf("Name() = %q, want \"droopescan\"", n)
	}
}

func TestDroopescanTool_IsAvailable(t *testing.T) { _ = NewDroopescanTool().IsAvailable() }

// TestParseDroopescanJSON_VersionAndFindings — full droopescan run
// surfaces a CMS version (info-severity) plus plugins/themes/
// interesting URLs (low-severity, awaiting classifier promotion).
func TestParseDroopescanJSON_VersionAndFindings(t *testing.T) {
	input := `{
		"host": "https://target.example.com",
		"cms": "drupal",
		"version": {"version": "9.5.0"},
		"plugins": {
			"finding": [
				{"name": "ctools", "url": "https://target.example.com/sites/all/modules/ctools"},
				{"name": "views", "url": "https://target.example.com/sites/all/modules/views"}
			]
		},
		"themes": {
			"finding": [
				{"name": "bartik", "url": "https://target.example.com/themes/bartik"}
			]
		},
		"interesting urls": {
			"finding": [
				{"url": "https://target.example.com/CHANGELOG.txt"}
			]
		}
	}`
	findings := parseDroopescanJSON(input)
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings (1 version + 2 plugins + 1 theme + 1 interesting), got %d", len(findings))
	}

	var versionCount, pluginCount, themeCount, intCount int
	for _, f := range findings {
		switch f["category"] {
		case "plugin":
			pluginCount++
		case "theme":
			themeCount++
		case "interesting_url":
			intCount++
		}
		if f["title"] == "CMS version identified" {
			versionCount++
			if f["value"] != "9.5.0" {
				t.Errorf("version value = %v", f["value"])
			}
		}
	}
	if versionCount != 1 || pluginCount != 2 || themeCount != 1 || intCount != 1 {
		t.Errorf("breakdown wrong: version=%d plugin=%d theme=%d interesting=%d",
			versionCount, pluginCount, themeCount, intCount)
	}
}

// TestParseDroopescanJSON_FindingsSeverity — plugins/themes/etc are
// low-severity by design; the version line is info. Classifier
// chains promotes to high after CVE correlation.
func TestParseDroopescanJSON_FindingsSeverity(t *testing.T) {
	input := `{"cms": "joomla", "plugins": {"finding": [{"name": "akeeba"}]}, "version": {"version": "3.10"}}`
	findings := parseDroopescanJSON(input)
	var plugin, version map[string]any
	for _, f := range findings {
		if f["category"] == "plugin" {
			plugin = f
		}
		if f["title"] == "CMS version identified" {
			version = f
		}
	}
	if plugin == nil || plugin["severity"] != "low" {
		t.Errorf("plugin severity not low: %+v", plugin)
	}
	if version == nil || version["severity"] != "info" {
		t.Errorf("version severity not info: %+v", version)
	}
}

func TestParseDroopescanJSON_MalformedReturnsNil(t *testing.T) {
	for _, c := range []string{"", "  ", "{not json", "garbage"} {
		if got := parseDroopescanJSON(c); got != nil {
			t.Errorf("input %q should produce nil, got %v", c, got)
		}
	}
}

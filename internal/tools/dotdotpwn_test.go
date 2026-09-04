package tools

import "testing"

func TestDotDotPwnTool_Name(t *testing.T) {
	if n := NewDotDotPwnTool().Name(); n != "dotdotpwn" {
		t.Errorf("Name() = %q, want \"dotdotpwn\"", n)
	}
}

func TestDotDotPwnTool_IsAvailable(t *testing.T) { _ = NewDotDotPwnTool().IsAvailable() }

// TestParseDotDotPwnText_VulnerableEmitted — only lines carrying the
// VULNERABLE marker become findings; the bulk of fuzz attempts are
// ignored. Each confirmed traversal is HIGH severity.
func TestParseDotDotPwnText_VulnerableEmitted(t *testing.T) {
	input := `[+] Testing Path: http://host:80/../../../etc/hosts
[+] Testing Path: http://host:80/../../../../etc/passwd <- VULNERABLE
[+] Testing Path: http://host:80/..%2f..%2f..%2fetc/passwd <- VULNERABLE
[+] Testing Path: http://host:80/../../../../boot.ini`
	findings := parseDotDotPwnText(input)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f["tool"] != "dotdotpwn" {
			t.Errorf("tool = %v", f["tool"])
		}
		if f["severity"] != "high" {
			t.Errorf("severity = %v, want \"high\"", f["severity"])
		}
		if f["category"] != "path_traversal" {
			t.Errorf("category = %v", f["category"])
		}
	}
	if findings[0]["path"] != "http://host:80/../../../../etc/passwd" {
		t.Errorf("first path = %v", findings[0]["path"])
	}
}

// TestParseDotDotPwnText_DedupesRepeats — the same confirmed traversal
// reported twice yields a single finding.
func TestParseDotDotPwnText_DedupesRepeats(t *testing.T) {
	input := `[+] Testing Path: http://host/../../etc/passwd <- VULNERABLE
[+] Testing Path: http://host/../../etc/passwd <- VULNERABLE`
	if got := len(parseDotDotPwnText(input)); got != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", got)
	}
}

// TestParseDotDotPwnText_NoHits — output with no VULNERABLE marker and
// empty input both yield no findings.
func TestParseDotDotPwnText_NoHits(t *testing.T) {
	if got := parseDotDotPwnText("[+] Testing Path: http://host/../../etc/passwd\n"); got != nil {
		t.Errorf("expected nil for no-hit output, got %v", got)
	}
	if got := parseDotDotPwnText(""); got != nil {
		t.Errorf("expected nil for empty input, got %v", got)
	}
}

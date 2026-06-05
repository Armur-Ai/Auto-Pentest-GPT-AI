package tools

import "testing"

func TestCRLFuzzTool_Name(t *testing.T) {
	if n := NewCRLFuzzTool().Name(); n != "crlfuzz" {
		t.Errorf("Name() = %q, want \"crlfuzz\"", n)
	}
}

func TestCRLFuzzTool_IsAvailable(t *testing.T) { _ = NewCRLFuzzTool().IsAvailable() }

// TestParseCRLFuzzOutput_OneFindingPerLine — crlfuzz writes one
// matched URL per line; each becomes a HIGH-severity finding
// categorised as crlf_injection.
func TestParseCRLFuzzOutput_OneFindingPerLine(t *testing.T) {
	input := "https://target.example.com/page?q=%0aSet-Cookie:%20x\nhttps://target.example.com/redir?u=%0d%0aSet-Cookie:%20y\n"
	findings := parseCRLFuzzOutput(input)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f["severity"] != "high" {
			t.Errorf("severity = %v, want high", f["severity"])
		}
		if f["category"] != "crlf_injection" {
			t.Errorf("category = %v", f["category"])
		}
	}
}

// TestParseCRLFuzzOutput_BlankLinesSkipped — crlfuzz sometimes prints
// trailing newlines / interleaved blanks; the parser should skip them
// without emitting empty findings.
func TestParseCRLFuzzOutput_BlankLinesSkipped(t *testing.T) {
	input := "\n\nhttps://x/?p=%0a\n\n   \n"
	findings := parseCRLFuzzOutput(input)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (%+v)", len(findings), findings)
	}
	if findings[0]["url"] != "https://x/?p=%0a" {
		t.Errorf("url = %v", findings[0]["url"])
	}
}

func TestParseCRLFuzzOutput_EmptyReturnsNil(t *testing.T) {
	for _, c := range []string{"", "\n\n", "   "} {
		if got := parseCRLFuzzOutput(c); got != nil {
			t.Errorf("input %q should produce nil, got %v", c, got)
		}
	}
}

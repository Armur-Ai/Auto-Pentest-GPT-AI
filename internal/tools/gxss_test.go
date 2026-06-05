package tools

import "testing"

func TestGXSSTool_Name(t *testing.T) {
	if n := NewGXSSTool().Name(); n != "gxss" {
		t.Errorf("Name() = %q, want \"gxss\"", n)
	}
}

func TestGXSSTool_IsAvailable(t *testing.T) { _ = NewGXSSTool().IsAvailable() }

// TestParseGXSSOutput_OneFindingPerReflectedURL — gxss prints one URL
// per line for reflected inputs. Each gets a MEDIUM finding tagged
// reflected_input — the agent should pair with dalfox to escalate.
func TestParseGXSSOutput_OneFindingPerReflectedURL(t *testing.T) {
	out := `https://target.example.com/?q=GxsS
https://target.example.com/search?term=GxsS
`
	findings := parseGXSSOutput(out)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f["severity"] != "medium" {
			t.Errorf("severity = %v, want medium", f["severity"])
		}
		if f["category"] != "reflected_input" {
			t.Errorf("category = %v", f["category"])
		}
	}
}

func TestParseGXSSOutput_BlankLinesSkipped(t *testing.T) {
	out := "\n\nhttps://x/?p=a\n  \n"
	findings := parseGXSSOutput(out)
	if len(findings) != 1 || findings[0]["url"] != "https://x/?p=a" {
		t.Errorf("blank lines not handled correctly: %+v", findings)
	}
}

func TestParseGXSSOutput_EmptyReturnsNil(t *testing.T) {
	for _, c := range []string{"", "\n", "  "} {
		if got := parseGXSSOutput(c); got != nil {
			t.Errorf("input %q should produce nil, got %v", c, got)
		}
	}
}

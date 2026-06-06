package tools

import "testing"

func TestPacuTool_Name(t *testing.T) {
	if n := NewPacuTool().Name(); n != "pacu" {
		t.Errorf("Name() = %q, want \"pacu\"", n)
	}
}

func TestPacuTool_IsAvailable(t *testing.T) { _ = NewPacuTool().IsAvailable() }

// TestParsePacuOutput_WrapsRawOutput — pacu modules vary too much in
// output shape for per-module structured parsing, so the adapter
// surfaces a single coarse-grained finding carrying the raw text +
// module name. Verify that shape.
func TestParsePacuOutput_WrapsRawOutput(t *testing.T) {
	output := "  [+] Privilege escalation possible via iam:CreatePolicyVersion\n  [+] User 'low-priv' can escalate to admin\n"
	findings := parsePacuOutput(output, "iam__privesc_scan")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f["module"] != "iam__privesc_scan" {
		t.Errorf("module = %v", f["module"])
	}
	if f["category"] != "aws_enumeration" {
		t.Errorf("category = %v", f["category"])
	}
	if f["raw"] != output {
		t.Errorf("raw output not preserved")
	}
}

// TestParsePacuOutput_EmptyReturnsNil — empty output means the
// module ran but found nothing; should produce nil so the swarm
// distinguishes "no findings" from "empty-but-truthy finding".
func TestParsePacuOutput_EmptyReturnsNil(t *testing.T) {
	for _, c := range []string{"", "  \n  ", "\t\n"} {
		if got := parsePacuOutput(c, "any_module"); got != nil {
			t.Errorf("input %q should produce nil, got %v", c, got)
		}
	}
}

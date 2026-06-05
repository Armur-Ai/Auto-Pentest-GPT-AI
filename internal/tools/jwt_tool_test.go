package tools

import "testing"

// TestJWTTool_Name — adapter advertises "jwt_tool" exactly. The
// underscore matches the upstream binary name and the plan's 2.1.11
// identifier; a typo here would mean scope guards + coordinator lookup
// silently skip the tool's findings.
func TestJWTTool_Name(t *testing.T) {
	if n := NewJWTTool().Name(); n != "jwt_tool" {
		t.Errorf("Name() = %q, want \"jwt_tool\"", n)
	}
}

// TestJWTTool_IsAvailable — value is host-dependent, just exercises
// the code path so a future refactor doesn't panic.
func TestJWTTool_IsAvailable(t *testing.T) {
	_ = NewJWTTool().IsAvailable()
}

// TestParseJWTToolOutput_VulnLineParsed — jwt_tool's verbose plaintext
// flags exploitable findings with "(VULN)" or "[+] ..." prefixes; the
// parser surfaces those as structured findings with severity=high.
func TestParseJWTToolOutput_VulnLineParsed(t *testing.T) {
	input := `[*] Running All Tests
[+] alg:none accepted, signature stripped: vulnerable
[-] Token signature is valid
[+] kid SQL injection (VULN)
`
	findings := parseJWTToolOutput(input)
	if len(findings) != 2 {
		t.Fatalf("expected 2 vuln findings, got %d (%+v)", len(findings), findings)
	}
	for _, f := range findings {
		if f["severity"] != "high" {
			t.Errorf("severity = %v, want high", f["severity"])
		}
		if f["tool"] != "jwt_tool" {
			t.Errorf("tool = %v, want jwt_tool", f["tool"])
		}
	}
}

// TestParseJWTToolOutput_BenignIgnored — when jwt_tool reports no
// vulnerability, the parser returns nil rather than fabricating empty
// findings.
func TestParseJWTToolOutput_BenignIgnored(t *testing.T) {
	cases := []string{
		"",
		"   \n  \n",
		"[*] Running test\n[-] Token signature is valid\n[*] Done.",
	}
	for _, c := range cases {
		if got := parseJWTToolOutput(c); got != nil {
			t.Errorf("input %q produced %d findings, want nil", c, len(got))
		}
	}
}

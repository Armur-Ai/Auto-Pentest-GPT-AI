package taxonomy

import "testing"

func TestLookup(t *testing.T) {
	cases := []struct {
		name      string
		category  string
		title     string
		wantOWASP string
		wantCWE   string
		wantOK    bool
	}{
		{"sqli lowercase", "sqli", "", "A03:2021-Injection", "CWE-89", true},
		{"SQLi mixed case", "SQLi", "", "A03:2021-Injection", "CWE-89", true},
		{"xss from title", "", "Reflected XSS in /profile", "A03:2021-Injection", "CWE-79", true},
		{"ssrf", "SSRF", "", "A10:2021-Server-Side Request Forgery", "CWE-918", true},
		{"idor", "idor", "", "A01:2021-Broken Access Control", "CWE-639", true},
		{"path traversal", "", "Directory traversal to /etc/passwd", "A01:2021-Broken Access Control", "CWE-22", true},
		{"deserialization", "insecure deserialization", "", "A08:2021-Software and Data Integrity Failures", "CWE-502", true},
		{"outdated component", "", "Outdated jQuery 1.12.4 (CVE-2020-11022)", "A06:2021-Vulnerable and Outdated Components", "CWE-1035", true},
		{"security header", "", "Missing X-Frame-Options header", "A05:2021-Security Misconfiguration", "CWE-693", true},
		{"exposed git", "", "Exposed .git directory", "A05:2021-Security Misconfiguration", "CWE-200", true},
		{"unknown", "some-novel-thing", "totally unrelated", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tag, ok := Lookup(c.category, c.title)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (tag %+v)", ok, c.wantOK, tag)
			}
			if ok && (tag.OWASP != c.wantOWASP || tag.CWE != c.wantCWE) {
				t.Errorf("tag = %+v, want {%s %s}", tag, c.wantOWASP, c.wantCWE)
			}
		})
	}
}

// TestLookup_ATTACK checks the MITRE ATT&CK mapping: defensible techniques
// where they exist, empty (no invented precision) where they don't.
func TestLookup_ATTACK(t *testing.T) {
	if tag, _ := Lookup("sqli", ""); tag.Attack != "T1190 Exploit Public-Facing Application" {
		t.Errorf("sqli ATT&CK = %q, want T1190", tag.Attack)
	}
	if tag, _ := Lookup("xss", ""); tag.Attack != "T1059.007 Command and Scripting Interpreter: JavaScript" {
		t.Errorf("xss ATT&CK = %q, want T1059.007", tag.Attack)
	}
	// CSRF has an OWASP/CWE mapping but no clean ATT&CK technique — must be empty.
	if tag, ok := Lookup("csrf", ""); !ok || tag.Attack != "" {
		t.Errorf("csrf should map OWASP/CWE with empty ATT&CK, got %+v ok=%v", tag, ok)
	}
}

// TestWordMatch_NoSubstringFalsePositives pins the whole-word boundary: short
// tokens must not match inside larger words.
func TestWordMatch_NoSubstringFalsePositives(t *testing.T) {
	// "rce" inside "resource" must NOT classify as command injection.
	if _, ok := Lookup("", "resource enumeration on the api"); ok {
		t.Error("'resource' should not match the 'rce' keyword")
	}
	// "ssl" as a whole word should still match.
	if tag, ok := Lookup("", "weak ssl configuration"); !ok || tag.CWE != "CWE-311" {
		t.Errorf("'ssl' should match crypto failures, got %+v ok=%v", tag, ok)
	}
}

// Package taxonomy maps a finding's (free-form) attack category and title
// onto the industry-standard labels security teams triage by: an OWASP
// Top 10 (2021) category and a CWE id. The classifier's `attack_category`
// is LLM-produced and inconsistent ("SQLi" / "sqli" / "XSS"), so lookups
// normalize and match on whole words rather than exact strings.
//
// Plan reference: D.10.1.
package taxonomy

import "strings"

// Tag is the standardized labelling for a finding.
type Tag struct {
	OWASP string // e.g. "A03:2021-Injection"
	CWE   string // e.g. "CWE-89"
	// Attack is a MITRE ATT&CK (Enterprise) technique, "Tid Name" (e.g.
	// "T1190 Exploit Public-Facing Application"). Empty when there's no
	// defensible mapping — ATT&CK is TTP-oriented and many web-vuln classes
	// don't map cleanly, so we leave it blank rather than invent precision.
	Attack string
}

// entry is one mapping rule: if any keyword appears (as a whole word) in the
// normalized "category + title" text, the finding gets this tag. Ordered
// most-specific first — the first matching entry wins.
type entry struct {
	keywords []string
	tag      Tag
}

const attackExploitApp = "T1190 Exploit Public-Facing Application"

var table = []entry{
	// Injection family (OWASP A03)
	{[]string{"sql injection", "sqli"}, Tag{"A03:2021-Injection", "CWE-89", attackExploitApp}},
	{[]string{"cross-site scripting", "xss"}, Tag{"A03:2021-Injection", "CWE-79", "T1059.007 Command and Scripting Interpreter: JavaScript"}},
	{[]string{"command injection", "os command", "rce", "remote code execution"}, Tag{"A03:2021-Injection", "CWE-78", attackExploitApp}},
	{[]string{"template injection", "ssti"}, Tag{"A03:2021-Injection", "CWE-1336", attackExploitApp}},
	{[]string{"code injection"}, Tag{"A03:2021-Injection", "CWE-94", attackExploitApp}},
	{[]string{"ldap injection"}, Tag{"A03:2021-Injection", "CWE-90", attackExploitApp}},
	{[]string{"crlf"}, Tag{"A03:2021-Injection", "CWE-93", attackExploitApp}},

	// SSRF (A10) — check before generic "request" words
	{[]string{"server-side request forgery", "ssrf"}, Tag{"A10:2021-Server-Side Request Forgery", "CWE-918", attackExploitApp}},

	// Deserialization / integrity (A08)
	{[]string{"insecure deserialization", "deserialization", "deserialisation"}, Tag{"A08:2021-Software and Data Integrity Failures", "CWE-502", attackExploitApp}},

	// Broken access control (A01)
	{[]string{"path traversal", "directory traversal", "local file inclusion", "lfi"}, Tag{"A01:2021-Broken Access Control", "CWE-22", "T1083 File and Directory Discovery"}},
	{[]string{"idor", "insecure direct object", "bola", "broken object level"}, Tag{"A01:2021-Broken Access Control", "CWE-639", attackExploitApp}},
	{[]string{"csrf", "cross-site request forgery"}, Tag{"A01:2021-Broken Access Control", "CWE-352", ""}},
	{[]string{"open redirect"}, Tag{"A01:2021-Broken Access Control", "CWE-601", ""}},
	{[]string{"privilege escalation", "broken access", "authorization", "authorisation"}, Tag{"A01:2021-Broken Access Control", "CWE-284", "T1068 Exploitation for Privilege Escalation"}},

	// Auth failures (A07)
	{[]string{"authentication", "auth bypass", "weak password", "brute force", "credential stuffing", "jwt"}, Tag{"A07:2021-Identification and Authentication Failures", "CWE-287", "T1078 Valid Accounts"}},

	// Cryptographic failures (A02)
	{[]string{"cryptograph", "weak cipher", "cleartext", "tls", "ssl", "sensitive data exposure"}, Tag{"A02:2021-Cryptographic Failures", "CWE-311", "T1040 Network Sniffing"}},

	// Vulnerable & outdated components (A06)
	{[]string{"outdated", "vulnerable component", "known cve", "cve-", "end-of-life", "eol"}, Tag{"A06:2021-Vulnerable and Outdated Components", "CWE-1035", attackExploitApp}},

	// XXE — merged into Security Misconfiguration in 2021 (A05)
	{[]string{"xxe", "xml external entity"}, Tag{"A05:2021-Security Misconfiguration", "CWE-611", attackExploitApp}},

	// File upload
	{[]string{"unrestricted upload", "file upload"}, Tag{"A05:2021-Security Misconfiguration", "CWE-434", attackExploitApp}},

	// Missing/weak security headers
	{[]string{"security header", "missing header", "x-frame-options", "hsts", "content-security-policy", "clickjack"}, Tag{"A05:2021-Security Misconfiguration", "CWE-693", ""}},

	// Information disclosure
	{[]string{".git", "information disclosure", "info disclosure", "data exposure", "verbose error", "stack trace"}, Tag{"A05:2021-Security Misconfiguration", "CWE-200", ""}},

	// Generic misconfiguration
	{[]string{"misconfiguration", "default credential", "directory listing", "exposed"}, Tag{"A05:2021-Security Misconfiguration", "CWE-16", ""}},

	// Logging & monitoring (A09)
	{[]string{"logging", "monitoring"}, Tag{"A09:2021-Security Logging and Monitoring Failures", "CWE-778", ""}},
}

// Lookup returns the standardized tag for a finding's category + title, and
// ok=false when nothing matches (callers should leave the finding untagged
// rather than guess). Both inputs are considered so a vague category can
// still be classified from the title.
func Lookup(category, title string) (Tag, bool) {
	hay := strings.ToLower(category + " " + title)
	for _, e := range table {
		for _, kw := range e.keywords {
			if wordMatch(hay, kw) {
				return e.tag, true
			}
		}
	}
	return Tag{}, false
}

// wordMatch reports whether kw appears in hay bounded by non-alphanumeric
// characters (or string ends), so short tokens like "rce" don't match
// inside "resource" and "xss" doesn't match inside a longer identifier.
func wordMatch(hay, kw string) bool {
	from := 0
	for {
		i := strings.Index(hay[from:], kw)
		if i < 0 {
			return false
		}
		i += from
		beforeOK := i == 0 || !isAlnum(hay[i-1])
		end := i + len(kw)
		afterOK := end >= len(hay) || !isAlnum(hay[end])
		if beforeOK && afterOK {
			return true
		}
		from = i + 1
	}
}

func isAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

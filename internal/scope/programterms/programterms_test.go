package programterms

import "testing"

func TestParse_NoAutomatedScanning(t *testing.T) {
	c := Parse("Researchers must not use automated scanners against this program.")
	if !c.NoAutomatedScanning {
		t.Error("expected NoAutomatedScanning=true")
	}
}

func TestParse_RateLimit(t *testing.T) {
	cases := map[string]float64{
		"Please limit your requests to 5 requests per second.": 5.0,
		"Do not exceed 60 requests per minute.":                1.0,
		"Maximum 3600 req/hour for any single endpoint.":       1.0,
	}
	for in, want := range cases {
		got := Parse(in).MaxRequestsPerSecond
		if got < want-0.01 || got > want+0.01 {
			t.Errorf("Parse(%q).RPS = %.4f, want %.4f", in, got, want)
		}
	}
}

func TestParse_DisallowedTechniques(t *testing.T) {
	policy := `
		Out of scope:
		- No brute force attacks
		- No denial of service or stress testing
		- No social engineering of employees
		- No physical security testing
	`
	c := Parse(policy)
	if !c.NoBruteForce {
		t.Error("expected NoBruteForce")
	}
	if !c.NoDoS {
		t.Error("expected NoDoS")
	}
	if !c.NoSocialEngineering {
		t.Error("expected NoSocialEngineering")
	}
	if !c.NoPhysical {
		t.Error("expected NoPhysical")
	}
}

func TestParse_RequiredHeader(t *testing.T) {
	policy := "Include the header `X-Bugbounty-User: yourname` on every request."
	c := Parse(policy)
	if got := c.RequiredHeaders["X-Bugbounty-User"]; got != "yourname" {
		t.Errorf("expected required header X-Bugbounty-User=yourname, got %q", got)
	}
}

func TestParse_DisallowedPath(t *testing.T) {
	policy := "Do not scan /admin and /internal/api"
	c := Parse(policy)
	if len(c.DisallowedPaths) == 0 {
		t.Fatal("expected at least one disallowed path")
	}
}

func TestParse_EmptyPolicyIsZero(t *testing.T) {
	c := Parse("")
	if c.NoAutomatedScanning || c.NoBruteForce || c.NoDoS {
		t.Error("empty policy should yield zero constraints")
	}
}

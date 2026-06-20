package tools

import "testing"

func TestKubeHunterTool_Name(t *testing.T) {
	if n := NewKubeHunterTool().Name(); n != "kube_hunter" {
		t.Errorf("Name() = %q, want \"kube_hunter\"", n)
	}
}

func TestKubeHunterTool_IsAvailable(t *testing.T) { _ = NewKubeHunterTool().IsAvailable() }

// TestParseKubeHunterJSON_VulnerabilitiesEmitted — kube-hunter emits
// per-vulnerability records with vid/category/severity/location.
// Parser carries those through as individual findings.
func TestParseKubeHunterJSON_VulnerabilitiesEmitted(t *testing.T) {
	input := []byte(`{
		"vulnerabilities": [
			{
				"location": "10.0.0.5:10250",
				"vid": "KHV041",
				"category": "Remote Code Execution",
				"severity": "high",
				"vulnerability": "Anonymous Authentication",
				"description": "The kubelet is configured to allow anonymous requests.",
				"evidence": "anonymous-auth=true",
				"hunter": "Kubelet API"
			},
			{
				"location": "10.0.0.5:8001",
				"vid": "KHV002",
				"category": "Information Disclosure",
				"severity": "medium",
				"vulnerability": "Kubernetes Dashboard exposed",
				"description": "Dashboard is reachable",
				"hunter": "Dashboard Hunter"
			}
		]
	}`)
	findings := parseKubeHunterJSON(input)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f["tool"] != "kube_hunter" {
			t.Errorf("tool = %v", f["tool"])
		}
	}
	if findings[0]["severity"] != "high" || findings[0]["vid"] != "KHV041" {
		t.Errorf("first finding shape wrong: %+v", findings[0])
	}
}

// TestParseKubeHunterJSON_EmptyVulns — kube-hunter ran but found
// nothing; parser produces empty (not nil) — or nil — but never panics.
func TestParseKubeHunterJSON_EmptyVulns(t *testing.T) {
	input := []byte(`{"vulnerabilities": []}`)
	if got := parseKubeHunterJSON(input); len(got) != 0 {
		t.Errorf("empty vulns should produce no findings; got %d", len(got))
	}
}

func TestParseKubeHunterJSON_MalformedReturnsNil(t *testing.T) {
	for _, c := range [][]byte{nil, []byte(""), []byte("{not json"), []byte("garbage")} {
		if got := parseKubeHunterJSON(c); got != nil {
			t.Errorf("input %q should produce nil, got %v", c, got)
		}
	}
}

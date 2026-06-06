package tools

import "testing"

func TestScoutSuiteTool_Name(t *testing.T) {
	if n := NewScoutSuiteTool().Name(); n != "scoutsuite" {
		t.Errorf("Name() = %q, want \"scoutsuite\"", n)
	}
}

func TestScoutSuiteTool_IsAvailable(t *testing.T) { _ = NewScoutSuiteTool().IsAvailable() }

// TestParseScoutSuiteJS_StripsAssignmentWrapper — scout's report
// file isn't pure JSON; it's `scoutsuite_results = {...}`. The
// parser must strip the `<varname> =` prefix (and optional trailing
// semicolon) before unmarshalling.
func TestParseScoutSuiteJS_StripsAssignmentWrapper(t *testing.T) {
	input := []byte(`scoutsuite_results = {
		"services": {
			"s3": {
				"findings": {
					"s3-bucket-allowing-public-read": {
						"description": "S3 bucket allowing public read",
						"level": "danger",
						"flagged_items": ["leaky.s3.amazonaws.com", "more-leaky.s3.amazonaws.com"]
					},
					"s3-bucket-versioning-disabled": {
						"description": "Versioning disabled",
						"level": "warning",
						"flagged_items": ["leaky.s3.amazonaws.com"]
					},
					"s3-some-passing-check": {
						"description": "Check that passed",
						"level": "warning",
						"flagged_items": []
					}
				}
			}
		}
	};`)
	findings := parseScoutSuiteJS(input, "aws")
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (passing check filtered), got %d", len(findings))
	}
	// danger → high, warning → medium
	var high, medium int
	for _, f := range findings {
		if f["service"] != "s3" {
			t.Errorf("service = %v", f["service"])
		}
		if f["provider"] != "aws" {
			t.Errorf("provider = %v", f["provider"])
		}
		switch f["severity"] {
		case "high":
			high++
		case "medium":
			medium++
		}
	}
	if high != 1 || medium != 1 {
		t.Errorf("severity breakdown wrong: high=%d medium=%d (want 1/1)", high, medium)
	}
}

// TestParseScoutSuiteJS_MultipleServices — scout walks every cloud
// service; checks must come back grouped by service correctly.
func TestParseScoutSuiteJS_MultipleServices(t *testing.T) {
	input := []byte(`scoutsuite_results = {"services": {
		"iam": {"findings": {"iam-user-no-mfa": {"description": "no mfa", "level": "danger", "flagged_items": ["alice"]}}},
		"ec2": {"findings": {"ec2-sg-open-to-world": {"description": "0.0.0.0/0", "level": "danger", "flagged_items": ["sg-123"]}}}
	}}`)
	findings := parseScoutSuiteJS(input, "aws")
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	services := map[string]bool{}
	for _, f := range findings {
		services[f["service"].(string)] = true
	}
	for _, svc := range []string{"iam", "ec2"} {
		if !services[svc] {
			t.Errorf("missing service: %s", svc)
		}
	}
}

func TestParseScoutSuiteJS_MalformedReturnsNil(t *testing.T) {
	for _, c := range [][]byte{nil, []byte(""), []byte("no equals sign here"), []byte("x = {broken"), []byte("scoutsuite_results = not json")} {
		if got := parseScoutSuiteJS(c, "aws"); got != nil {
			t.Errorf("input %q should produce nil, got %v", c, got)
		}
	}
}

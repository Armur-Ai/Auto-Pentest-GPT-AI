package tools

import "testing"

func TestCheckovTool_Name(t *testing.T) {
	if n := NewCheckovTool().Name(); n != "checkov" {
		t.Errorf("Name() = %q, want \"checkov\"", n)
	}
}

func TestCheckovTool_IsAvailable(t *testing.T) { _ = NewCheckovTool().IsAvailable() }

// TestParseCheckovJSON_SingleFramework — single-framework run emits
// a single top-level object; verify failed_checks become findings
// with severity falling back to "medium" when checkov omits it.
func TestParseCheckovJSON_SingleFramework(t *testing.T) {
	input := `{
		"check_type": "terraform",
		"results": {
			"failed_checks": [
				{
					"check_id": "CKV_AWS_20",
					"check_name": "S3 Bucket should not allow public READ access",
					"file_path": "/main.tf",
					"file_line_range": [10, 25],
					"resource": "aws_s3_bucket.public",
					"severity": "HIGH"
				},
				{
					"check_id": "CKV_AWS_21",
					"check_name": "S3 Bucket should have versioning enabled",
					"file_path": "/main.tf",
					"file_line_range": [10, 25],
					"resource": "aws_s3_bucket.public"
				}
			]
		}
	}`
	findings := parseCheckovJSON(input)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f["framework"] != "terraform" {
			t.Errorf("framework = %v", f["framework"])
		}
		if f["tool"] != "checkov" {
			t.Errorf("tool = %v", f["tool"])
		}
	}
	if findings[0]["severity"] != "high" {
		t.Errorf("severity (explicit HIGH) should lowercase to high; got %v", findings[0]["severity"])
	}
	if findings[1]["severity"] != "medium" {
		t.Errorf("severity (missing) should fall back to medium; got %v", findings[1]["severity"])
	}
}

// TestParseCheckovJSON_MultiFramework — multi-framework run wraps
// the per-framework reports in a top-level array; both branches of
// the parser must yield findings.
func TestParseCheckovJSON_MultiFramework(t *testing.T) {
	input := `[
		{"check_type": "terraform", "results": {"failed_checks": [
			{"check_id": "CKV_AWS_1", "check_name": "tf check", "file_path": "/a.tf", "file_line_range": [1,2], "resource": "r1"}
		]}},
		{"check_type": "kubernetes", "results": {"failed_checks": [
			{"check_id": "CKV_K8S_1", "check_name": "k8s check", "file_path": "/p.yml", "file_line_range": [1,5], "resource": "r2"}
		]}}
	]`
	findings := parseCheckovJSON(input)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings across frameworks, got %d", len(findings))
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f["framework"].(string)] = true
	}
	for _, fw := range []string{"terraform", "kubernetes"} {
		if !got[fw] {
			t.Errorf("missing framework: %s", fw)
		}
	}
}

func TestParseCheckovJSON_MalformedReturnsNil(t *testing.T) {
	for _, c := range []string{"", "{not json}", "garbage", "  \n"} {
		if got := parseCheckovJSON(c); got != nil {
			t.Errorf("input %q should produce nil, got %v", c, got)
		}
	}
}

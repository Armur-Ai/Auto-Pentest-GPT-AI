package tools

import "testing"

func TestProwlerTool_Name(t *testing.T) {
	if n := NewProwlerTool().Name(); n != "prowler" {
		t.Errorf("Name() = %q, want \"prowler\"", n)
	}
}

func TestProwlerTool_IsAvailable(t *testing.T) { _ = NewProwlerTool().IsAvailable() }

// TestParseProwlerJSON_FAILSurvivesPASSFiltered — prowler's OCSF
// output mixes PASS and FAIL events. The parser must emit one
// finding per FAIL and drop the PASS entries so the LLM only sees
// actual misconfigurations.
func TestParseProwlerJSON_FAILSurvivesPASSFiltered(t *testing.T) {
	input := []byte(`[
		{
			"status_code": 1,
			"status_detail": "PASS",
			"severity": "Medium",
			"message": "Bucket encryption enabled",
			"metadata": {"event_code": "s3_bucket_default_encryption"}
		},
		{
			"status_code": 2,
			"status_detail": "FAIL",
			"severity": "High",
			"message": "Bucket allows public read",
			"resources": [{"uid": "arn:aws:s3:::leaky-bucket", "type": "AwsS3Bucket", "region": "us-east-1"}],
			"metadata": {"event_code": "s3_bucket_public_access"},
			"remediation": {"desc": "Disable public access block"}
		},
		{
			"status_code": 2,
			"status_detail": "FAIL",
			"severity": "Critical",
			"message": "Root account has access keys",
			"resources": [{"uid": "arn:aws:iam::123:user/root", "type": "AwsIamUser", "region": "global"}],
			"metadata": {"event_code": "iam_root_access_keys"},
			"remediation": {"desc": "Delete root access keys"}
		}
	]`)
	findings := parseProwlerJSON(input)
	if len(findings) != 2 {
		t.Fatalf("expected 2 FAIL findings (PASS filtered), got %d", len(findings))
	}
	for _, f := range findings {
		if f["tool"] != "prowler" {
			t.Errorf("tool = %v", f["tool"])
		}
		if f["severity"] == "high" {
			if f["check_id"] != "s3_bucket_public_access" {
				t.Errorf("wrong check id: %v", f["check_id"])
			}
		}
		if f["severity"] == "critical" {
			if f["region"] != "global" {
				t.Errorf("region not preserved: %v", f["region"])
			}
		}
	}
}

// TestParseProwlerJSON_FAILWithoutResources — prowler can emit a
// FAIL event with no resources block (account-wide config issues
// like "Password policy too weak"). Adapter must still emit the
// finding with check_id + message + severity, just without
// resource_uid metadata.
func TestParseProwlerJSON_FAILWithoutResources(t *testing.T) {
	input := []byte(`[{
		"status_code": 2,
		"status_detail": "FAIL",
		"severity": "Medium",
		"message": "Password policy missing",
		"metadata": {"event_code": "iam_password_policy_minimum_length"}
	}]`)
	findings := parseProwlerJSON(input)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0]["check_id"] != "iam_password_policy_minimum_length" {
		t.Errorf("check_id = %v", findings[0]["check_id"])
	}
	if _, ok := findings[0]["resource_uid"]; ok {
		t.Errorf("resource_uid should not be set for resource-less finding")
	}
}

func TestParseProwlerJSON_MalformedReturnsNil(t *testing.T) {
	for _, c := range [][]byte{nil, []byte(""), []byte("{not json"), []byte("garbage")} {
		if got := parseProwlerJSON(c); got != nil {
			t.Errorf("input %q should produce nil, got %v", c, got)
		}
	}
}

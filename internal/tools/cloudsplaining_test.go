package tools

import "testing"

func TestCloudsplainingTool_Name(t *testing.T) {
	if n := NewCloudsplainingTool().Name(); n != "cloudsplaining" {
		t.Errorf("Name() = %q, want \"cloudsplaining\"", n)
	}
}

func TestCloudsplainingTool_IsAvailable(t *testing.T) { _ = NewCloudsplainingTool().IsAvailable() }

// TestParseCloudsplainingJSON_AllCategoriesEmitted — cloudsplaining
// flags five risk categories per policy. Each non-empty category
// becomes one finding with the documented severity.
func TestParseCloudsplainingJSON_AllCategoriesEmitted(t *testing.T) {
	input := []byte(`{
		"results": {
			"policy-arn-1": {
				"PolicyName": "AdminEverything",
				"PolicyType": "Customer",
				"PrivilegeEscalation": [{"type": "iam_CreateAccessKey", "actions": ["iam:CreateAccessKey"]}],
				"DataExfiltration": ["s3:GetObject", "dynamodb:Scan"],
				"ResourceExposure": ["s3:PutBucketPolicy"],
				"CredentialsExposure": ["iam:CreateAccessKey"],
				"InfrastructureModification": ["ec2:RunInstances"]
			}
		}
	}`)
	findings := parseCloudsplainingJSON(input)
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings (one per category), got %d", len(findings))
	}

	severities := map[string]string{}
	for _, f := range findings {
		severities[f["category"].(string)] = f["severity"].(string)
		if f["policy"] != "AdminEverything" {
			t.Errorf("policy = %v", f["policy"])
		}
	}
	expected := map[string]string{
		"privilege_escalation":         "high",
		"data_exfiltration":            "high",
		"resource_exposure":            "high",
		"credentials_exposure":         "critical",
		"infrastructure_modification":  "medium",
	}
	for cat, want := range expected {
		if got := severities[cat]; got != want {
			t.Errorf("category %s severity = %q, want %q", cat, got, want)
		}
	}
}

// TestParseCloudsplainingJSON_EmptyCategoriesSkipped — a policy may
// only have risks in one or two categories; the parser must not emit
// empty/no-action findings for the others.
func TestParseCloudsplainingJSON_EmptyCategoriesSkipped(t *testing.T) {
	input := []byte(`{
		"results": {
			"benign-policy": {
				"PolicyName": "ReadOnlyAccess",
				"PolicyType": "AWS",
				"PrivilegeEscalation": [],
				"DataExfiltration": ["s3:GetObject"],
				"ResourceExposure": [],
				"CredentialsExposure": [],
				"InfrastructureModification": []
			}
		}
	}`)
	findings := parseCloudsplainingJSON(input)
	if len(findings) != 1 {
		t.Fatalf("expected only 1 finding (data_exfiltration), got %d", len(findings))
	}
	if findings[0]["category"] != "data_exfiltration" {
		t.Errorf("category = %v", findings[0]["category"])
	}
}

func TestParseCloudsplainingJSON_MalformedReturnsNil(t *testing.T) {
	for _, c := range [][]byte{nil, []byte(""), []byte("{not json"), []byte("garbage")} {
		if got := parseCloudsplainingJSON(c); got != nil {
			t.Errorf("input %q should produce nil, got %v", c, got)
		}
	}
}

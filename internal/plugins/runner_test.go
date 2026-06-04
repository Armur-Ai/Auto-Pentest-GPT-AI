package plugins

import (
	"strings"
	"testing"
)

func TestResolveVariables_SeedsTargetDomainFromTargetFlag(t *testing.T) {
	pb := &Playbook{
		Variables: map[string]Variable{
			"target_domain": {Type: "string", Required: true},
		},
	}
	got, err := resolveVariables(pb, "example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["target_domain"] != "example.com" {
		t.Fatalf("target_domain not seeded from --target; got %q", got["target_domain"])
	}
}

func TestResolveVariables_CallerOverrideWins(t *testing.T) {
	pb := &Playbook{
		Variables: map[string]Variable{
			"target_domain": {Type: "string", Required: true},
		},
	}
	got, err := resolveVariables(pb, "example.com", map[string]string{
		"target_domain": "explicit.invalid",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["target_domain"] != "explicit.invalid" {
		t.Fatalf("caller-supplied value should win; got %q", got["target_domain"])
	}
}

func TestResolveVariables_DefaultFillsMissingRequired(t *testing.T) {
	pb := &Playbook{
		Variables: map[string]Variable{
			"target_domain": {Type: "string", Required: true},
			"depth":         {Type: "string", Required: true, Default: "2"},
		},
	}
	got, err := resolveVariables(pb, "example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["depth"] != "2" {
		t.Fatalf("depth default not applied; got %q", got["depth"])
	}
}

func TestResolveVariables_MissingRequiredErrors(t *testing.T) {
	pb := &Playbook{
		Variables: map[string]Variable{
			"api_token": {Type: "string", Required: true},
		},
	}
	_, err := resolveVariables(pb, "example.com", nil)
	if err == nil {
		t.Fatal("expected error for missing required variable")
	}
	if !strings.Contains(err.Error(), "api_token") {
		t.Fatalf("error should name the missing variable; got %v", err)
	}
}

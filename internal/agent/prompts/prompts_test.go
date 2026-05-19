package prompts

import (
	"strings"
	"testing"
)

func TestLoad_OffsecSystem(t *testing.T) {
	out, err := Load("offsec_system", Context{
		Engagement: "HackerOne program H1-12345",
		Scope:      "*.example.com",
		Role:       "exploit",
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.Contains(out, "HackerOne program H1-12345") {
		t.Errorf("rendered prompt should include engagement context")
	}
	if !strings.Contains(out, "*.example.com") {
		t.Errorf("rendered prompt should include scope")
	}
	if !strings.Contains(out, "RECON") || !strings.Contains(out, "HYPOTHESIS") {
		t.Errorf("rendered prompt should include the reasoning loop")
	}
}

func TestLoad_EmptyContext(t *testing.T) {
	// Empty Context should render with neutral defaults, not error.
	out, err := Load("offsec_system", Context{})
	if err != nil {
		t.Fatalf("Load with empty context: %v", err)
	}
	if len(out) < 500 {
		t.Errorf("rendered prompt suspiciously short: %d chars", len(out))
	}
}

func TestLoad_StrictReframe(t *testing.T) {
	out, err := Load("offsec_system_strict", Context{
		Engagement: "Authorized testing",
		Scope:      "internal-app.test",
	})
	if err != nil {
		t.Fatalf("Load strict: %v", err)
	}
	if !strings.Contains(strings.ToLower(out), "authorization") {
		t.Errorf("strict template should re-emphasize authorization")
	}
}

func TestLoad_UnknownTemplate(t *testing.T) {
	_, err := Load("does_not_exist", Context{})
	if err == nil {
		t.Fatal("expected error for unknown template")
	}
}

func TestLoad_ToolsRenderedWhenProvided(t *testing.T) {
	out, err := Load("offsec_system", Context{
		Tools: []ToolDescription{
			{Name: "nmap", Description: "port scanner"},
			{Name: "sqlmap", Description: "SQL injection exploiter"},
		},
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.Contains(out, "nmap") || !strings.Contains(out, "sqlmap") {
		t.Errorf("rendered prompt should list tools")
	}
}

func TestFewShot_KnownCategory(t *testing.T) {
	msgs := FewShot(CategoryWeb, 5)
	if len(msgs) == 0 {
		t.Fatal("expected at least one example for web category")
	}
	if len(msgs)%2 != 0 {
		t.Errorf("FewShot returns user/assistant pairs; got odd count %d", len(msgs))
	}
	// First pair must be user → assistant.
	if msgs[0].Role != "user" {
		t.Errorf("first message role = %q, want user", msgs[0].Role)
	}
	if msgs[1].Role != "assistant" {
		t.Errorf("second message role = %q, want assistant", msgs[1].Role)
	}
}

func TestFewShot_ZeroLimit(t *testing.T) {
	if got := FewShot(CategoryWeb, 0); got != nil {
		t.Errorf("FewShot(_, 0) = %v, want nil", got)
	}
	if got := FewShot(CategoryWeb, -1); got != nil {
		t.Errorf("FewShot(_, -1) = %v, want nil", got)
	}
}

func TestFewShot_UnknownCategory(t *testing.T) {
	// Unknown category returns nil rather than erroring — scaffolding
	// stays optional / degrades gracefully.
	msgs := FewShot("nonexistent_category", 5)
	if msgs != nil {
		t.Errorf("unknown category should return nil, got %d messages", len(msgs))
	}
}

func TestFewShot_HonorsLimit(t *testing.T) {
	// Even if the category has 5 examples, asking for 1 returns 1 pair (2 messages).
	msgs := FewShot(CategoryWeb, 1)
	if len(msgs) != 2 {
		t.Errorf("FewShot(web, 1) returned %d messages, want 2 (one user/assistant pair)", len(msgs))
	}
}

func TestCategoryCount(t *testing.T) {
	if n := CategoryCount(CategoryWeb); n < 1 {
		t.Errorf("web category should have at least 1 example, got %d", n)
	}
	if n := CategoryCount("nonexistent"); n != 0 {
		t.Errorf("unknown category count = %d, want 0", n)
	}
}

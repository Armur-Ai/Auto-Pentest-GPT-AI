// Package llm_eval holds the evaluation harness for classifier / recon /
// exploit agent prompts.
//
// Each fixture describes:
//   - the agent under test
//   - the input the agent would see in a real campaign
//   - a rubric of assertions (severity range, CVSS range, category allow-list)
//   - a mock_response block used by the default offline runner
//
// The default eval runs everything against a mock LLM that replays the
// mock_response, validating the AGENT CODE path. The -live flag swaps in
// the real LLM provider and validates the MODEL output against the same
// rubric. Either way, failed assertions produce actionable diffs.
package llm_eval

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"go.yaml.in/yaml/v3"
)

// Fixture is the on-disk shape.
type Fixture struct {
	Name         string         `yaml:"name"`
	Agent        string         `yaml:"agent"`
	Input        map[string]any `yaml:"input"`
	Rubric       Rubric         `yaml:"rubric"`
	MockResponse map[string]any `yaml:"mock_response"`
}

// Rubric is a lightweight DSL for expressing what an agent's output should
// look like. All set fields must hold (AND semantics). Unset fields are
// ignored — so a fixture can check only severity without constraining CVSS.
type Rubric struct {
	Severity              string   `yaml:"severity,omitempty"`
	SeverityAnyOf         []string `yaml:"severity_any_of,omitempty"`
	CVSSMin               float64  `yaml:"cvss_min,omitempty"`
	CVSSMax               float64  `yaml:"cvss_max,omitempty"`
	ConfidenceAnyOf       []string `yaml:"confidence_any_of,omitempty"`
	AttackCategoryAnyOf   []string `yaml:"attack_category_any_of,omitempty"`
	ContainsInDescription string   `yaml:"contains_in_description,omitempty"`
}

// LoadFixtures reads every .yaml under dir recursively.
func LoadFixtures(dir string) ([]Fixture, error) {
	var out []Fixture
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var f Fixture
		if err := yaml.Unmarshal(data, &f); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		out = append(out, f)
		return nil
	})
	return out, err
}

// Check runs the rubric against a single classified finding. Returns the
// list of mismatches — nil means the rubric passed.
func (r Rubric) Check(f pipeline.ClassifiedFinding) []string {
	var fail []string

	if r.Severity != "" && string(f.Severity) != r.Severity {
		fail = append(fail, fmt.Sprintf("severity: want %q, got %q", r.Severity, f.Severity))
	}
	if len(r.SeverityAnyOf) > 0 && !contains(r.SeverityAnyOf, string(f.Severity)) {
		fail = append(fail, fmt.Sprintf("severity not in %v (got %q)", r.SeverityAnyOf, f.Severity))
	}
	if r.CVSSMin > 0 && f.CVSSScore < r.CVSSMin {
		fail = append(fail, fmt.Sprintf("cvss_score %.2f below min %.2f", f.CVSSScore, r.CVSSMin))
	}
	if r.CVSSMax > 0 && f.CVSSScore > r.CVSSMax {
		fail = append(fail, fmt.Sprintf("cvss_score %.2f above max %.2f", f.CVSSScore, r.CVSSMax))
	}
	if len(r.ConfidenceAnyOf) > 0 && !contains(r.ConfidenceAnyOf, string(f.Confidence)) {
		fail = append(fail, fmt.Sprintf("confidence not in %v (got %q)", r.ConfidenceAnyOf, f.Confidence))
	}
	if len(r.AttackCategoryAnyOf) > 0 && !contains(r.AttackCategoryAnyOf, f.AttackCategory) {
		fail = append(fail, fmt.Sprintf("attack_category not in %v (got %q)", r.AttackCategoryAnyOf, f.AttackCategory))
	}
	if r.ContainsInDescription != "" && !strings.Contains(strings.ToLower(f.Description), strings.ToLower(r.ContainsInDescription)) {
		fail = append(fail, fmt.Sprintf("description missing %q", r.ContainsInDescription))
	}
	return fail
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// --- Mock provider: replays the fixture's mock_response as a structured
// tool call, so the classifier's tool-use path is the one being tested.

// MockProvider implements llm.Provider by returning a canned tool call.
type MockProvider struct {
	response map[string]any
}

// NewMockProvider wraps a mock_response blob into an llm.Provider.
func NewMockProvider(resp map[string]any) *MockProvider { return &MockProvider{response: resp} }

// Complete returns a structured tool call built from the fixture.
func (m *MockProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	if m.response == nil {
		return &llm.CompletionResponse{}, nil
	}
	args, _ := json.Marshal(m.response)
	return &llm.CompletionResponse{
		ToolCalls: []llm.ToolCall{{
			ID:        "mock-1",
			Name:      "emit_classified_findings",
			Arguments: string(args),
		}},
	}, nil
}

// Stream is unused in eval but must exist to satisfy llm.Provider.
func (m *MockProvider) Stream(ctx context.Context, _ llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	ch := make(chan llm.StreamChunk)
	close(ch)
	return ch, nil
}

// HealthCheck always passes.
func (m *MockProvider) HealthCheck(ctx context.Context) error { return nil }

// ModelName identifies the mock.
func (m *MockProvider) ModelName() string { return "mock" }

// ContextWindow matches Claude to avoid spurious validation failures.
func (m *MockProvider) ContextWindow() int { return 200000 }

// SupportsToolUse returns true so the classifier takes the structured path.
func (m *MockProvider) SupportsToolUse() bool { return true }

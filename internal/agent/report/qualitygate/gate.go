// Package qualitygate runs a generated submission draft through a
// second LLM call that grades it on clarity, impact framing, and
// reproducibility. A low score blocks submission and surfaces
// actionable polish suggestions.
//
// Phase 4.4.7 of Wave 4. Researchers sometimes hit 'submit' on a draft
// that looks fine at a glance but triages poorly on the other end.
// A 30-second second-pass rubric catches most of those before they
// burn a program submission credit.
package qualitygate

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
)

// Report is the rubric result.
type Report struct {
	OverallScore         float64  `json:"overall_score"`         // 0-10
	ClarityScore         float64  `json:"clarity_score"`         // 0-10
	ImpactScore          float64  `json:"impact_score"`          // 0-10
	ReproducibilityScore float64  `json:"reproducibility_score"` // 0-10
	Suggestions          []string `json:"suggestions"`
	BlockingIssue        string   `json:"blocking_issue,omitempty"` // set when overall < threshold
}

// Threshold is the pass/fail cutoff. Below this overall score, the
// submission should NOT be filed without polish.
const Threshold = 6.0

// Pass returns true when the report should be allowed through the gate.
func (r Report) Pass() bool { return r.OverallScore >= Threshold }

var gradeTool = llm.Tool{
	Name:        "grade_submission",
	Description: "Grade a bug-bounty submission draft on clarity, impact framing, and reproducibility.",
	Parameters: json.RawMessage(`{
		"type": "object",
		"properties": {
			"overall_score":        { "type": "number", "minimum": 0, "maximum": 10 },
			"clarity_score":        { "type": "number", "minimum": 0, "maximum": 10 },
			"impact_score":         { "type": "number", "minimum": 0, "maximum": 10 },
			"reproducibility_score":{ "type": "number", "minimum": 0, "maximum": 10 },
			"suggestions":          { "type": "array", "items": {"type": "string"}, "minItems": 1 },
			"blocking_issue":       { "type": "string" }
		},
		"required": ["overall_score","clarity_score","impact_score","reproducibility_score","suggestions"]
	}`),
}

const systemPrompt = `You are a senior bug bounty triage engineer grading a draft
report before it is filed. Be tough but fair.

Grade 0-10 on three axes:
  - clarity: could a stranger reproduce + understand this on their first read?
  - impact: does 'Impact' explain real-world consequences, not just 'attacker can do X'?
  - reproducibility: are steps specific enough that triage doesn't have to guess?

overall_score is the minimum of the three — a report is only as strong
as its weakest section. Always provide at least two concrete, rewrite-
ready suggestions.

If you would flat-out refuse to file this report yourself, set
blocking_issue to a one-sentence summary of the core problem.`

// Grade runs the gate and returns a Report.
func Grade(ctx context.Context, provider llm.Provider, body string) (*Report, error) {
	if !provider.SupportsToolUse() {
		return nil, fmt.Errorf("quality gate requires a tool-use-capable provider (Claude)")
	}
	req := llm.CompletionRequest{
		SystemPrompt:      systemPrompt,
		Messages:          []llm.Message{{Role: "user", Content: "Grade this submission draft:\n\n" + body}},
		Tools:             []llm.Tool{gradeTool},
		MaxTokens:         1024,
		Temperature:       0.1,
		CacheSystemPrompt: true,
	}
	resp, err := provider.Complete(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("quality gate llm: %w", err)
	}
	if len(resp.ToolCalls) == 0 || resp.ToolCalls[0].Name != gradeTool.Name {
		return nil, fmt.Errorf("quality gate: model did not call grade_submission")
	}
	var r Report
	if err := json.Unmarshal([]byte(resp.ToolCalls[0].Arguments), &r); err != nil {
		return nil, fmt.Errorf("parse grade: %w", err)
	}
	return &r, nil
}

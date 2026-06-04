package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/tuning"
	"github.com/google/uuid"
)

// NucleiAuthorAgent drafts a nuclei template from novel classifier findings.
// Each successful authoring produces a TypeNucleiTemplateDraft finding
// whose Data payload is the proposed YAML template. A human reviewer
// (or a future auto-merge gate) decides whether to promote the draft to
// ./playbooks/nuclei-templates/.
//
// The agent only fires on findings that:
//   - classifier marked high/critical severity (worth writing a template for)
//   - don't already have a CVE id (novel — existing CVEs already have templates)
type NucleiAuthorAgent struct {
	provider   llm.Provider
	campaignID uuid.UUID
	outputDir  string
	parallel   int
	validate   bool // run `nuclei -validate` on drafts before publishing
	tun        *tuning.Settings
}

// NewNucleiAuthorAgent constructs the author. outputDir is where draft
// YAMLs land for human review; defaults to ./drafts/nuclei.
func NewNucleiAuthorAgent(provider llm.Provider, campaignID uuid.UUID, outputDir string, parallel int, validate bool, tun *tuning.Settings) *NucleiAuthorAgent {
	if outputDir == "" {
		outputDir = "drafts/nuclei"
	}
	if parallel <= 0 {
		parallel = 1
	}
	if tun == nil {
		tun = tuning.Default()
	}
	return &NucleiAuthorAgent{
		provider:   provider,
		campaignID: campaignID,
		outputDir:  outputDir,
		parallel:   parallel,
		validate:   validate,
		tun:        tun,
	}
}

// Name implements swarm.Agent.
func (a *NucleiAuthorAgent) Name() string { return "nuclei-author" }

// Trigger: high-pheromone CVE_MATCH and MISCONFIG findings.
func (a *NucleiAuthorAgent) Trigger() blackboard.Predicate {
	return blackboard.Predicate{
		Types:        []blackboard.FindingType{blackboard.TypeCVEMatch, blackboard.TypeMisconfig},
		MinPheromone: 0.7,
	}
}

// MaxConcurrency implements swarm.Agent.
func (a *NucleiAuthorAgent) MaxConcurrency() int { return a.parallel }

// nucleiAuthorTool is the structured output we ask the LLM to produce.
var nucleiAuthorTool = llm.Tool{
	Name:        "emit_nuclei_template",
	Description: "Emit a valid nuclei v3 template YAML for the input finding.",
	Parameters: json.RawMessage(`{
		"type": "object",
		"properties": {
			"template_id":  { "type": "string", "pattern": "^[a-z0-9-]+$" },
			"name":         { "type": "string" },
			"severity":     { "type": "string", "enum": ["critical","high","medium","low","info"] },
			"description":  { "type": "string" },
			"yaml":         { "type": "string", "description": "Full nuclei template YAML, ready to be written to disk" },
			"reference_urls":{ "type": "array", "items": { "type": "string" } },
			"confidence":   { "type": "string", "enum": ["high","medium","low"] }
		},
		"required": ["template_id","name","severity","yaml","confidence"]
	}`),
}

type nucleiDraft struct {
	TemplateID    string   `json:"template_id"`
	Name          string   `json:"name"`
	Severity      string   `json:"severity"`
	Description   string   `json:"description"`
	YAML          string   `json:"yaml"`
	ReferenceURLs []string `json:"reference_urls"`
	Confidence    string   `json:"confidence"`
}

// Handle generates a draft template and publishes it as a blackboard finding.
func (a *NucleiAuthorAgent) Handle(ctx context.Context, f blackboard.Finding, board blackboard.Board) error {
	var cf pipeline.ClassifiedFinding
	if err := json.Unmarshal(f.Data, &cf); err != nil {
		return fmt.Errorf("decode classified finding: %w", err)
	}
	// Skip findings that already map to a known CVE — those have official templates.
	if len(cf.CVEIDs) > 0 {
		return nil
	}

	req := llm.CompletionRequest{
		SystemPrompt: nucleiAuthorSystemPrompt,
		Messages: []llm.Message{{
			Role: "user",
			Content: fmt.Sprintf(
				"Draft a nuclei v3 template that detects this novel finding.\n\n%s",
				mustJSON(cf),
			),
		}},
		MaxTokens:         4096,
		Temperature:       0.1,
		CacheSystemPrompt: true,
	}
	if a.provider.SupportsToolUse() {
		req.Tools = []llm.Tool{nucleiAuthorTool}
	}

	resp, err := a.provider.Complete(ctx, req)
	if err != nil {
		return fmt.Errorf("nuclei author: %w", err)
	}
	if len(resp.ToolCalls) == 0 || resp.ToolCalls[0].Name != nucleiAuthorTool.Name {
		// Fallback providers: we'd need to parse the text. Skip for now.
		return nil
	}
	var d nucleiDraft
	if err := json.Unmarshal([]byte(resp.ToolCalls[0].Arguments), &d); err != nil {
		return fmt.Errorf("decode nuclei draft: %w", err)
	}

	// Persist YAML for human review.
	_ = os.MkdirAll(a.outputDir, 0o755)
	hash := sha256.Sum256([]byte(d.YAML))
	filename := filepath.Join(a.outputDir, fmt.Sprintf("%s-%s.yaml", d.TemplateID, hex.EncodeToString(hash[:4])))
	if err := os.WriteFile(filename, []byte(d.YAML), 0o644); err != nil {
		return fmt.Errorf("write draft: %w", err)
	}

	// Optionally validate with `nuclei -validate`. Rejects ill-formed drafts
	// before surfacing them so reviewers don't waste cycles.
	if a.validate {
		if _, err := exec.LookPath("nuclei"); err == nil {
			cmd := exec.CommandContext(ctx, "nuclei", "-validate", "-t", filename)
			if out, err := cmd.CombinedOutput(); err != nil {
				// Keep the file for debugging but don't publish a finding.
				return fmt.Errorf("nuclei validate rejected draft %s: %s", filename, string(out))
			}
		}
	}

	base, half := a.tun.Lookup(blackboard.TypeNucleiTemplateDraft)
	payload, _ := json.Marshal(map[string]any{
		"path":        filename,
		"template_id": d.TemplateID,
		"name":        d.Name,
		"severity":    d.Severity,
		"confidence":  d.Confidence,
		"references":  d.ReferenceURLs,
	})
	_, _ = board.Write(ctx, blackboard.Finding{
		CampaignID:    a.campaignID,
		AgentName:     a.Name(),
		Type:          blackboard.TypeNucleiTemplateDraft,
		Target:        cf.Target,
		Data:          payload,
		PheromoneBase: base,
		HalfLifeSec:   half,
	})
	return nil
}

const nucleiAuthorSystemPrompt = `You are a nuclei template author.

Given a novel security finding (one that doesn't map to an existing CVE),
write a valid nuclei v3 template that detects the same class of issue.

Requirements:
  - template_id must be lowercase-with-hyphens
  - severity must match the finding's severity exactly
  - yaml field MUST be a complete, valid nuclei v3 template, including
    id, info, and one or more http/network/dns request blocks
  - prefer matchers that are unlikely to produce false positives
  - include reference_urls when you cite public advisories

If you cannot confidently author a template (the finding is too vague,
or there's insufficient detail to write reliable matchers), respond with
confidence="low" and a minimal placeholder template flagged TODO in
info.description — the human reviewer will refine.`

func mustJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

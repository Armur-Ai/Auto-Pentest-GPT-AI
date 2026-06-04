package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/google/uuid"
)

// ClassifierAgent enriches raw findings with CVE mappings, CVSS scores, and severity.
type ClassifierAgent struct {
	provider llm.Provider
	fpFilter *FPFilter
	strict   bool
	onErr    func(error)
}

// Option customises ClassifierAgent construction.
type Option func(*ClassifierAgent)

// WithStrict makes any LLM error fatal (Classify returns the error instead
// of silently falling back to heuristic classification).
func WithStrict() Option {
	return func(c *ClassifierAgent) { c.strict = true }
}

// WithErrorSink installs a callback invoked on LLM / parse errors. Useful
// for surfacing degraded-mode warnings to the event stream.
func WithErrorSink(fn func(error)) Option {
	return func(c *ClassifierAgent) { c.onErr = fn }
}

// NewClassifierAgent creates a new classifier agent.
func NewClassifierAgent(provider llm.Provider, opts ...Option) *ClassifierAgent {
	c := &ClassifierAgent{
		provider: provider,
		fpFilter: NewFPFilter(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Classify takes raw findings and produces classified, scored, ranked findings.
func (c *ClassifierAgent) Classify(ctx context.Context, campaignID uuid.UUID, rawFindings []pipeline.RawFinding) (*pipeline.ClassifiedFindingSet, error) {
	var classified []pipeline.ClassifiedFinding
	filteredCount := 0

	for _, raw := range rawFindings {
		// Check false positive probability
		if c.fpFilter.ShouldFilter(raw) {
			filteredCount++
			continue
		}

		fpProb := c.fpFilter.Score(raw)

		classified = append(classified, pipeline.ClassifiedFinding{
			ID:                       uuid.New(),
			RawFindingID:             raw.ID,
			CampaignID:               campaignID,
			Title:                    raw.Detail,
			Description:              raw.Detail,
			Severity:                 pipeline.SeverityMedium, // will be updated by LLM
			Confidence:               pipeline.ConfidenceUnverified,
			FalsePositiveProbability: fpProb,
			Target:                   raw.Target,
			ClassifiedAt:             time.Now(),
		})
	}

	// Batch classify with LLM (groups of 20)
	batchSize := 20
	for i := 0; i < len(classified); i += batchSize {
		end := i + batchSize
		if end > len(classified) {
			end = len(classified)
		}

		batch := classified[i:end]
		enriched, err := c.classifyBatch(ctx, batch)
		if err != nil {
			if c.strict {
				return nil, fmt.Errorf("classifier batch %d-%d: %w", i, end, err)
			}
			if c.onErr != nil {
				c.onErr(fmt.Errorf("classifier degraded for batch %d-%d: %w", i, end, err))
			}
			// Heuristic classification stands; continue with next batch.
			continue
		}

		// Merge LLM results back
		for j, e := range enriched {
			if i+j < len(classified) {
				classified[i+j].Title = e.Title
				classified[i+j].Description = e.Description
				classified[i+j].CVEIDs = e.CVEIDs
				classified[i+j].CVSSScore = e.CVSSScore
				classified[i+j].CVSSVector = e.CVSSVector
				classified[i+j].Severity = e.Severity
				classified[i+j].AttackCategory = e.AttackCategory
				classified[i+j].Confidence = e.Confidence
				classified[i+j].ChainCandidates = e.ChainCandidates
			}
		}
	}

	// Sort by CVSS score descending
	sort.Slice(classified, func(i, j int) bool {
		return classified[i].CVSSScore > classified[j].CVSSScore
	})

	// Build summary
	bySeverity := make(map[pipeline.Severity]int)
	categoryCount := make(map[string]int)
	for _, f := range classified {
		bySeverity[f.Severity]++
		if f.AttackCategory != "" {
			categoryCount[f.AttackCategory]++
		}
	}

	var topCategories []string
	for cat := range categoryCount {
		topCategories = append(topCategories, cat)
	}
	sort.Slice(topCategories, func(i, j int) bool {
		return categoryCount[topCategories[i]] > categoryCount[topCategories[j]]
	})
	if len(topCategories) > 5 {
		topCategories = topCategories[:5]
	}

	return &pipeline.ClassifiedFindingSet{
		CampaignID: campaignID,
		Findings:   classified,
		Summary: pipeline.ClassificationSummary{
			TotalFindings: len(classified),
			BySeverity:    bySeverity,
			TopCategories: topCategories,
			FilteredAsFP:  filteredCount,
		},
		CreatedAt: time.Now(),
	}, nil
}

// classifierTool is the structured tool schema we ask the LLM to populate.
// Providers that advertise SupportsToolUse() get this path; others fall
// back to the legacy JSON-in-prompt path below.
var classifierTool = llm.Tool{
	Name:        "emit_classified_findings",
	Description: "Emit enriched classifications for each input finding in the same order.",
	Parameters: json.RawMessage(`{
		"type": "object",
		"properties": {
			"findings": {
				"type": "array",
				"items": {
					"type": "object",
					"properties": {
						"input_index":      { "type": "integer", "description": "0-based index matching the input array order" },
						"title":            { "type": "string" },
						"description":      { "type": "string" },
						"cve_ids":          { "type": "array", "items": { "type": "string" } },
						"cvss_score":       { "type": "number" },
						"cvss_vector":      { "type": "string" },
						"severity":         { "type": "string", "enum": ["critical","high","medium","low","informational"] },
						"attack_category":  { "type": "string" },
						"confidence":       { "type": "string", "enum": ["high","medium","low","unverified"] }
					},
					"required": ["input_index","title","severity","cvss_score","confidence"]
				}
			}
		},
		"required": ["findings"]
	}`),
}

type classifierToolOutput struct {
	Findings []struct {
		InputIndex     int      `json:"input_index"`
		Title          string   `json:"title"`
		Description    string   `json:"description"`
		CVEIDs         []string `json:"cve_ids"`
		CVSSScore      float64  `json:"cvss_score"`
		CVSSVector     string   `json:"cvss_vector"`
		Severity       string   `json:"severity"`
		AttackCategory string   `json:"attack_category"`
		Confidence     string   `json:"confidence"`
	} `json:"findings"`
}

// classifyBatch sends a batch of findings to the LLM for enrichment.
// When the provider supports tool-use (Claude), we use structured tool
// calls so the response is guaranteed-parseable. Otherwise we fall back
// to JSON-in-prompt.
func (c *ClassifierAgent) classifyBatch(ctx context.Context, findings []pipeline.ClassifiedFinding) ([]pipeline.ClassifiedFinding, error) {
	findingsJSON, _ := json.Marshal(findings)
	userMsg := fmt.Sprintf(
		"Classify and enrich these security findings. Call the emit_classified_findings tool with one entry per input in the same order (input_index starts at 0).\n\n%s",
		string(findingsJSON),
	)

	req := llm.CompletionRequest{
		SystemPrompt:      classifierSystemPrompt,
		Messages:          []llm.Message{{Role: "user", Content: userMsg}},
		MaxTokens:         4096,
		Temperature:       0.1,
		CacheSystemPrompt: true,
	}
	if c.provider.SupportsToolUse() {
		req.Tools = []llm.Tool{classifierTool}
	}

	resp, err := c.provider.Complete(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("classifier LLM call failed: %w", err)
	}

	// Structured path: prefer tool calls if present.
	if len(resp.ToolCalls) > 0 && resp.ToolCalls[0].Name == classifierTool.Name {
		var out classifierToolOutput
		if err := json.Unmarshal([]byte(resp.ToolCalls[0].Arguments), &out); err != nil {
			return nil, fmt.Errorf("parsing classifier tool args: %w", err)
		}
		enriched := make([]pipeline.ClassifiedFinding, len(findings))
		copy(enriched, findings)
		for _, f := range out.Findings {
			if f.InputIndex < 0 || f.InputIndex >= len(enriched) {
				continue
			}
			enriched[f.InputIndex].Title = f.Title
			enriched[f.InputIndex].Description = f.Description
			enriched[f.InputIndex].CVEIDs = f.CVEIDs
			enriched[f.InputIndex].CVSSScore = f.CVSSScore
			enriched[f.InputIndex].CVSSVector = f.CVSSVector
			enriched[f.InputIndex].Severity = pipeline.Severity(f.Severity)
			enriched[f.InputIndex].AttackCategory = f.AttackCategory
			enriched[f.InputIndex].Confidence = pipeline.Confidence(f.Confidence)
		}
		return enriched, nil
	}

	// Fallback: parse JSON out of the text response. Local Ollama models
	// drift from the spec'd array shape — they sometimes wrap findings in
	// {"findings": [...]} or return a single classification object instead
	// of a one-element array. Try all three before giving up (#19).
	content := stripCodeFence(resp.Content)
	enriched, err := parseClassifierFindings(content)
	if err != nil {
		return nil, fmt.Errorf("parsing classifier response: %w (raw: %.200s)", err, content)
	}
	return enriched, nil
}

// parseClassifierFindings tolerates three shapes from the classifier LLM:
// the strict []ClassifiedFinding array, a wrapped {"findings": [...]} object,
// or a single classification object. Exported-as-package for direct testing.
func parseClassifierFindings(content string) ([]pipeline.ClassifiedFinding, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, fmt.Errorf("empty response")
	}

	var arr []pipeline.ClassifiedFinding
	if err := json.Unmarshal([]byte(content), &arr); err == nil {
		return arr, nil
	}

	var wrapped struct {
		Findings []pipeline.ClassifiedFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(content), &wrapped); err == nil && wrapped.Findings != nil {
		return wrapped.Findings, nil
	}

	var single pipeline.ClassifiedFinding
	if err := json.Unmarshal([]byte(content), &single); err == nil && single.Title != "" {
		return []pipeline.ClassifiedFinding{single}, nil
	}

	return nil, fmt.Errorf("response did not match array, wrapped object, or single-finding shape")
}

const classifierSystemPrompt = `You are a security vulnerability classifier. For each finding:

1. Map to relevant CVE IDs if applicable
2. Compute or assign a CVSS v3.1 score
3. Assign severity: critical (9.0-10.0), high (7.0-8.9), medium (4.0-6.9), low (0.1-3.9), informational (0.0)
4. Categorize: sqli, xss, ssrf, rce, auth_bypass, info_disclosure, misconfig, etc.
5. Assess confidence: high, medium, low, unverified
6. Identify chain candidates: which other findings could this chain with

Respond with a JSON array of classified findings. Each finding must have:
title, description, cve_ids, cvss_score, cvss_vector, severity, attack_category, confidence, chain_candidates`

func stripCodeFence(s string) string {
	s = trimString(s)
	if len(s) > 7 && s[:7] == "```json" {
		s = s[7:]
	} else if len(s) > 3 && s[:3] == "```" {
		s = s[3:]
	}
	if len(s) > 3 && s[len(s)-3:] == "```" {
		s = s[:len(s)-3]
	}
	return trimString(s)
}

func trimString(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\r' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

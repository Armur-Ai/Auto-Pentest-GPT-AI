package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// ToSARIF renders a PentestReport as SARIF 2.1.0 JSON.
//
// SARIF (Static Analysis Results Interchange Format) is what GitHub
// Code Scanning, Azure DevOps, and most enterprise scanners speak.
// Emitting it lets the swarm's findings show up in the Security tab
// of the repo for free, without the GH Action having to do any parsing.
//
// Compliance target: SARIF 2.1.0 via the OASIS spec. We populate the
// required fields (version, $schema, runs[].tool, runs[].results) plus
// enough optional metadata (CVSS, CVE, help URI) for the Code Scanning
// UI to render severity + reference links. Exit with a valid SARIF
// even when the run found zero findings (empty runs[].results).
func (r *Renderer) ToSARIF(report *pipeline.PentestReport) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("nil report")
	}

	// One unique rule per finding id — keep it simple; the LLM-generated
	// rule id is whatever the classifier produced. If we start writing the
	// same rule for multiple findings, GitHub's dedup logic handles it.
	var rules []sarifRule
	var results []sarifResult
	seen := map[string]struct{}{}

	for _, f := range report.Findings {
		ruleID := sanitiseRuleID(f.Title)
		if _, dup := seen[ruleID]; !dup {
			rules = append(rules, sarifRule{
				ID:                   ruleID,
				Name:                 f.Title,
				ShortDescription:     sarifDescription{Text: f.Title},
				FullDescription:      sarifDescription{Text: fallback(f.Description, f.Title)},
				Help:                 sarifMultiformatHelp{Text: fallback(f.Remediation, "See advisory for remediation."), Markdown: fallback(f.Remediation, "See advisory for remediation.")},
				HelpURI:              firstReference(f.References),
				DefaultConfiguration: sarifDefaultConfig{Level: severityToLevel(f.Severity)},
				Properties: map[string]any{
					"security-severity": fmt.Sprintf("%.1f", f.CVSSScore),
					"tags":              sarifTags(f),
				},
			})
			seen[ruleID] = struct{}{}
		}
		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   severityToLevel(f.Severity),
			Message: sarifMessage{Text: buildMessage(f)},
			Properties: map[string]any{
				"cvss_score":  f.CVSSScore,
				"cvss_vector": f.CVSSVector,
			},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: affectedURI(f)},
				},
			}},
		})
	}

	doc := sarifDoc{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "Pentest Swarm AI",
					InformationURI: "https://github.com/Armur-Ai/Pentest-Swarm-AI",
					Version:        "0.2",
					Rules:          rules,
				},
			},
			Results: results,
			// GitHub Code Scanning needs a non-nil automationDetails for
			// a usable timeline; the id is arbitrary per scan.
			AutomationDetails: &sarifAutomationDetails{ID: report.ID.String()},
		}},
	}

	return json.MarshalIndent(doc, "", "  ")
}

// --- types ---

type sarifDoc struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool               `json:"tool"`
	Results           []sarifResult           `json:"results"`
	AutomationDetails *sarifAutomationDetails `json:"automationDetails,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string               `json:"id"`
	Name                 string               `json:"name"`
	ShortDescription     sarifDescription     `json:"shortDescription"`
	FullDescription      sarifDescription     `json:"fullDescription"`
	Help                 sarifMultiformatHelp `json:"help"`
	HelpURI              string               `json:"helpUri,omitempty"`
	DefaultConfiguration sarifDefaultConfig   `json:"defaultConfiguration"`
	Properties           map[string]any       `json:"properties,omitempty"`
}

type sarifDescription struct {
	Text string `json:"text"`
}

type sarifMultiformatHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"` // none | note | warning | error
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifAutomationDetails struct {
	ID string `json:"id"`
}

// --- helpers ---

// severityToLevel maps our severity to SARIF's 4-level enum.
// SARIF only has note | warning | error (none is reserved for non-
// findings). critical + high => error, medium => warning, low + info => note.
// sarifTags builds the rule tag list, including the standardized taxonomy
// labels. CWE uses the `external/cwe/cwe-nnn` convention GitHub Code Scanning
// recognizes and links; the OWASP category rides along for filtering.
func sarifTags(f pipeline.ReportFinding) []string {
	tags := []string{"security", string(f.Severity)}
	if f.CWE != "" {
		tags = append(tags, "external/cwe/"+strings.ToLower(f.CWE))
	}
	if f.OWASP != "" {
		tags = append(tags, "owasp/"+f.OWASP)
	}
	// ATTACK is "Tid Name"; tag with the technique id only.
	if f.ATTACK != "" {
		tags = append(tags, "attack/"+strings.Fields(f.ATTACK)[0])
	}
	return tags
}

func severityToLevel(s pipeline.Severity) string {
	switch s {
	case pipeline.SeverityCritical, pipeline.SeverityHigh:
		return "error"
	case pipeline.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// sanitiseRuleID builds a stable, short, deterministic rule id from the
// finding title. SARIF rule ids should be ASCII-alphanumeric + hyphen.
func sanitiseRuleID(title string) string {
	out := make([]byte, 0, len(title))
	prevHyphen := false
	for _, r := range title {
		switch {
		case r >= 'A' && r <= 'Z':
			out = append(out, byte(r-'A'+'a'))
			prevHyphen = false
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			out = append(out, byte(r))
			prevHyphen = false
		default:
			if !prevHyphen && len(out) > 0 {
				out = append(out, '-')
				prevHyphen = true
			}
		}
	}
	// Trim trailing hyphen + clamp length.
	for len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	if len(out) > 50 {
		out = out[:50]
	}
	if len(out) == 0 {
		return "pentest-finding"
	}
	return "pentestswarm/" + string(out)
}

func fallback(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func firstReference(refs []string) string {
	for _, r := range refs {
		if r != "" {
			return r
		}
	}
	return ""
}

func affectedURI(f pipeline.ReportFinding) string {
	for _, c := range f.AffectedComponents {
		if c != "" {
			return c
		}
	}
	return "unknown"
}

func buildMessage(f pipeline.ReportFinding) string {
	msg := f.Title
	if f.CVSSScore > 0 {
		msg += fmt.Sprintf(" (CVSS %.1f)", f.CVSSScore)
	}
	if f.Description != "" {
		msg += "\n\n" + f.Description
	}
	return msg
}

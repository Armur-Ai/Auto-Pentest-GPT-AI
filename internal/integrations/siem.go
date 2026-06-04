package integrations

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// FormatCEF converts a finding to Common Event Format for SIEM ingestion.
func FormatCEF(finding pipeline.ClassifiedFinding) string {
	severity := cefSeverity(finding.Severity)

	return fmt.Sprintf(
		"CEF:0|ArmurAI|pentestswarm|1.0|%s|%s|%d|src=%s cat=%s cvss=%.1f msg=%s",
		finding.AttackCategory,
		finding.Title,
		severity,
		finding.Target,
		finding.AttackCategory,
		finding.CVSSScore,
		strings.ReplaceAll(finding.Description, "|", "\\|"),
	)
}

// FormatSARIF converts findings to Static Analysis Results Interchange Format.
func FormatSARIF(findings []pipeline.ClassifiedFinding) ([]byte, error) {
	sarif := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":           "pentestswarm",
						"version":        "1.0.0",
						"informationUri": "https://github.com/Armur-Ai/Pentest-Swarm-AI",
						"rules":          buildSARIFRules(findings),
					},
				},
				"results": buildSARIFResults(findings),
			},
		},
	}

	return json.MarshalIndent(sarif, "", "  ")
}

// FormatSTIX converts a finding to STIX 2.1 vulnerability object.
func FormatSTIX(finding pipeline.ClassifiedFinding) ([]byte, error) {
	stix := map[string]any{
		"type":                "vulnerability",
		"spec_version":        "2.1",
		"id":                  fmt.Sprintf("vulnerability--%s", finding.ID),
		"created":             finding.ClassifiedAt.Format(time.RFC3339),
		"modified":            time.Now().Format(time.RFC3339),
		"name":                finding.Title,
		"description":         finding.Description,
		"external_references": buildExternalRefs(finding),
	}

	return json.MarshalIndent(stix, "", "  ")
}

func cefSeverity(s pipeline.Severity) int {
	switch s {
	case pipeline.SeverityCritical:
		return 10
	case pipeline.SeverityHigh:
		return 8
	case pipeline.SeverityMedium:
		return 5
	case pipeline.SeverityLow:
		return 3
	default:
		return 1
	}
}

func buildSARIFRules(findings []pipeline.ClassifiedFinding) []map[string]any {
	seen := make(map[string]bool)
	var rules []map[string]any

	for _, f := range findings {
		if seen[f.AttackCategory] {
			continue
		}
		seen[f.AttackCategory] = true

		rules = append(rules, map[string]any{
			"id":   f.AttackCategory,
			"name": f.AttackCategory,
			"defaultConfiguration": map[string]string{
				"level": sarifLevel(f.Severity),
			},
		})
	}
	return rules
}

func buildSARIFResults(findings []pipeline.ClassifiedFinding) []map[string]any {
	var results []map[string]any
	for _, f := range findings {
		results = append(results, map[string]any{
			"ruleId":  f.AttackCategory,
			"level":   sarifLevel(f.Severity),
			"message": map[string]string{"text": f.Description},
			"locations": []map[string]any{
				{"physicalLocation": map[string]any{
					"artifactLocation": map[string]string{"uri": f.Target},
				}},
			},
		})
	}
	return results
}

func sarifLevel(s pipeline.Severity) string {
	switch s {
	case pipeline.SeverityCritical, pipeline.SeverityHigh:
		return "error"
	case pipeline.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func buildExternalRefs(f pipeline.ClassifiedFinding) []map[string]string {
	var refs []map[string]string
	for _, cve := range f.CVEIDs {
		refs = append(refs, map[string]string{
			"source_name": "cve",
			"external_id": cve,
			"url":         fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve),
		})
	}
	return refs
}

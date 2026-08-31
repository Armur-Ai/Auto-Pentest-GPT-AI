package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// Renderer converts a PentestReport to various output formats.
type Renderer struct{}

// NewRenderer creates a new report renderer.
func NewRenderer() *Renderer {
	return &Renderer{}
}

// ToMarkdown renders the report as GitHub-flavored Markdown.
func (r *Renderer) ToMarkdown(report *pipeline.PentestReport) ([]byte, error) {
	var b strings.Builder

	b.WriteString("# Penetration Test Report\n\n")
	b.WriteString(fmt.Sprintf("**Target:** %s\n\n", report.Target))
	b.WriteString(fmt.Sprintf("**Objective:** %s\n\n", report.Objective))
	b.WriteString(fmt.Sprintf("**Date:** %s\n\n", report.GeneratedAt.Format("January 2, 2006")))
	b.WriteString("---\n\n")

	// Executive Summary
	b.WriteString("## Executive Summary\n\n")
	b.WriteString(report.ExecutiveSummary + "\n\n")

	// Risk Summary
	b.WriteString("## Risk Summary\n\n")
	b.WriteString(fmt.Sprintf("| Severity | Count |\n|---|---|\n"))
	b.WriteString(fmt.Sprintf("| Critical | %d |\n", report.RiskSummary.CriticalCount))
	b.WriteString(fmt.Sprintf("| High | %d |\n", report.RiskSummary.HighCount))
	b.WriteString(fmt.Sprintf("| Medium | %d |\n", report.RiskSummary.MediumCount))
	b.WriteString(fmt.Sprintf("| Low | %d |\n", report.RiskSummary.LowCount))
	b.WriteString(fmt.Sprintf("| Info | %d |\n\n", report.RiskSummary.InfoCount))

	// Findings
	b.WriteString("## Findings\n\n")
	for i, f := range report.Findings {
		b.WriteString(fmt.Sprintf("### %d. [%s] %s (CVSS: %.1f)\n\n", i+1, strings.ToUpper(string(f.Severity)), f.Title, f.CVSSScore))

		// Standardized classification labels, when mapped.
		if f.OWASP != "" || f.CWE != "" || f.ATTACK != "" {
			parts := make([]string, 0, 3)
			if f.OWASP != "" {
				parts = append(parts, "OWASP "+f.OWASP)
			}
			if f.CWE != "" {
				parts = append(parts, f.CWE)
			}
			if f.ATTACK != "" {
				parts = append(parts, "ATT&CK "+f.ATTACK)
			}
			b.WriteString("**Classification:** " + strings.Join(parts, " · ") + "\n\n")
		}

		b.WriteString(f.Description + "\n\n")

		if len(f.Evidence) > 0 {
			b.WriteString("**Evidence:**\n\n")
			for _, e := range f.Evidence {
				b.WriteString(fmt.Sprintf("```\n%s\n```\n\n", e.Content))
			}
		}

		// Steps to Reproduce — copy-pasteable command / raw HTTP request the
		// operator can re-run. Only rendered when there's real repro content.
		if rp := f.Reproduce; rp != nil && (rp.Command != "" || rp.HTTPRequest != "" || rp.ExpectedIndicator != "") {
			b.WriteString("**Steps to Reproduce:**\n\n")
			if rp.Command != "" {
				b.WriteString(fmt.Sprintf("```sh\n%s\n```\n\n", rp.Command))
			}
			if rp.HTTPRequest != "" {
				b.WriteString(fmt.Sprintf("```http\n%s\n```\n\n", rp.HTTPRequest))
			}
			if rp.ExpectedIndicator != "" {
				b.WriteString(fmt.Sprintf("Expected indicator: `%s`\n\n", rp.ExpectedIndicator))
			}
		}

		if f.Remediation != "" {
			b.WriteString("**Remediation:**\n\n")
			b.WriteString(f.Remediation + "\n\n")
		}

		b.WriteString("---\n\n")
	}

	// Attack Narrative
	if report.AttackNarrative != "" {
		b.WriteString("## Attack Narrative\n\n")
		b.WriteString(report.AttackNarrative + "\n\n")
	}

	// Remediation Plan
	b.WriteString("## Remediation Plan\n\n")
	b.WriteString("| Priority | Finding | Action | Effort | Impact |\n|---|---|---|---|---|\n")
	for _, item := range report.RemediationPlan {
		b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s |\n",
			item.Priority, item.Finding, item.Action, item.Effort, item.Impact))
	}

	// ROI footer (4.5.7) — only renders when the runner supplied spend data.
	if report.ROIFooter != "" {
		b.WriteString("\n---\n\n")
		b.WriteString(report.ROIFooter)
		b.WriteString("\n")
	}

	return []byte(b.String()), nil
}

// ToJSON renders the report as formatted JSON.
func (r *Renderer) ToJSON(report *pipeline.PentestReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// ToHTML renders the report as self-contained HTML with embedded CSS.
func (r *Renderer) ToHTML(report *pipeline.PentestReport) ([]byte, error) {
	md, err := r.ToMarkdown(report)
	if err != nil {
		return nil, err
	}

	// Wrap markdown in a basic HTML template with dark styling
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pentest Report — %s</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0f; color: #e0e0e0; max-width: 900px; margin: 0 auto; padding: 2rem; line-height: 1.6; }
  h1 { color: #fff; border-bottom: 2px solid #333; padding-bottom: 0.5rem; }
  h2 { color: #60a5fa; margin-top: 2rem; }
  h3 { color: #f59e0b; }
  table { border-collapse: collapse; width: 100%%; margin: 1rem 0; }
  th, td { border: 1px solid #333; padding: 0.5rem 1rem; text-align: left; }
  th { background: #1a1a2e; color: #60a5fa; }
  code, pre { background: #1a1a2e; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.9rem; }
  pre { padding: 1rem; overflow-x: auto; border: 1px solid #333; }
  hr { border: none; border-top: 1px solid #333; margin: 2rem 0; }
  .severity-critical { color: #ef4444; font-weight: bold; }
  .severity-high { color: #f97316; font-weight: bold; }
  .severity-medium { color: #eab308; }
  .severity-low { color: #22c55e; }
</style>
</head>
<body>
<pre style="white-space: pre-wrap;">%s</pre>
</body>
</html>`, report.Target, string(md))

	return []byte(html), nil
}

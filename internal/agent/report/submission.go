package report

import (
	"bytes"
	"embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

//go:embed templates/hackerone.md.tmpl templates/bugcrowd.md.tmpl templates/intigriti.md.tmpl
var submissionTemplates embed.FS

// SubmissionView is the view-model every platform template consumes.
// Keeping the shape flat keeps the templates skimmable — they read
// more like a submission form than a Go program.
type SubmissionView struct {
	Title              string
	Target             string
	AttackCategory     string
	Severity           string
	CVSSScore          float64
	CVSSVector         string
	CVEIDs             []string
	Summary            string
	Impact             string
	Remediation        string
	Reproduce          *pipeline.Reproduction
	Evidence           []pipeline.Evidence
	CorroboratingTools []string
}

// BuildSubmissionView collapses a ReportFinding into the view-model
// the submission templates expect. Impact / Summary / Remediation fall
// back to sensible defaults rather than leaving the template blank —
// a submission form with a blank "Impact" reads as sloppy.
func BuildSubmissionView(f pipeline.ReportFinding, cf *pipeline.ClassifiedFinding, corroborating []string) SubmissionView {
	v := SubmissionView{
		Title:              f.Title,
		Target:             firstNonEmpty(f.AffectedComponents),
		Severity:           strings.Title(string(f.Severity)),
		CVSSScore:          f.CVSSScore,
		CVSSVector:         f.CVSSVector,
		Evidence:           f.Evidence,
		CorroboratingTools: corroborating,
	}
	v.Summary = fallbackStr(f.Description, "Automated scanner detected a vulnerability on "+v.Target+".")
	v.Impact = fallbackStr(inferImpact(f.Severity), "See severity rating.")
	v.Remediation = fallbackStr(f.Remediation, "Apply vendor patch / disable affected feature / sanitize input per vendor guidance.")
	if cf != nil {
		v.CVEIDs = cf.CVEIDs
		v.AttackCategory = cf.AttackCategory
		v.Reproduce = cf.Reproduce
		if v.Reproduce == nil {
			v.Reproduce = &pipeline.Reproduction{}
		}
	} else {
		v.Reproduce = &pipeline.Reproduction{}
	}
	return v
}

// RenderSubmission picks a template by platform ("h1" | "hackerone" |
// "bugcrowd" | "intigriti") and executes it against v.
func RenderSubmission(platform string, v SubmissionView) ([]byte, error) {
	name, err := templateNameFor(platform)
	if err != nil {
		return nil, err
	}
	raw, err := submissionTemplates.ReadFile("templates/" + name)
	if err != nil {
		return nil, fmt.Errorf("load template %s: %w", name, err)
	}
	tpl, err := template.New(name).Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("parse template %s: %w", name, err)
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, v); err != nil {
		return nil, fmt.Errorf("render %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

func templateNameFor(platform string) (string, error) {
	switch strings.ToLower(platform) {
	case "h1", "hackerone":
		return "hackerone.md.tmpl", nil
	case "bugcrowd":
		return "bugcrowd.md.tmpl", nil
	case "intigriti":
		return "intigriti.md.tmpl", nil
	default:
		return "", fmt.Errorf("unknown platform %q (supported: h1, bugcrowd, intigriti)", platform)
	}
}

func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return "unknown"
}

func fallbackStr(primary, fallback string) string {
	if strings.TrimSpace(primary) == "" {
		return fallback
	}
	return primary
}

// inferImpact generates a reasonable impact sentence from severity
// alone, for findings where the classifier didn't populate description.
func inferImpact(s pipeline.Severity) string {
	switch s {
	case pipeline.SeverityCritical:
		return "Critical. An unauthenticated remote attacker can likely achieve full compromise of the asset."
	case pipeline.SeverityHigh:
		return "High. An attacker can likely obtain sensitive data, elevate privileges, or disrupt service."
	case pipeline.SeverityMedium:
		return "Medium. Exploitable, but requires some preconditions (authenticated access, user interaction, or chained with another finding)."
	case pipeline.SeverityLow:
		return "Low. Minor information disclosure or hardening gap."
	default:
		return "Informational. No direct security impact; included for situational awareness."
	}
}

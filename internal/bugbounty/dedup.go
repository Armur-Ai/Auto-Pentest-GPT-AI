package bugbounty

import (
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// DuplicateResult indicates whether a finding is a potential duplicate.
type DuplicateResult struct {
	IsDuplicate bool        `json:"is_duplicate"`
	Confidence  float64     `json:"confidence"`
	MatchedSub  *Submission `json:"matched_submission,omitempty"`
	Reason      string      `json:"reason"`
}

// DuplicateDetector checks findings against previous submissions.
type DuplicateDetector struct{}

// NewDuplicateDetector creates a new duplicate detector.
func NewDuplicateDetector() *DuplicateDetector {
	return &DuplicateDetector{}
}

// Check determines if a finding is likely a duplicate of an existing submission.
func (d *DuplicateDetector) Check(finding pipeline.ClassifiedFinding, submissions []Submission) DuplicateResult {
	for _, sub := range submissions {
		// CVE match
		for _, cve := range finding.CVEIDs {
			if strings.Contains(strings.ToLower(sub.Title), strings.ToLower(cve)) {
				return DuplicateResult{
					IsDuplicate: true,
					Confidence:  0.95,
					MatchedSub:  &sub,
					Reason:      "Same CVE ID: " + cve,
				}
			}
		}

		// Title similarity (simple word overlap)
		similarity := wordOverlap(finding.Title, sub.Title)
		if similarity > 0.85 {
			return DuplicateResult{
				IsDuplicate: true,
				Confidence:  similarity,
				MatchedSub:  &sub,
				Reason:      "High title similarity",
			}
		}

		// Same vulnerability type on same target
		if strings.Contains(strings.ToLower(sub.Title), strings.ToLower(finding.AttackCategory)) &&
			strings.Contains(strings.ToLower(sub.Title), extractDomain(finding.Target)) {
			return DuplicateResult{
				IsDuplicate: true,
				Confidence:  0.80,
				MatchedSub:  &sub,
				Reason:      "Same vuln type on same target",
			}
		}
	}

	return DuplicateResult{IsDuplicate: false}
}

// BatchCheck checks multiple findings for duplicates.
func (d *DuplicateDetector) BatchCheck(findings []pipeline.ClassifiedFinding, submissions []Submission) map[string]DuplicateResult {
	results := make(map[string]DuplicateResult, len(findings))
	for _, f := range findings {
		results[f.ID.String()] = d.Check(f, submissions)
	}
	return results
}

func wordOverlap(a, b string) float64 {
	wordsA := strings.Fields(strings.ToLower(a))
	wordsB := strings.Fields(strings.ToLower(b))

	if len(wordsA) == 0 || len(wordsB) == 0 {
		return 0
	}

	setB := make(map[string]bool, len(wordsB))
	for _, w := range wordsB {
		setB[w] = true
	}

	matches := 0
	for _, w := range wordsA {
		if setB[w] {
			matches++
		}
	}

	return float64(matches) / float64(max(len(wordsA), len(wordsB)))
}

func extractDomain(target string) string {
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	parts := strings.Split(target, "/")
	return parts[0]
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

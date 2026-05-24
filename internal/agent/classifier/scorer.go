package classifier

import (
	"fmt"
	"math"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// CVSSComponents holds parsed CVSS v3.1 vector components.
type CVSSComponents struct {
	AttackVector          string // N, A, L, P
	AttackComplexity      string // L, H
	PrivilegesRequired    string // N, L, H
	UserInteraction       string // N, R
	Scope                 string // U, C
	ConfidentialityImpact string // N, L, H
	IntegrityImpact       string // N, L, H
	AvailabilityImpact    string // N, L, H
}

// ScoringContext provides additional context for CVSS adjustment.
type ScoringContext struct {
	InternetFacing         bool
	AuthenticationRequired bool
	ExploitAvailable       bool
}

// ParseCVSSVector parses a CVSS v3.1 vector string into components.
func ParseCVSSVector(vector string) (*CVSSComponents, error) {
	components := &CVSSComponents{}
	parts := strings.Split(vector, "/")

	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}

		switch kv[0] {
		case "AV":
			components.AttackVector = kv[1]
		case "AC":
			components.AttackComplexity = kv[1]
		case "PR":
			components.PrivilegesRequired = kv[1]
		case "UI":
			components.UserInteraction = kv[1]
		case "S":
			components.Scope = kv[1]
		case "C":
			components.ConfidentialityImpact = kv[1]
		case "I":
			components.IntegrityImpact = kv[1]
		case "A":
			components.AvailabilityImpact = kv[1]
		}
	}

	if components.AttackVector == "" {
		return nil, fmt.Errorf("invalid CVSS vector: missing AV component")
	}

	return components, nil
}

// ComputeBaseScore implements the CVSS v3.1 base score formula per FIRST specification.
func ComputeBaseScore(c CVSSComponents) float64 {
	iss := 1 - ((1 - impactValue(c.ConfidentialityImpact)) *
		(1 - impactValue(c.IntegrityImpact)) *
		(1 - impactValue(c.AvailabilityImpact)))

	var impact float64
	if c.Scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}

	if impact <= 0 {
		return 0
	}

	exploitability := 8.22 * attackVectorValue(c.AttackVector) *
		attackComplexityValue(c.AttackComplexity) *
		privilegesRequiredValue(c.PrivilegesRequired, c.Scope) *
		userInteractionValue(c.UserInteraction)

	var score float64
	if c.Scope == "U" {
		score = math.Min(impact+exploitability, 10)
	} else {
		score = math.Min(1.08*(impact+exploitability), 10)
	}

	return roundUp(score)
}

// AdjustForContext adjusts a CVSS base score based on environmental context.
func AdjustForContext(base float64, ctx ScoringContext) float64 {
	score := base

	if ctx.InternetFacing {
		score *= 1.15
	}
	if ctx.AuthenticationRequired {
		score *= 0.8
	}
	if ctx.ExploitAvailable {
		score *= 1.2
	}

	if score > 10.0 {
		score = 10.0
	}
	if score < 0 {
		score = 0
	}

	return math.Round(score*10) / 10
}

// ScoreToSeverity converts a CVSS score to a severity level.
func ScoreToSeverity(score float64) pipeline.Severity {
	switch {
	case score >= 9.0:
		return pipeline.SeverityCritical
	case score >= 7.0:
		return pipeline.SeverityHigh
	case score >= 4.0:
		return pipeline.SeverityMedium
	case score > 0:
		return pipeline.SeverityLow
	default:
		return pipeline.SeverityInformational
	}
}

// CVSS v3.1 metric value lookups per FIRST specification

func attackVectorValue(av string) float64 {
	switch av {
	case "N":
		return 0.85
	case "A":
		return 0.62
	case "L":
		return 0.55
	case "P":
		return 0.20
	}
	return 0.85
}

func attackComplexityValue(ac string) float64 {
	switch ac {
	case "L":
		return 0.77
	case "H":
		return 0.44
	}
	return 0.77
}

func privilegesRequiredValue(pr, scope string) float64 {
	if scope == "C" {
		switch pr {
		case "N":
			return 0.85
		case "L":
			return 0.68
		case "H":
			return 0.50
		}
	}
	switch pr {
	case "N":
		return 0.85
	case "L":
		return 0.62
	case "H":
		return 0.27
	}
	return 0.85
}

func userInteractionValue(ui string) float64 {
	switch ui {
	case "N":
		return 0.85
	case "R":
		return 0.62
	}
	return 0.85
}

func impactValue(impact string) float64 {
	switch impact {
	case "H":
		return 0.56
	case "L":
		return 0.22
	case "N":
		return 0
	}
	return 0
}

// roundUp rounds up to one decimal place per CVSS spec.
func roundUp(val float64) float64 {
	return math.Ceil(val*10) / 10
}

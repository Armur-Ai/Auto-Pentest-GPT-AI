// Package blackboard implements the stigmergic shared state for the swarm.
//
// The blackboard replaces the sequential 5-phase runner. Agents read and write
// findings tagged with a type; their trigger predicates wake them when
// relevant state appears. Pheromone weights decay over time so the swarm
// naturally prioritizes recent, high-signal findings and lets stale paths die.
package blackboard

import (
	"time"

	"github.com/google/uuid"
)

// FindingType is a coarse-grained classifier for what a finding represents.
// Agents subscribe by type; the scheduler routes work based on type.
type FindingType string

const (
	// Recon-phase findings
	TypeTargetRegistered FindingType = "TARGET_REGISTERED"
	TypeSubdomain        FindingType = "SUBDOMAIN"
	TypeHTTPEndpoint     FindingType = "HTTP_ENDPOINT"
	TypePortOpen         FindingType = "PORT_OPEN"
	TypeService          FindingType = "SERVICE"
	TypeTechnology       FindingType = "TECHNOLOGY"

	// Classification-phase findings
	TypeCVEMatch      FindingType = "CVE_MATCH"
	TypeCVSSScore     FindingType = "CVSS_SCORE"
	TypeMisconfig     FindingType = "MISCONFIGURATION"
	TypeSecretLeak    FindingType = "SECRET_LEAK"
	TypePotentialSQLI FindingType = "POTENTIAL_SQLI"

	// Exploit-phase findings
	TypeExploitChain  FindingType = "EXPLOIT_CHAIN"
	TypeExploitResult FindingType = "EXPLOIT_RESULT"
	TypeSession       FindingType = "SESSION"

	// Meta findings
	TypeCampaignComplete FindingType = "CAMPAIGN_COMPLETE"
	TypeAgentError       FindingType = "AGENT_ERROR"

	// Generated artifacts — nuclei templates, playbook drafts, etc.
	TypeNucleiTemplateDraft FindingType = "NUCLEI_TEMPLATE_DRAFT"
)

// Finding is a single atomic piece of shared state on the blackboard.
type Finding struct {
	ID            uuid.UUID   `json:"id"`
	CampaignID    uuid.UUID   `json:"campaign_id"`
	AgentName     string      `json:"agent_name"`
	Type          FindingType `json:"type"`
	Target        string      `json:"target"`
	Data          []byte      `json:"data"`           // JSON-encoded payload specific to Type
	PheromoneBase float64     `json:"pheromone_base"` // initial weight (0.0–1.0)
	HalfLifeSec   int         `json:"half_life_sec"`  // decay half-life in seconds
	SupersededBy  *uuid.UUID  `json:"superseded_by,omitempty"`
	CreatedAt     time.Time   `json:"created_at"`

	// Pheromone is the current decayed weight (0.0–1.0), computed at read time.
	// Only populated by Query / Subscribe; not persisted.
	Pheromone float64 `json:"pheromone,omitempty"`
}

// Predicate selects findings from the blackboard. All set conditions must
// match (AND semantics). A zero Predicate matches everything.
type Predicate struct {
	// Types, if set, restricts to findings whose Type is one of these.
	Types []FindingType

	// TargetPrefix, if set, restricts to findings whose Target starts with this string.
	TargetPrefix string

	// MinPheromone, if > 0, restricts to findings whose current pheromone
	// weight is at least this value.
	MinPheromone float64

	// SinceID, if non-zero, restricts to findings created after this ID
	// (exclusive). Used by agent cursors for exactly-once delivery.
	SinceID uuid.UUID

	// Limit caps the number of results. Zero = unlimited.
	Limit int
}

// WriteOption customizes a Write call.
type WriteOption func(*writeOpts)

type writeOpts struct {
	pheromoneBase float64
	halfLifeSec   int
	embedding     []float32
	supersedes    *uuid.UUID
}

// WithPheromone sets the initial pheromone weight for a finding.
// Valid range [0.0, 1.0]; default 1.0.
func WithPheromone(base float64) WriteOption {
	return func(o *writeOpts) { o.pheromoneBase = base }
}

// WithHalfLife sets the pheromone decay half-life in seconds.
// Default: 3600 (1 hour).
func WithHalfLife(seconds int) WriteOption {
	return func(o *writeOpts) { o.halfLifeSec = seconds }
}

// WithEmbedding attaches a semantic embedding for vector similarity search.
// Must be 1536-dim to match the schema.
func WithEmbedding(v []float32) WriteOption {
	return func(o *writeOpts) { o.embedding = v }
}

// Supersedes marks an existing finding as superseded by the one being written.
// Used by classifier/exploit agents to replace older hypotheses with refined ones.
func Supersedes(id uuid.UUID) WriteOption {
	return func(o *writeOpts) { o.supersedes = &id }
}

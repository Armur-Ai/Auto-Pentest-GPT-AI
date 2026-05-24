package pipeline

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// CampaignStatus represents the current state of a campaign.
type CampaignStatus string

const (
	StatusPlanned      CampaignStatus = "planned"
	StatusInitializing CampaignStatus = "initializing"
	StatusRecon        CampaignStatus = "recon"
	StatusClassifying  CampaignStatus = "classifying"
	StatusPlanning     CampaignStatus = "planning"
	StatusExecuting    CampaignStatus = "executing"
	StatusAdapting     CampaignStatus = "adapting"
	StatusReporting    CampaignStatus = "reporting"
	StatusComplete     CampaignStatus = "complete"
	StatusFailed       CampaignStatus = "failed"
	StatusAborted      CampaignStatus = "aborted"
)

// CampaignMode determines the campaign workflow.
type CampaignMode string

const (
	ModeManual        CampaignMode = "manual"
	ModeBugBounty     CampaignMode = "bugbounty"
	ModeContinuousASM CampaignMode = "asm"
	ModeCTF           CampaignMode = "ctf"
)

// Campaign is the top-level entity for a penetration test run.
type Campaign struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	Name        string          `json:"name" db:"name"`
	Target      string          `json:"target" db:"target"`
	Objective   string          `json:"objective" db:"objective"`
	Status      CampaignStatus  `json:"status" db:"status"`
	Mode        CampaignMode    `json:"mode" db:"mode"`
	Scope       ScopeDefinition `json:"scope" db:"scope"`
	AuthToken   string          `json:"-" db:"auth_token"`
	Provider    string          `json:"provider" db:"provider"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
	StartedAt   *time.Time      `json:"started_at,omitempty" db:"started_at"`
	CompletedAt *time.Time      `json:"completed_at,omitempty" db:"completed_at"`
}

// ScopeDefinition defines the allowed targets for a campaign.
type ScopeDefinition struct {
	AllowedCIDRs   []string `json:"allowed_cidrs"`
	AllowedDomains []string `json:"allowed_domains"`
	AllowedPorts   []int    `json:"allowed_ports,omitempty"`
	ExcludedCIDRs  []string `json:"excluded_cidrs,omitempty"`
}

// Scan implements the sql.Scanner interface for database storage.
func (s *ScopeDefinition) Scan(src any) error {
	if src == nil {
		return nil
	}
	switch v := src.(type) {
	case []byte:
		return json.Unmarshal(v, s)
	case string:
		return json.Unmarshal([]byte(v), s)
	}
	return nil
}

// CampaignEvent is an append-only audit log entry.
type CampaignEvent struct {
	ID         uuid.UUID       `json:"id" db:"id"`
	CampaignID uuid.UUID       `json:"campaign_id" db:"campaign_id"`
	Timestamp  time.Time       `json:"timestamp" db:"timestamp"`
	EventType  EventType       `json:"event_type" db:"event_type"`
	AgentName  string          `json:"agent_name,omitempty" db:"agent_name"`
	Detail     string          `json:"detail" db:"detail"`
	Data       json.RawMessage `json:"data,omitempty" db:"data"`
}

// EventType categorizes campaign events.
type EventType string

const (
	EventThought           EventType = "thought"
	EventToolCall          EventType = "tool_call"
	EventToolResult        EventType = "tool_result"
	EventFindingDiscovered EventType = "finding_discovered"
	EventStateChange       EventType = "state_change"
	EventStepExecuted      EventType = "step_executed"
	EventError             EventType = "error"
	EventMilestone         EventType = "milestone"
)

// Severity levels for findings.
type Severity string

const (
	SeverityCritical      Severity = "critical"
	SeverityHigh          Severity = "high"
	SeverityMedium        Severity = "medium"
	SeverityLow           Severity = "low"
	SeverityInformational Severity = "informational"
)

// Confidence levels for classified findings.
type Confidence string

const (
	ConfidenceHigh       Confidence = "high"
	ConfidenceMedium     Confidence = "medium"
	ConfidenceLow        Confidence = "low"
	ConfidenceUnverified Confidence = "unverified"
)

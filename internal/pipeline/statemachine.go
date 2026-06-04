package pipeline

import (
	"fmt"
	"time"

	apperrors "github.com/Armur-Ai/Pentest-Swarm-AI/internal/errors"
)

// validTransitions defines allowed state transitions.
var validTransitions = map[CampaignStatus][]CampaignStatus{
	StatusPlanned:      {StatusInitializing},
	StatusInitializing: {StatusRecon, StatusFailed, StatusAborted},
	StatusRecon:        {StatusClassifying, StatusFailed, StatusAborted},
	StatusClassifying:  {StatusPlanning, StatusFailed, StatusAborted},
	StatusPlanning:     {StatusExecuting, StatusReporting, StatusFailed, StatusAborted},
	StatusExecuting:    {StatusAdapting, StatusReporting, StatusFailed, StatusAborted},
	StatusAdapting:     {StatusExecuting, StatusReporting, StatusFailed, StatusAborted},
	StatusReporting:    {StatusComplete, StatusFailed, StatusAborted},
}

// StateMachine manages campaign state transitions with validation.
type StateMachine struct {
	campaign *Campaign
	onEvent  func(CampaignEvent) // callback for state change events
}

// NewStateMachine creates a state machine for a campaign.
func NewStateMachine(campaign *Campaign, onEvent func(CampaignEvent)) *StateMachine {
	return &StateMachine{
		campaign: campaign,
		onEvent:  onEvent,
	}
}

// Transition moves the campaign to a new state if the transition is valid.
func (sm *StateMachine) Transition(newStatus CampaignStatus) error {
	allowed, ok := validTransitions[sm.campaign.Status]
	if !ok {
		return fmt.Errorf("%w: no transitions from %s", apperrors.ErrInvalidTransition, sm.campaign.Status)
	}

	valid := false
	for _, s := range allowed {
		if s == newStatus {
			valid = true
			break
		}
	}

	if !valid {
		return fmt.Errorf("%w: cannot transition from %s to %s", apperrors.ErrInvalidTransition, sm.campaign.Status, newStatus)
	}

	oldStatus := sm.campaign.Status
	sm.campaign.Status = newStatus

	now := time.Now()
	if newStatus == StatusRecon && sm.campaign.StartedAt == nil {
		sm.campaign.StartedAt = &now
	}
	if newStatus == StatusComplete || newStatus == StatusFailed || newStatus == StatusAborted {
		sm.campaign.CompletedAt = &now
	}

	if sm.onEvent != nil {
		sm.onEvent(CampaignEvent{
			CampaignID: sm.campaign.ID,
			Timestamp:  now,
			EventType:  EventStateChange,
			Detail:     fmt.Sprintf("%s → %s", oldStatus, newStatus),
		})
	}

	return nil
}

// Start begins the campaign.
func (sm *StateMachine) Start() error            { return sm.Transition(StatusInitializing) }
func (sm *StateMachine) BeginRecon() error       { return sm.Transition(StatusRecon) }
func (sm *StateMachine) BeginClassifying() error { return sm.Transition(StatusClassifying) }
func (sm *StateMachine) BeginPlanning() error    { return sm.Transition(StatusPlanning) }
func (sm *StateMachine) BeginExecuting() error   { return sm.Transition(StatusExecuting) }
func (sm *StateMachine) BeginAdapting() error    { return sm.Transition(StatusAdapting) }
func (sm *StateMachine) BeginReporting() error   { return sm.Transition(StatusReporting) }
func (sm *StateMachine) Complete() error         { return sm.Transition(StatusComplete) }
func (sm *StateMachine) Fail(reason string) error {
	err := sm.Transition(StatusFailed)
	if err == nil && sm.onEvent != nil {
		sm.onEvent(CampaignEvent{
			CampaignID: sm.campaign.ID,
			Timestamp:  time.Now(),
			EventType:  EventError,
			Detail:     "Campaign failed: " + reason,
		})
	}
	return err
}

// Abort immediately stops the campaign.
func (sm *StateMachine) Abort() error {
	return sm.Transition(StatusAborted)
}

// Status returns the current campaign status.
func (sm *StateMachine) Status() CampaignStatus {
	return sm.campaign.Status
}

package pipeline

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/shellsafe"
)

// MemoryCleanupRegistry is a pool-less cleanup registry for installations
// without a database. Actions are held in memory and are replayed in reverse
// registration order on RunCleanup. Not durable across restarts, so a crash
// mid-campaign will leak artefacts — use the Postgres registry in production.
type MemoryCleanupRegistry struct {
	mu      sync.Mutex
	actions map[uuid.UUID][]CleanupAction
	exec    func(ctx context.Context, cmd string) error
}

// NewMemoryCleanupRegistry creates an in-memory cleanup registry. If exec is
// nil, RunCleanup will mark actions executed without actually running them
// (useful for tests and dry-runs).
func NewMemoryCleanupRegistry(exec func(ctx context.Context, cmd string) error) *MemoryCleanupRegistry {
	return &MemoryCleanupRegistry{
		actions: map[uuid.UUID][]CleanupAction{},
		exec:    exec,
	}
}

// Register records a cleanup command that should run if the campaign ends.
func (m *MemoryCleanupRegistry) Register(ctx context.Context, campaignID uuid.UUID, command, target string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.actions[campaignID] = append(m.actions[campaignID], CleanupAction{
		ID:           uuid.New(),
		CampaignID:   campaignID,
		Command:      command,
		Target:       target,
		RegisteredAt: time.Now(),
		Status:       "pending",
	})
	return nil
}

// RunCleanup executes all pending cleanup actions for a campaign in reverse order.
func (m *MemoryCleanupRegistry) RunCleanup(ctx context.Context, campaignID uuid.UUID) *CleanupReport {
	m.mu.Lock()
	actions := m.actions[campaignID]
	delete(m.actions, campaignID)
	m.mu.Unlock()

	report := &CleanupReport{CampaignID: campaignID, TotalCount: len(actions)}

	for i := len(actions) - 1; i >= 0; i-- {
		a := actions[i]
		if m.exec == nil {
			now := time.Now()
			a.ExecutedAt = &now
			a.Status = "executed"
			report.Executed = append(report.Executed, a)
			continue
		}
		err := m.exec(ctx, a.Command)
		now := time.Now()
		a.ExecutedAt = &now
		if err != nil {
			a.Status = "failed"
			report.Failed = append(report.Failed, a)
		} else {
			a.Status = "executed"
			report.Executed = append(report.Executed, a)
		}
	}
	return report
}

// PendingCleanup returns unexecuted cleanup actions for a campaign.
func (m *MemoryCleanupRegistry) PendingCleanup(ctx context.Context, campaignID uuid.UUID) ([]CleanupAction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]CleanupAction, len(m.actions[campaignID]))
	copy(out, m.actions[campaignID])
	return out, nil
}

// DefaultCleanupExec runs a cleanup command without going through a
// shell. Parsed with the same quote-aware, metachar-rejecting policy
// the exploit executor uses (shellsafe.Parse), so an LLM-authored
// cleanup command can't abuse pipes, redirects, or command substitution
// even if a prompt injection upstream crafts something that looks
// shell-friendly. Callers that genuinely need a shell must encode
// `sh -c "..."` as a single quoted token. See #44.3.
func DefaultCleanupExec(ctx context.Context, cmdStr string) error {
	parts, err := shellsafe.Parse(cmdStr)
	if err != nil {
		return fmt.Errorf("unsafe cleanup command: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	return cmd.Run()
}

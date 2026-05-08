package engine

import (
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
)

// TestZeroPostgresBoot pins Phase 4.8.4: the researcher flow MUST work
// without a Postgres connection. Construction must succeed when the
// config has no Database section, and falls back to the in-memory
// cleanup registry + in-memory blackboard.
//
// Regression guard — if a PR introduces a hard dependency on a DB
// pool (e.g. by panicking when cfg.Database.DSN is empty), this
// test fires before it merges.
func TestZeroPostgresBoot(t *testing.T) {
	cfg := &config.Config{}
	r := NewRunner(cfg)
	if r == nil {
		t.Fatal("NewRunner returned nil")
	}
	if r.cleanup == nil {
		t.Error("zero-DB runner should fall back to an in-memory cleanup registry, not nil")
	}
	// We don't actually run a campaign here — the smoke test only
	// verifies the cold-boot path is DB-free. End-to-end coverage of
	// the swarm path lives in tests/integration/swarm_e2e_test.go.
}

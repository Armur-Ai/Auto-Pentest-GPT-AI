package asm

import (
	"sync"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/google/uuid"
)

// SnapshotStore stores attack surface snapshots in memory.
// In production, this would persist to PostgreSQL.
type SnapshotStore struct {
	mu          sync.RWMutex
	snapshots   map[uuid.UUID][]*pipeline.AttackSurface // scopeID -> snapshots (newest last)
	maxPerScope int
}

// NewSnapshotStore creates a new snapshot store.
func NewSnapshotStore() *SnapshotStore {
	return &SnapshotStore{
		snapshots:   make(map[uuid.UUID][]*pipeline.AttackSurface),
		maxPerScope: 100,
	}
}

// Save stores a new snapshot.
func (s *SnapshotStore) Save(scopeID uuid.UUID, surface *pipeline.AttackSurface) {
	s.mu.Lock()
	defer s.mu.Unlock()

	snaps := s.snapshots[scopeID]
	snaps = append(snaps, surface)

	// Trim old snapshots
	if len(snaps) > s.maxPerScope {
		snaps = snaps[len(snaps)-s.maxPerScope:]
	}

	s.snapshots[scopeID] = snaps
}

// GetLatest returns the most recent snapshot, or nil.
func (s *SnapshotStore) GetLatest(scopeID uuid.UUID) *pipeline.AttackSurface {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snaps := s.snapshots[scopeID]
	if len(snaps) == 0 {
		return nil
	}
	return snaps[len(snaps)-1]
}

// GetHistory returns the N most recent snapshots.
func (s *SnapshotStore) GetHistory(scopeID uuid.UUID, limit int) []*pipeline.AttackSurface {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snaps := s.snapshots[scopeID]
	if len(snaps) <= limit {
		result := make([]*pipeline.AttackSurface, len(snaps))
		copy(result, snaps)
		return result
	}

	result := make([]*pipeline.AttackSurface, limit)
	copy(result, snaps[len(snaps)-limit:])
	return result
}

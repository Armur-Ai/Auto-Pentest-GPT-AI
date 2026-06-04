package asm

import (
	"context"
	"sync"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/google/uuid"
)

// WatchedScope defines a scope being continuously monitored.
type WatchedScope struct {
	ID        uuid.UUID                `json:"id"`
	Target    string                   `json:"target"`
	Scope     pipeline.ScopeDefinition `json:"scope"`
	Schedule  time.Duration            `json:"schedule"`
	AuthToken string                   `json:"-"`
	Active    bool                     `json:"active"`
	CreatedAt time.Time                `json:"created_at"`
}

// ScopeWatcher continuously monitors scopes for asset changes.
type ScopeWatcher struct {
	scopes    map[uuid.UUID]*WatchedScope
	mu        sync.RWMutex
	onChange  func(scopeID uuid.UUID, diff *AssetDiff)
	reconFunc func(ctx context.Context, target string, scope pipeline.ScopeDefinition) (*pipeline.AttackSurface, error)
	snapStore *SnapshotStore
}

// NewScopeWatcher creates a new scope watcher.
func NewScopeWatcher(
	snapStore *SnapshotStore,
	reconFunc func(ctx context.Context, target string, scope pipeline.ScopeDefinition) (*pipeline.AttackSurface, error),
	onChange func(scopeID uuid.UUID, diff *AssetDiff),
) *ScopeWatcher {
	return &ScopeWatcher{
		scopes:    make(map[uuid.UUID]*WatchedScope),
		onChange:  onChange,
		reconFunc: reconFunc,
		snapStore: snapStore,
	}
}

// AddScope starts watching a new scope.
func (w *ScopeWatcher) AddScope(ws WatchedScope) {
	w.mu.Lock()
	ws.Active = true
	w.scopes[ws.ID] = &ws
	w.mu.Unlock()

	go w.watchLoop(ws.ID)
}

// RemoveScope stops watching a scope.
func (w *ScopeWatcher) RemoveScope(id uuid.UUID) {
	w.mu.Lock()
	if s, ok := w.scopes[id]; ok {
		s.Active = false
	}
	delete(w.scopes, id)
	w.mu.Unlock()
}

// ListScopes returns all watched scopes.
func (w *ScopeWatcher) ListScopes() []WatchedScope {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var result []WatchedScope
	for _, s := range w.scopes {
		result = append(result, *s)
	}
	return result
}

func (w *ScopeWatcher) watchLoop(scopeID uuid.UUID) {
	for {
		w.mu.RLock()
		ws, ok := w.scopes[scopeID]
		if !ok || !ws.Active {
			w.mu.RUnlock()
			return
		}
		schedule := ws.Schedule
		target := ws.Target
		scope := ws.Scope
		w.mu.RUnlock()

		// Run recon
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		surface, err := w.reconFunc(ctx, target, scope)
		cancel()

		if err == nil && surface != nil {
			// Get previous snapshot
			prev := w.snapStore.GetLatest(scopeID)

			// Save current
			w.snapStore.Save(scopeID, surface)

			// Diff
			if prev != nil {
				diff := Diff(prev, surface)
				if diff.IsSignificant() {
					w.onChange(scopeID, diff)
				}
			}
		}

		// Sleep until next scan
		time.Sleep(schedule)
	}
}

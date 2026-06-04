package memory

import (
	"sync"
	"time"
)

// MemoryEntry is a learned pattern from a previous campaign.
type MemoryEntry struct {
	ID         string    `json:"id"`
	Category   string    `json:"category"` // tech_stack, attack_chain, false_positive, timing
	Pattern    string    `json:"pattern"`
	Confidence float64   `json:"confidence"`
	UsageCount int       `json:"usage_count"`
	LastUsed   time.Time `json:"last_used"`
	CreatedAt  time.Time `json:"created_at"`
}

// MemoryStore persists learned patterns across campaigns.
type MemoryStore struct {
	mu      sync.RWMutex
	entries []MemoryEntry
}

// NewMemoryStore creates a new memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

// Save persists a new memory entry.
func (m *MemoryStore) Save(entry MemoryEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry.CreatedAt = time.Now()
	entry.LastUsed = time.Now()
	entry.UsageCount = 1
	m.entries = append(m.entries, entry)
}

// RecallRelevant returns memories matching the given tech stack keywords.
func (m *MemoryStore) RecallRelevant(keywords []string) []MemoryEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var relevant []MemoryEntry
	for _, entry := range m.entries {
		for _, kw := range keywords {
			if containsCI(entry.Pattern, kw) {
				relevant = append(relevant, entry)
				break
			}
		}
	}
	return relevant
}

// All returns all stored memory entries.
func (m *MemoryStore) All() []MemoryEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]MemoryEntry, len(m.entries))
	copy(result, m.entries)
	return result
}

// Clear removes all memory entries.
func (m *MemoryStore) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = nil
}

// Count returns the number of stored patterns.
func (m *MemoryStore) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.entries)
}

func containsCI(s, substr string) bool {
	s = toLower(s)
	substr = toLower(substr)
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b[i] = s[i] + 32
		} else {
			b[i] = s[i]
		}
	}
	return string(b)
}

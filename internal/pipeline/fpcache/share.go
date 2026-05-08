package fpcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SharedPattern is the anonymized variant of a Pattern, safe to publish
// to the community FP corpus (Phase 4.6.6).
//
// What's stripped:
//   - Target — would leak the program the researcher was scanning
//   - Reason — researchers often paste customer-internal context here
//
// What's kept:
//   - AttackCategory — necessary to match other researchers' findings
//   - TitleHash — SHA-256 over the lowercased title's *normalized*
//     tokens (stopwords stripped, sorted, joined). Preserves enough
//     signal to compare patterns across researchers without exposing
//     the original wording (which can leak the target's tech stack).
type SharedPattern struct {
	AttackCategory string `json:"attack_category"`
	TitleHash      string `json:"title_hash"`
	// Schema version — lets the corpus evolve without orphaning old
	// uploads. Bump when the hashing or stripping rules change.
	Schema int `json:"schema"`
}

const sharedSchemaVersion = 1

// Anonymize converts a Pattern into a SharedPattern. Target + reason
// are dropped; title is hashed.
func Anonymize(p Pattern) SharedPattern {
	return SharedPattern{
		AttackCategory: strings.ToLower(p.AttackCategory),
		TitleHash:      titleHash(p.TitleContains),
		Schema:         sharedSchemaVersion,
	}
}

// ExportShare reads every Pattern from the store, anonymizes each, and
// writes them to outPath as line-delimited JSON. Returns the number
// written. The file is the upload payload — researchers who opt in
// run `pentestswarm fp share` and post the file to the corpus
// endpoint manually (until automated upload ships in 4.7.1).
func (s *Store) ExportShare(outPath string) (int, error) {
	s.mu.RLock()
	patterns := make([]Pattern, len(s.patterns))
	copy(patterns, s.patterns)
	s.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return 0, err
	}
	f, err := os.Create(outPath)
	if err != nil {
		return 0, fmt.Errorf("create share file: %w", err)
	}
	defer f.Close()

	written := 0
	enc := json.NewEncoder(f)
	for _, p := range patterns {
		// Skip anonymous-only fields with zero info value.
		if p.AttackCategory == "" && p.TitleContains == "" {
			continue
		}
		if err := enc.Encode(Anonymize(p)); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// titleHash normalizes + hashes a title so two researchers who marked
// "SQL Injection in /search" vs "Sql injection on the search endpoint"
// land on the same hash — same thing, different wording.
//
// Algorithm: lowercase → split on non-alnum → drop stopwords + tokens
// shorter than 3 chars → sort → join with spaces → SHA-256 → hex.
func titleHash(title string) string {
	out := []string{}
	cur := strings.Builder{}
	flush := func() {
		w := cur.String()
		cur.Reset()
		if len(w) < 3 {
			return
		}
		if _, stop := titleHashStopwords[w]; stop {
			return
		}
		out = append(out, w)
	}
	for _, r := range strings.ToLower(title) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	// Sort tokens so different orderings hash to the same value.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	joined := strings.Join(out, " ")
	sum := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(sum[:])
}

var titleHashStopwords = map[string]struct{}{
	"the": {}, "and": {}, "for": {}, "with": {}, "via": {},
	"from": {}, "into": {}, "onto": {}, "thru": {}, "through": {},
	"endpoint": {}, "endpoints": {}, // common but uninformative
}

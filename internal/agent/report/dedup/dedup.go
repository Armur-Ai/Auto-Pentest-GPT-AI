// Package dedup detects likely duplicate submissions by comparing a new
// finding's title (+ optional target) against a corpus of prior reports.
//
// Used twice:
//   - Phase 4.4.5: against the researcher's OWN prior submissions on a
//     program, so we don't file the same bug twice
//   - Phase 4.4.6: against the program's PUBLIC disclosed reports (where
//     available), so we don't file something already triaged away
//
// Algorithm is deliberately simple: token-set Jaccard similarity with
// stopword removal. Good enough to catch "SQL Injection in /search" vs
// "Sql injection on the search endpoint". Fancier edit-distance metrics
// would add dependencies for marginal accuracy gains at this stage.
package dedup

import "strings"

// Prior is a minimal record of a past submission — just enough for
// title-based matching. Callers map platform-specific shapes onto this.
type Prior struct {
	ID     string
	Title  string
	Target string // optional; if set, we boost similarity when it matches
	State  string // optional state, e.g. "duplicate", "resolved"
}

// Match is a ranked hit: (the prior report, similarity 0..1).
type Match struct {
	Prior      Prior
	Similarity float64
}

// FindDuplicates returns the top-K matches above threshold for a new
// finding's title. Empty result = no credible duplicates.
//
// Threshold 0.6 is a reasonable default — titles with 60%+ word overlap
// are very often the same bug. Tune down if researchers complain about
// missed duplicates, up if they complain about false-duplicate flags.
func FindDuplicates(title, target string, priors []Prior, threshold float64, k int) []Match {
	if threshold <= 0 {
		threshold = 0.6
	}
	if k <= 0 {
		k = 3
	}
	tokens := tokenise(title)
	var hits []Match
	for _, p := range priors {
		sim := jaccard(tokens, tokenise(p.Title))
		if target != "" && p.Target != "" && strings.EqualFold(target, p.Target) {
			// A matching target is a strong signal — nudge similarity up.
			sim = 1.0 - (1.0-sim)*0.5
		}
		if sim >= threshold {
			hits = append(hits, Match{Prior: p, Similarity: sim})
		}
	}
	// Simple selection sort — corpora here are tiny (dozens, not millions).
	for i := 0; i < len(hits); i++ {
		best := i
		for j := i + 1; j < len(hits); j++ {
			if hits[j].Similarity > hits[best].Similarity {
				best = j
			}
		}
		hits[i], hits[best] = hits[best], hits[i]
	}
	if len(hits) > k {
		hits = hits[:k]
	}
	return hits
}

// --- internals ---

var stopwords = map[string]struct{}{}

func init() {
	for _, w := range []string{
		"a", "an", "and", "at", "by", "for", "in", "is", "it", "of",
		"on", "or", "the", "to", "via", "with", "through",
	} {
		stopwords[w] = struct{}{}
	}
}

// tokenise lowercases + splits on non-alphanumeric + strips stopwords.
func tokenise(s string) map[string]struct{} {
	out := map[string]struct{}{}
	cur := strings.Builder{}
	flush := func() {
		w := cur.String()
		cur.Reset()
		if len(w) < 2 {
			return
		}
		if _, stop := stopwords[w]; stop {
			return
		}
		out[w] = struct{}{}
	}
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

// jaccard = |A ∩ B| / |A ∪ B|. 1.0 = identical sets, 0.0 = disjoint.
func jaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if _, ok := b[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

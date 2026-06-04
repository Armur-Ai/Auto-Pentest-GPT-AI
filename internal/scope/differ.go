package scope

import "sort"

// Diff summarizes additions + removals + unchanged between two scopes.
// Callers decide how to render — JSON, colored terminal, SARIF, etc.
type Diff struct {
	AddedDomains   []string `json:"added_domains"`
	RemovedDomains []string `json:"removed_domains"`
	AddedCIDRs     []string `json:"added_cidrs"`
	RemovedCIDRs   []string `json:"removed_cidrs"`
	Unchanged      int      `json:"unchanged_count"`
}

// HasChanges is true when either side is non-empty — useful for exit codes.
func (d Diff) HasChanges() bool {
	return len(d.AddedDomains) > 0 || len(d.RemovedDomains) > 0 ||
		len(d.AddedCIDRs) > 0 || len(d.RemovedCIDRs) > 0
}

// Compare returns a Diff describing what changed from prev to cur.
func Compare(prev, cur ScopeDefinition) Diff {
	d := Diff{
		AddedDomains:   setDiff(cur.AllowedDomains, prev.AllowedDomains),
		RemovedDomains: setDiff(prev.AllowedDomains, cur.AllowedDomains),
		AddedCIDRs:     setDiff(cur.AllowedCIDRs, prev.AllowedCIDRs),
		RemovedCIDRs:   setDiff(prev.AllowedCIDRs, cur.AllowedCIDRs),
	}
	d.Unchanged = len(cur.AllowedDomains) + len(cur.AllowedCIDRs) -
		len(d.AddedDomains) - len(d.AddedCIDRs)
	return d
}

// setDiff returns elements of a that are not in b, sorted for stable output.
func setDiff(a, b []string) []string {
	bSet := make(map[string]struct{}, len(b))
	for _, x := range b {
		bSet[x] = struct{}{}
	}
	var out []string
	for _, x := range a {
		if _, in := bSet[x]; !in {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

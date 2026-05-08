package plugins

// Overlay merges a per-program tuning playbook on top of a base
// playbook (Phase 4.6.7).
//
// The community pattern: `playbooks/bug-bounty.yaml` is the base, and
// `playbooks/programs/<slug>.yaml` is a small overlay containing only
// what's special about that program — variable overrides, additional
// phases, focus hints. This keeps the base playbook generic and lets
// program-specific knowledge accumulate without forking.
//
// Merge semantics:
//   - Name, Description, Author, Version: overlay wins when non-empty.
//   - Tags: union (de-duped).
//   - Variables: overlay wins per-key.
//   - Phases: overlay phases are appended AFTER base phases. To
//     replace a base phase, give the overlay phase the same Name —
//     it then *replaces* the base phase in-place (preserving order).
//   - Include: union, deduplicated.
//
// The merge does NOT validate the result. Run plugins.Validate() on
// the merged playbook before executing it — that's the contract.
func Overlay(base, overlay *Playbook) *Playbook {
	if base == nil {
		return overlay
	}
	if overlay == nil {
		// Return a shallow copy so callers don't mutate the input.
		c := *base
		return &c
	}

	out := *base
	if overlay.Name != "" {
		out.Name = overlay.Name
	}
	if overlay.Description != "" {
		out.Description = overlay.Description
	}
	if overlay.Author.Name != "" || overlay.Author.GitHub != "" {
		out.Author = overlay.Author
	}
	if overlay.Version != "" {
		out.Version = overlay.Version
	}

	// Tags — union, dedup. Preserve base order, append unseen overlay
	// tags so program-specific tags rank lower in any list display.
	seen := map[string]struct{}{}
	tags := make([]string, 0, len(base.Tags)+len(overlay.Tags))
	for _, t := range base.Tags {
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			tags = append(tags, t)
		}
	}
	for _, t := range overlay.Tags {
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			tags = append(tags, t)
		}
	}
	out.Tags = tags

	// Variables — copy base, then overlay-wins per key.
	if len(base.Variables) > 0 || len(overlay.Variables) > 0 {
		merged := map[string]Variable{}
		for k, v := range base.Variables {
			merged[k] = v
		}
		for k, v := range overlay.Variables {
			merged[k] = v
		}
		out.Variables = merged
	}

	// Phases — replace by name, otherwise append. Preserves base order.
	out.Phases = mergePhases(base.Phases, overlay.Phases)

	// Includes — union, dedup.
	seenInc := map[string]struct{}{}
	includes := make([]string, 0, len(base.Include)+len(overlay.Include))
	for _, s := range base.Include {
		if _, ok := seenInc[s]; !ok {
			seenInc[s] = struct{}{}
			includes = append(includes, s)
		}
	}
	for _, s := range overlay.Include {
		if _, ok := seenInc[s]; !ok {
			seenInc[s] = struct{}{}
			includes = append(includes, s)
		}
	}
	out.Include = includes

	return &out
}

func mergePhases(base, overlay []Phase) []Phase {
	if len(overlay) == 0 {
		return append([]Phase{}, base...)
	}
	// Index base phases by name so overlay can replace by name.
	idx := map[string]int{}
	for i, p := range base {
		idx[p.Name] = i
	}
	out := append([]Phase{}, base...)
	for _, op := range overlay {
		if i, ok := idx[op.Name]; ok {
			out[i] = op
			continue
		}
		out = append(out, op)
	}
	return out
}

<!--
Thanks for the PR. Filling this out properly makes review ~10x faster
and means we can usually merge same-day if CI is green.

Tight, scoped PRs ship. Sprawling PRs sit. If this PR touches >5 files,
consider whether it could be split.
-->

## Summary

<!-- One paragraph. What did you do, and why? -->

## Plan item

<!-- If this PR closes a roadmap task, reference the plan item:
       Closes #123  (where 123 is the issue tracking the plan item)
     If there's no tracking issue yet, link the line in IMPLEMENTATION_PLAN.md. -->

Closes #

## Testing

<!-- How did you verify this works? At minimum:
       - Unit tests added (`go test ./internal/<pkg>/...` passes)
       - Local build clean (`go build ./...`)
     For tool-adapter / external-API changes, also describe any manual
     end-to-end check you ran. -->

- [ ] Unit tests added or updated
- [ ] `go build ./...` clean
- [ ] `go test ./internal/...` green
- [ ] Manual verification (if applicable):

## Anything reviewers should look at carefully?

<!-- Subtle behaviour change? Security-sensitive code? Public API
     change? Call it out explicitly so it doesn't get missed in review. -->

## Checklist

- [ ] Commit messages follow the convention seen in `git log` (`feat(area): …`, `fix(area): …`, `docs(area): …`, etc.)
- [ ] UK English in comments (the project uses defence / colour / customise / sanitise / artefact — not US spellings)
- [ ] No unrelated scope creep — single feature / fix per PR
- [ ] Contribution is under AGPL-3.0 (same as the project's LICENSE)

# Contributing to Pentest Swarm AI

Thanks for sending a PR. Three things before you do.

## 1. The one-command invariant (4.8.1)

**A researcher must be able to find a real bug with one command.**

```bash
pentestswarm scan example.com
```

That's the only command they should *need* to know. Everything else
(`scope import`, `program inspect`, `submit`, `report polish`, `fp share`)
is optional polish that pays for itself only when the user asks for it.

**This is enforced at review time, not by tooling.** If your PR adds a
required step to the `scan` flow — a new flag the user MUST set, a new
file the user MUST author, a new CLI command the user MUST run before
`scan` works — the PR will be rejected unless you can show that the
default behavior still works without it.

Concrete examples:

- ✅ A new optional flag `--foo` that improves things when set
- ✅ A new file `~/.pentestswarm/foo.yaml` that's auto-created with
  sensible defaults if missing
- ✅ A new command `pentestswarm bar` that augments the workflow
- ❌ Making `--scope` required again (we removed it intentionally; the
  default infers scope from the target — see [4.8.5](IMPLEMENTATION_PLAN.md))
- ❌ A migration that breaks existing `~/.pentestswarm/config.yaml`
- ❌ A new "you must run `pentestswarm setup-thing` first" step

When in doubt: if a researcher who installed the tool yesterday can't
follow the [Quick Start in the README](README.md#quick-start) verbatim
after your PR, the PR isn't done.

## 2. The CLI UX budget (4.8.2)

`pentestswarm --help` must fit in **30 lines or fewer** so it stays on
one laptop screen.

Adding a new top-level command is fine, but if it pushes the help
output past 30 lines, you have to either:

- Hide it with `Hidden: true` on the cobra command (still callable via
  `pentestswarm <command> --help`, just not in the index), or
- Combine it under an existing parent command (e.g., `pentestswarm scope
  <thing>` instead of a new top-level)

Verify with:

```bash
pentestswarm --help | wc -l
```

CI doesn't enforce this yet — reviewer call.

## 3. Error messages must end with a next step (4.8.3)

Every error path the user can hit needs to tell them what to do next.

```go
// ✅ Good — actionable
return fmt.Errorf("no API key configured.\n  Fix: run %s",
    colorCyan("pentestswarm init"))

// ❌ Bad — leaves the user guessing
return fmt.Errorf("no API key")
```

The litmus test: if a reasonable researcher encounters this error, does
the message tell them what command to run, what file to edit, or what
docs page to read? If not, fix the message before merging.

## Other things worth knowing

- **Conventional commit prefixes** are used: `feat:`, `fix:`, `docs:`,
  `test:`, `chore:`, `refactor:`. Scope in parens is optional but
  helpful: `feat(scheduler): ...`.

- **Tests come with the code.** New packages ship with a `_test.go`
  file, even if it only has one happy-path test. CI fails without one.

- **No new external deps without a reason.** `go.mod` should be small.
  We declined `golang.org/x/time/rate` for the rate limiter and rolled
  ~50 lines instead — that's the bar.

- **Plan check-offs.** If your PR completes a phase task in
  [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md), tick the box and
  rewrite the bullet to describe what actually shipped (paths, function
  names, behavior). That keeps the plan honest as a record of *what
  exists*, not just *what was promised*.

## Reporting security issues

Don't open a public issue. Email the security inbox listed in
[SECURITY.md](SECURITY.md), or open a private GitHub Security Advisory.
Same applies to vulnerabilities in dependencies.

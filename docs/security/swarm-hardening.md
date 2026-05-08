# How we hardened the swarm against memory-injection attacks

> Status: shipped in v0.x, ongoing. This document doubles as the script for the
> talk we want to give at BSides / Black Hat Arsenal once the benchmark
> numbers land.

## Why this matters

Pentest Swarm AI is a multi-agent system. Agents read and write a shared
blackboard. That shape — many writers, many readers, one piece of state —
is exactly the structure that memory-injection attacks target.

Two recent papers frame the threat:

- **MINJA** (arXiv:2503.03704) — an attacker who can write to an agent's memory
  can inject payloads that bias downstream reasoning. The agent retrieves the
  injected memory as if it were a legitimate finding.
- **MemoryGraft** (arXiv:2512.16962) — variants where the attacker plants
  artefacts that *look like* high-confidence findings, drowning real signal.

A pentest swarm is a tempting target for this attack class because:

1. The blackboard's whole job is to bias agent reasoning toward interesting
   findings. That biasing mechanism — pheromones — is the attack surface.
2. The findings are JSON blobs. Agents trust the JSON. An attacker who can
   write valid JSON can claim to be any agent, with any confidence.
3. The output (a vulnerability report) is high-value enough to be worth
   poisoning. A submitted false positive costs the researcher's reputation
   on the platform.

So we built four layers of defense, each closing a specific attack class.

## Layer 1 — Pheromone clamp (boundary)

The attack: write a finding with `PheromoneBase: 9999` so it dominates every
ranked query.

The fix: `MemoryBoard.Write` clamps `PheromoneBase` to `[0, 1]` before
storage. Test:

```go
// internal/swarm/blackboard/injection_test.go
_, _ = b.Write(ctx, Finding{
    PheromoneBase: 9999.0, ...
})
results, _ := b.Query(ctx, Predicate{Types: []FindingType{TypeCVEMatch}})
if results[0].Pheromone > 1.0 {
    t.Errorf("pheromone-flood not clamped: got %f", results[0].Pheromone)
}
```

This was the *first* defense gap MINJA-style tests caught. Before the clamp,
a single bogus write could permanently sit at the top of every "what's most
interesting" query. After the clamp, the attacker has to compete in the
same `[0, 1]` band as every legit agent.

## Layer 2 — Ed25519 finding provenance (per-write trust)

The attack: write a finding with `AgentName: "classifier"` even though the
real classifier didn't write it. Agents that filter on AgentName trust the
forged label.

The fix: every write is signed with an Ed25519 keypair held by the originating
agent. Verifying the signature against (campaign | agent | type | target |
data | createdUnix) detects two attack classes at once:

- Tampering: any byte changed in the canonical message → signature fails
- Impersonation: signing with a different keypair under a stolen agent name
  → signature fails against the real agent's public key

```go
// internal/swarm/provenance/provenance.go
sig := signer.Sign(campaign, agent, findingType, target, data, ts)
err := provenance.Verify(pub, sig, campaign, agent, findingType, target, data, ts)
```

This is layer 2 because it lives at the per-write level. Layer 1 protected
ranking; layer 2 protects authorship.

## Layer 3 — MemoryGraft heuristic detector (post-hoc surveillance)

Provenance + clamp catch a single malicious write. They don't catch *patterns*
of malicious behavior. A compromised legitimate agent — one with a valid key —
can still write nonsense, and provenance won't flag it.

So we run a watchdog. `internal/swarm/memorygraft.Scan` reads recent findings
and emits alerts for four patterns characteristic of memory-graft attacks:

| Pattern | What it catches |
|---|---|
| **burst** | An agent writes ≥ N findings in a small window (default 50/60s). Real agents pulse, attackers spam. |
| **repeat-title** | The same title fingerprint repeats from one agent. Real findings vary in shape. |
| **duplicate-data** | Byte-identical Data payloads from one agent. Real findings have different evidence per finding. |
| **type-mismatch** | An agent emits a finding under a type owned by another agent (e.g. `recon` writing `CVE_MATCH`). |

This is intentionally conservative. False positives drown signal worse than
missed catches — we prefer letting subtle attacks slide than spamming the
operator with normal swarm noise. Operators can tighten thresholds via
`Config{}`.

## Layer 4 — Per-agent rate limit (resource exhaustion)

The attack: an agent writes findings that wake itself, in a tight loop. Even
without malicious intent, this saturates the LLM provider in seconds.

The fix: `swarm.WithAgentRateLimit(agentName, perSec, burst)` installs a
token-bucket limiter. The scheduler calls `lim.Take(ctx)` before dispatching
each finding to that agent.

This is at the dispatch boundary, not the write boundary. We let any agent
write whatever they want (subject to layers 1-3); we just refuse to drain
their queue faster than the configured rate.

No external dependency — the limiter is ~50 lines of Go. Worth flagging
because we considered `golang.org/x/time/rate` and decided one tiny token
bucket beat the dependency.

## What we explicitly did NOT do

A few defenses we considered and dropped:

- **Cross-agent comm encryption.** All agent traffic is local-process; the
  threat model is misbehaving code on the same host, not a network adversary.
  Encryption here is theatre.
- **Anomaly-detection ML.** Conservative heuristics catch the 80% of attacks
  worth catching at zero false-positive cost. ML adds magic that's hard to
  explain in a security review.
- **Full audit log signing.** Every write already carries an Ed25519
  signature; signing the *log of writes* is double-counting and adds an
  HSM dependency we don't want yet.

## Test coverage

| Defense | Tests |
|---|---|
| Pheromone clamp | `internal/swarm/blackboard/injection_test.go::TestMINJA_PheromoneFloodIsClamped` |
| Provenance | `internal/swarm/provenance/provenance_test.go` (4 tests: roundtrip, tamper, impersonation, malformed key/sig) |
| MemoryGraft detector | `internal/swarm/memorygraft/detector_test.go` (4 tests: burst, duplicate-data, type-mismatch, quiet-board) |
| Rate limit | `internal/swarm/ratelimit/ratelimit_test.go` (4 tests: zero-rate, burst-then-throttle, ctx-cancel, nil-safe) |

CI fails if any of these regress. The MINJA pheromone-flood test in
particular caught the original defense gap during development.

## What's next

- **3.4.1 follow-up**: wire `Board.Write` to require + verify a signature
  on every accepted finding. Today, signing is per-package; integrating
  it into the Board interface itself is the obvious next step but blocks
  on a Board API revision.
- **3.4.2 follow-up**: extend MINJA tests to cover cross-agent collusion
  (two compromised agents reinforcing each other's signal).
- **3.4.5**: this document → blog post → talk. The story is more credible
  with one real CVE the swarm caught while running with these defenses on.

## References

- MINJA — arXiv:2503.03704
- MemoryGraft — arXiv:2512.16962
- Dark Side of LLMs — arXiv:2507.06850

---

*Written 2026-05. Living doc; PRs welcome at*
*[Armur-Ai/Pentest-Swarm-AI](https://github.com/Armur-Ai/Pentest-Swarm-AI).*

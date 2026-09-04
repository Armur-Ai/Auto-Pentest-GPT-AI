# Speed benchmark — swarm vs. sequential

The most on-brand number we can publish: **same findings, N× faster.**

Pentest Swarm's whole thesis is that it's a *real* swarm — agents working a
target concurrently through a shared blackboard — not a pipeline that runs
recon → classify → exploit → report one step at a time. This benchmark proves
exactly that, and it's far cheaper to produce than an exploitation benchmark
(Cybench / XBOW): run the same scan twice, time both, check the findings match.

Tracked as **D.9.4** in `IMPLEMENTATION_PLAN.md`.

## What it measures

For each target, a `Trial` records:

- `SwarmDuration` — wall-clock for `pentestswarm scan --swarm`
- `SequentialDuration` — wall-clock for the sequential runner
- `SwarmFindings` / `SequentialFindings` — so we can assert **parity**

`Summarize` folds trials into the headline (`Summary.Headline()`), e.g.
`3.8× faster, same findings (5 targets)`. The parity check is a deliberate
honesty guard: if the swarm is faster only because it dropped findings, the
summary says so instead of overclaiming.

The scoring types (`speed.go`) are pure and unit-tested (`speed_test.go`).

## Producing real numbers

`ShellRunner` (in `runner.go`) is the concrete `Runner`: it shells out to the
`pentestswarm` binary, scans a target once with `--swarm` and once sequentially,
times both, and counts findings from each JSON report. It's driven by the
env-guarded live test so it stays out of normal `go test`.

Run it against the **bundled lab target** (D.9.1) so the numbers are
reproducible and legal — no external host, and no API key if you point
`--provider ollama` at a local model:

```bash
# 1. build the binary + bring the lab up
make build
docker compose -f deploy/lab/docker-compose.yml up -d
until curl -sf http://localhost:3000/rest/admin/application-version >/dev/null; do sleep 3; done

# 2. run the head-to-head (swarm vs sequential), print the headline
SPEEDBENCH_BIN=./bin/pentestswarm \
SPEEDBENCH_TARGET=http://localhost:3000 \
SPEEDBENCH_SCOPE=127.0.0.1/32,localhost \
SPEEDBENCH_EXTRA="--provider ollama" \
  go test ./tests/bench/speed -run Live -v

# 3. tear the lab down
docker compose -f deploy/lab/docker-compose.yml down -v
```

The live test logs `swarm=… sequential=… findings swarm/seq=…` and the
`Summarize` headline (e.g. `3.8× faster, same findings (1 targets)`). Run
several targets and average. Publish the chart in `docs/benchmarks.md` + the
README, and **always label the setup** (targets, model, hardware) — an honest,
reproducible number is worth more than a big one. The `FindingsParity` guard
refuses to claim "same findings" if the swarm dropped any.

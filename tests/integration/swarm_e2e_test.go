package integration

import (
	"context"
	"encoding/json"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
	"github.com/google/uuid"
)

// TestSwarmEndToEnd_StubbedAgents runs the full scheduler loop with
// stubbed agents standing in for recon / classifier / exploit.
// Verifies three invariants of the swarm model:
//  1. Findings flow strictly via the blackboard — no direct agent→agent calls.
//  2. An agent's Trigger predicate gates dispatch: classifier only fires on
//     raw recon findings, exploit only on CVE_MATCH above the pheromone gate.
//  3. The scheduler returns cleanly once CAMPAIGN_COMPLETE is written and
//     the final board snapshot matches the golden list.
//
// No LLM, no Postgres, no network — everything is in-process so this test
// runs in CI in <1 s.
func TestSwarmEndToEnd_StubbedAgents(t *testing.T) {
	board := blackboard.NewMemoryBoard(nil)
	campaignID := uuid.New()

	var reconCalls, classifierCalls, exploitCalls int32

	// Recon: triggers on TARGET_REGISTERED, publishes 2 SUBDOMAINs.
	recon := swarm.NamedPredicate{
		AgentName: "recon",
		Pred:      blackboard.Predicate{Types: []blackboard.FindingType{blackboard.TypeTargetRegistered}},
		Parallel:  1,
		Fn: func(ctx context.Context, f blackboard.Finding, b blackboard.Board) error {
			atomic.AddInt32(&reconCalls, 1)
			for _, sub := range []string{"api.example.com", "www.example.com"} {
				data, _ := json.Marshal(map[string]string{"domain": sub})
				_, _ = b.Write(ctx, blackboard.Finding{
					CampaignID: campaignID, AgentName: "recon",
					Type: blackboard.TypeSubdomain, Target: sub, Data: data,
					PheromoneBase: 0.8, HalfLifeSec: 7200,
				})
			}
			return nil
		},
	}

	// Classifier: triggers on SUBDOMAIN, publishes CVE_MATCH with high pheromone
	// on the "api." host only — simulating a real classifier ranking.
	classifier := swarm.NamedPredicate{
		AgentName: "classifier",
		Pred: blackboard.Predicate{
			Types:        []blackboard.FindingType{blackboard.TypeSubdomain},
			MinPheromone: 0.2,
		},
		Parallel: 2,
		Fn: func(ctx context.Context, f blackboard.Finding, b blackboard.Board) error {
			atomic.AddInt32(&classifierCalls, 1)
			pheromone := 0.3 // low pheromone = exploit won't fire
			if f.Target == "api.example.com" {
				pheromone = 0.9 // high = exploit MUST fire
			}
			data, _ := json.Marshal(map[string]string{"subject": f.Target})
			_, _ = b.Write(ctx, blackboard.Finding{
				CampaignID: campaignID, AgentName: "classifier",
				Type: blackboard.TypeCVEMatch, Target: f.Target, Data: data,
				PheromoneBase: pheromone, HalfLifeSec: 3600,
			})
			return nil
		},
	}

	// Exploit: triggers ONLY on CVE_MATCH with pheromone >= 0.5. In this
	// scenario that means api.example.com only.
	exploit := swarm.NamedPredicate{
		AgentName: "exploit",
		Pred: blackboard.Predicate{
			Types:        []blackboard.FindingType{blackboard.TypeCVEMatch},
			MinPheromone: 0.5,
		},
		Parallel: 1,
		Fn: func(ctx context.Context, f blackboard.Finding, b blackboard.Board) error {
			atomic.AddInt32(&exploitCalls, 1)
			data, _ := json.Marshal(map[string]string{"verdict": "exploited"})
			_, _ = b.Write(ctx, blackboard.Finding{
				CampaignID: campaignID, AgentName: "exploit",
				Type: blackboard.TypeExploitResult, Target: f.Target, Data: data,
				PheromoneBase: 1.0, HalfLifeSec: 1800,
			})
			return nil
		},
	}

	sched := swarm.NewScheduler(board, campaignID)
	sched.Register(recon)
	sched.Register(classifier)
	sched.Register(exploit)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- sched.Run(ctx) }()

	// Seed and wait for the chain to settle.
	_, err := board.Write(ctx, blackboard.Finding{
		CampaignID: campaignID, AgentName: "engine",
		Type: blackboard.TypeTargetRegistered, Target: "example.com",
		PheromoneBase: 1.0, HalfLifeSec: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Poll until the chain has fully propagated.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&exploitCalls) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// End the campaign so the scheduler returns.
	_, _ = board.Write(ctx, blackboard.Finding{
		CampaignID: campaignID, AgentName: "engine",
		Type: blackboard.TypeCampaignComplete, Target: "example.com",
		PheromoneBase: 1.0, HalfLifeSec: 300,
	})

	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("scheduler returned error: %v", runErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not return after CAMPAIGN_COMPLETE")
	}

	// --- Invariants ---

	if got := atomic.LoadInt32(&reconCalls); got != 1 {
		t.Errorf("recon should fire exactly once for the seed, got %d", got)
	}
	if got := atomic.LoadInt32(&classifierCalls); got != 2 {
		t.Errorf("classifier should fire for both subdomains, got %d", got)
	}
	// Exploit should fire exactly once — only api.example.com had pheromone
	// above the 0.5 gate.
	if got := atomic.LoadInt32(&exploitCalls); got != 1 {
		t.Errorf("exploit should fire only for high-pheromone finding, got %d", got)
	}

	// Golden final-state shape: finding-type counts.
	all, err := board.Query(context.Background(), blackboard.Predicate{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[blackboard.FindingType]int{}
	for _, f := range all {
		counts[f.Type]++
	}
	want := map[blackboard.FindingType]int{
		blackboard.TypeTargetRegistered: 1,
		blackboard.TypeSubdomain:        2,
		blackboard.TypeCVEMatch:         2,
		blackboard.TypeExploitResult:    1,
		blackboard.TypeCampaignComplete: 1,
	}
	if !equalCounts(counts, want) {
		t.Fatalf("board counts mismatch\nwant: %v\ngot:  %v", prettyCounts(want), prettyCounts(counts))
	}
}

func equalCounts(a, b map[blackboard.FindingType]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func prettyCounts(m map[blackboard.FindingType]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	var out []byte
	for i, k := range keys {
		if i > 0 {
			out = append(out, ", "...)
		}
		out = append(out, k...)
		out = append(out, '=')
		out = append(out, []byte(itoa(m[blackboard.FindingType(k)]))...)
	}
	return string(out)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

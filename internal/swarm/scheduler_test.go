package swarm

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
	"github.com/google/uuid"
)

// buildBoard returns an in-memory board + campaign id for testing.
func buildBoard(t *testing.T) (blackboard.Board, uuid.UUID) {
	t.Helper()
	b := blackboard.NewMemoryBoard(nil)
	return b, uuid.New()
}

func TestScheduler_DispatchesMatchingFindings(t *testing.T) {
	board, cid := buildBoard(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var handled int32
	reacter := NamedPredicate{
		AgentName: "test-agent",
		Pred:      blackboard.Predicate{Types: []blackboard.FindingType{blackboard.TypeSubdomain}},
		Parallel:  1,
		Fn: func(ctx context.Context, f blackboard.Finding, b blackboard.Board) error {
			atomic.AddInt32(&handled, 1)
			return nil
		},
	}

	sched := NewScheduler(board, cid)
	sched.Register(reacter)

	go func() {
		_ = sched.Run(ctx)
	}()

	// Publish 3 matching and 1 non-matching
	write := func(typ blackboard.FindingType, tgt string) {
		_, err := board.Write(ctx, blackboard.Finding{
			CampaignID: cid, AgentName: "seed", Type: typ, Target: tgt,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	write(blackboard.TypeSubdomain, "a.com")
	write(blackboard.TypeSubdomain, "b.com")
	write(blackboard.TypeSubdomain, "c.com")
	write(blackboard.TypePortOpen, "ignored.com")

	// Poll for handled count up to 500ms.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&handled) == 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&handled); got != 3 {
		t.Fatalf("want 3 handled, got %d", got)
	}
}

func TestScheduler_CompletesOnCampaignCompleteFinding(t *testing.T) {
	board, cid := buildBoard(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	noop := NamedPredicate{
		AgentName: "noop",
		Pred:      blackboard.Predicate{Types: []blackboard.FindingType{blackboard.TypeSubdomain}},
		Fn:        func(ctx context.Context, f blackboard.Finding, b blackboard.Board) error { return nil },
	}
	sched := NewScheduler(board, cid)
	sched.Register(noop)

	done := make(chan error, 1)
	go func() { done <- sched.Run(ctx) }()

	// Publish CAMPAIGN_COMPLETE after a short delay.
	time.Sleep(30 * time.Millisecond)
	_, _ = board.Write(ctx, blackboard.Finding{
		CampaignID: cid, AgentName: "engine", Type: blackboard.TypeCampaignComplete, Target: "done",
	})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not return after CAMPAIGN_COMPLETE")
	}
}

func TestScheduler_BudgetExceededCancels(t *testing.T) {
	board, cid := buildBoard(t)
	// Set tiny limit so first budget check will cancel.
	_ = board.SetBudgetLimits(context.Background(), cid, 0.000001, 1)

	ctx := context.Background()
	noop := NamedPredicate{
		AgentName: "noop",
		Pred:      blackboard.Predicate{Types: []blackboard.FindingType{blackboard.TypeSubdomain}},
		Fn:        func(ctx context.Context, f blackboard.Finding, b blackboard.Board) error { return nil },
	}
	// Use up the budget by consuming tokens via UpdateBudget.
	_ = board.UpdateBudget(ctx, cid, 0, 10)

	sched := NewScheduler(board, cid, WithBudgetCheckInterval(20*time.Millisecond))
	sched.Register(noop)

	done := make(chan error, 1)
	go func() { done <- sched.Run(ctx) }()

	select {
	case <-done:
		// Scheduler returned — expected.
	case <-time.After(2 * time.Second):
		t.Fatal("budget enforcement did not cancel the scheduler")
	}
}

// TestScheduler_CompletesOnQuiescence is the regression for #65: a swarm that
// does work and then goes idle must complete on its own, not hang forever
// waiting for a CAMPAIGN_COMPLETE that nobody writes.
func TestScheduler_CompletesOnQuiescence(t *testing.T) {
	board, cid := buildBoard(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var handled int32
	worker := NamedPredicate{
		AgentName: "worker",
		Pred:      blackboard.Predicate{Types: []blackboard.FindingType{blackboard.TypeSubdomain}},
		Fn: func(ctx context.Context, f blackboard.Finding, b blackboard.Board) error {
			atomic.AddInt32(&handled, 1)
			return nil
		},
	}
	sched := NewScheduler(board, cid, WithIdleTimeout(80*time.Millisecond))
	sched.Register(worker)

	done := make(chan error, 1)
	go func() { done <- sched.Run(ctx) }()
	_, _ = board.Write(ctx, blackboard.Finding{
		CampaignID: cid, AgentName: "seed", Type: blackboard.TypeSubdomain, Target: "a.com",
	})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("scheduler hung — quiescence did not complete the campaign (regression: #65)")
	}
	if atomic.LoadInt32(&handled) != 1 {
		t.Fatalf("seed handled %d times, want 1", handled)
	}
}

// TestScheduler_QuiescenceWaitsForInflightHandle proves the idle watcher never
// completes the campaign while an agent Handle is still running.
func TestScheduler_QuiescenceWaitsForInflightHandle(t *testing.T) {
	board, cid := buildBoard(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var handled int32
	worker := NamedPredicate{
		AgentName: "slow",
		Pred:      blackboard.Predicate{Types: []blackboard.FindingType{blackboard.TypeSubdomain}},
		Fn: func(ctx context.Context, f blackboard.Finding, b blackboard.Board) error {
			time.Sleep(250 * time.Millisecond)
			atomic.AddInt32(&handled, 1)
			return nil
		},
	}
	sched := NewScheduler(board, cid, WithIdleTimeout(60*time.Millisecond))
	sched.Register(worker)

	done := make(chan error, 1)
	go func() { done <- sched.Run(ctx) }()
	_, _ = board.Write(ctx, blackboard.Finding{
		CampaignID: cid, AgentName: "seed", Type: blackboard.TypeSubdomain, Target: "a.com",
	})

	// The handle sleeps 250ms; at 150ms it is still in-flight, so the idle
	// window (60ms) must NOT have completed the campaign yet.
	select {
	case <-done:
		t.Fatal("scheduler completed while a Handle was still in-flight")
	case <-time.After(150 * time.Millisecond):
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not complete after the handle finished")
	}
	if atomic.LoadInt32(&handled) != 1 {
		t.Fatalf("handle ran %d times, want 1", handled)
	}
}

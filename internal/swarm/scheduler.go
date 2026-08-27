package swarm

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/logger"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/ratelimit"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Scheduler is the thin coordinator for the swarm. It does NOT plan — each
// agent's trigger predicate decides what it picks up. The scheduler only
// enforces concurrency caps, budget caps, and clean shutdown.
type Scheduler struct {
	board      blackboard.Board
	agents     []Agent
	campaignID uuid.UUID

	// budgetCheckInterval controls how often the scheduler polls the budget
	// and cancels the campaign if exceeded.
	budgetCheckInterval time.Duration

	// onEvent is an optional observability hook. Nil is fine.
	onEvent func(Event)

	// tracer is the distributed-tracing plug point. Defaults to NoopTracer.
	tracer Tracer

	// agentLimits caps how many findings each agent can dispatch per
	// second. Missing entries → no limit (preserve historical behavior).
	// See WithAgentRateLimit.
	agentLimits map[string]*ratelimit.Limiter

	// idleTimeout is the quiescence auto-complete window: once the swarm has
	// done some work and then goes idle (no in-flight Handle calls and no new
	// activity) for this long, the scheduler writes CAMPAIGN_COMPLETE so the
	// report agent fires and Run returns. Without it, a swarm that finishes
	// its work but never emits CAMPAIGN_COMPLETE hangs forever. 0 disables.
	idleTimeout time.Duration

	// inFlight counts currently-executing agent Handle calls (atomic).
	inFlight int64
	// lastActivityNano is the UnixNano of the last agent start/finish (atomic).
	lastActivityNano int64
	// sawActivity flips to 1 once any agent has started (atomic bool) — the
	// idle watcher only completes a swarm that was active and went quiet, never
	// one that simply hasn't started.
	sawActivity int32
}

// Event is a structured scheduler event emitted via the onEvent hook.
type Event struct {
	Type       string    `json:"type"` // "agent_started", "agent_finished", "agent_error", "budget_exceeded", "campaign_complete"
	Timestamp  time.Time `json:"timestamp"`
	CampaignID uuid.UUID `json:"campaign_id"`
	AgentName  string    `json:"agent_name,omitempty"`
	FindingID  uuid.UUID `json:"finding_id,omitempty"`
	Detail     string    `json:"detail,omitempty"`
}

// SchedulerOption customises Scheduler construction.
type SchedulerOption func(*Scheduler)

// WithBudgetCheckInterval overrides the default budget poll interval (5s).
func WithBudgetCheckInterval(d time.Duration) SchedulerOption {
	return func(s *Scheduler) { s.budgetCheckInterval = d }
}

// WithEventSink installs an observability callback.
func WithEventSink(fn func(Event)) SchedulerOption {
	return func(s *Scheduler) { s.onEvent = fn }
}

// WithIdleTimeout overrides the quiescence auto-complete window (default 60s).
// Pass 0 to disable idle-based completion entirely (completion then relies on
// a CAMPAIGN_COMPLETE finding or ctx cancellation only).
func WithIdleTimeout(d time.Duration) SchedulerOption {
	return func(s *Scheduler) { s.idleTimeout = d }
}

// WithTracer installs a Tracer for per-iteration spans. Defaults to NoopTracer.
func WithTracer(t Tracer) SchedulerOption {
	return func(s *Scheduler) {
		if t != nil {
			s.tracer = t
		}
	}
}

// WithAgentRateLimit caps how many findings the named agent can dispatch
// per second, with the given burst (== perSecond if burst<=0). Phase
// 3.4.4 — defends against pathological feedback loops where an agent
// wakes itself faster than its LLM provider can drain.
//
// Agents without a configured limit are uncapped (preserves prior
// behavior; opt-in tightening, not blanket throttling).
func WithAgentRateLimit(agentName string, perSecond, burst float64) SchedulerOption {
	return func(s *Scheduler) {
		if s.agentLimits == nil {
			s.agentLimits = map[string]*ratelimit.Limiter{}
		}
		s.agentLimits[agentName] = ratelimit.New(perSecond, burst)
	}
}

// NewScheduler creates a scheduler for the given campaign.
func NewScheduler(board blackboard.Board, campaignID uuid.UUID, opts ...SchedulerOption) *Scheduler {
	s := &Scheduler{
		board:               board,
		campaignID:          campaignID,
		budgetCheckInterval: 5 * time.Second,
		idleTimeout:         60 * time.Second,
		tracer:              NoopTracer{},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Register adds an agent to the swarm. Must be called before Run.
func (s *Scheduler) Register(a Agent) {
	s.agents = append(s.agents, a)
}

// touchActivity records that an agent just started or finished handling a
// finding, resetting the quiescence idle clock.
func (s *Scheduler) touchActivity() {
	atomic.StoreInt64(&s.lastActivityNano, time.Now().UnixNano())
	atomic.StoreInt32(&s.sawActivity, 1)
}

// Run drives the swarm until one of:
//   - ctx is cancelled (graceful shutdown; returns ctx.Err())
//   - a CAMPAIGN_COMPLETE finding is written to the blackboard (returns nil)
//
// Run never returns while agents are still handling findings — it waits for
// in-flight Handle calls to complete or the shutdown grace period to expire.
//
// Budget exhaustion does NOT abort directly; it writes CAMPAIGN_COMPLETE so
// the report agent fires on partial state. See the budget enforcer below.
func (s *Scheduler) Run(ctx context.Context) error {
	if len(s.agents) == 0 {
		return fmt.Errorf("no agents registered")
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	atomic.StoreInt64(&s.lastActivityNano, time.Now().UnixNano())

	var wg sync.WaitGroup
	completionCh := make(chan struct{})

	// Campaign completion watcher — subscribes for CAMPAIGN_COMPLETE and cancels.
	wg.Add(1)
	go func() {
		defer wg.Done()
		doneCh, err := s.board.Subscribe(runCtx, blackboard.Predicate{
			Types: []blackboard.FindingType{blackboard.TypeCampaignComplete},
			Limit: 1,
		})
		if err != nil {
			return
		}
		select {
		case <-runCtx.Done():
			return
		case <-doneCh:
			s.emit(Event{Type: "campaign_complete", Timestamp: time.Now(), CampaignID: s.campaignID})
			close(completionCh)
			cancel()
		}
	}()

	// Budget enforcer. Pause-on-budget (4.5.3): instead of immediately
	// cancelling the runCtx (which would orphan partial findings without
	// a report), we write a CAMPAIGN_COMPLETE finding to the blackboard.
	// That fires the report agent, which renders whatever the swarm
	// surfaced before the cap. The campaign-completion watcher above
	// then closes out cleanly. Net effect: the researcher gets a partial
	// report instead of an empty output dir, and they can extend the
	// budget + re-run if they want more.
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(s.budgetCheckInterval)
		defer t.Stop()
		paused := false
		for {
			select {
			case <-runCtx.Done():
				return
			case <-t.C:
			}
			bud, err := s.board.Budget(runCtx, s.campaignID)
			if err == nil && bud.Exceeded() && !paused {
				paused = true
				s.emit(Event{
					Type: "budget_exceeded", Timestamp: time.Now(), CampaignID: s.campaignID,
					Detail: fmt.Sprintf("paused — hours=%.2f/%.2f tokens=%d/%d (firing partial report)",
						bud.AgentHoursUsed, bud.MaxAgentHours, bud.TokensUsed, bud.MaxTokens),
				})
				_, _ = s.board.Write(runCtx, blackboard.Finding{
					CampaignID:    s.campaignID,
					AgentName:     "scheduler",
					Type:          blackboard.TypeCampaignComplete,
					Target:        "",
					PheromoneBase: 1.0,
					HalfLifeSec:   300,
				})
				// Don't cancel here — let the campaign-complete watcher
				// drive shutdown so the report agent has time to run.
			}
		}
	}()

	// Quiescence watcher. The swarm has no central planner that declares the
	// campaign done, and the report agent triggers on CAMPAIGN_COMPLETE — so
	// if nothing writes that finding, Run blocks on wg.Wait() forever (agents
	// sit on their subscriptions). Once the swarm has done work and then gone
	// idle (no in-flight Handle calls and no new activity for idleTimeout), we
	// write CAMPAIGN_COMPLETE ourselves, which fires the report agent and lets
	// the completion watcher above drive a clean shutdown.
	if s.idleTimeout > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			interval := s.idleTimeout / 3
			if interval < 50*time.Millisecond {
				interval = 50 * time.Millisecond
			}
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-runCtx.Done():
					return
				case <-t.C:
				}
				// Only complete a swarm that was active and went quiet, and
				// never while a Handle is still running.
				if atomic.LoadInt32(&s.sawActivity) == 0 || atomic.LoadInt64(&s.inFlight) != 0 {
					continue
				}
				idleNano := time.Now().UnixNano() - atomic.LoadInt64(&s.lastActivityNano)
				if idleNano < int64(s.idleTimeout) {
					continue
				}
				s.emit(Event{
					Type: "campaign_quiescent", Timestamp: time.Now(), CampaignID: s.campaignID,
					Detail: fmt.Sprintf("no agent activity for %s — writing CAMPAIGN_COMPLETE", s.idleTimeout),
				})
				_, _ = s.board.Write(runCtx, blackboard.Finding{
					CampaignID:    s.campaignID,
					AgentName:     "scheduler",
					Type:          blackboard.TypeCampaignComplete,
					PheromoneBase: 1.0,
					HalfLifeSec:   300,
				})
				return
			}
		}()
	}

	// One goroutine per agent runs its dispatch loop.
	for _, a := range s.agents {
		wg.Add(1)
		go func(agent Agent) {
			defer wg.Done()
			s.runAgent(runCtx, agent)
		}(a)
	}

	wg.Wait()

	// Distinguish completion from cancellation.
	select {
	case <-completionCh:
		return nil
	default:
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// runAgent is the per-agent dispatch loop. It subscribes to the agent's
// trigger predicate and runs Handle against each finding, bounded by the
// agent's MaxConcurrency.
func (s *Scheduler) runAgent(ctx context.Context, agent Agent) {
	// Resume from last committed cursor.
	cursor, _ := s.board.Cursor(ctx, s.campaignID, agent.Name())
	pred := agent.Trigger()
	pred.SinceID = cursor

	ch, err := s.board.Subscribe(ctx, pred)
	if err != nil {
		s.emit(Event{
			Type: "agent_error", Timestamp: time.Now(), CampaignID: s.campaignID,
			AgentName: agent.Name(), Detail: fmt.Sprintf("subscribe: %s", err),
		})
		return
	}

	parallel := agent.MaxConcurrency()
	if parallel <= 0 {
		parallel = 1
	}
	sem := make(chan struct{}, parallel)
	var inflight sync.WaitGroup

	for {
		select {
		case <-ctx.Done():
			inflight.Wait()
			return
		case f, ok := <-ch:
			if !ok {
				inflight.Wait()
				return
			}
			// Per-agent budget gate. If this agent blew its token cap we
			// skip dispatch (and record a single WARN-level event so the
			// operator knows). Cursor is NOT advanced, so the finding
			// can be retried after the operator raises the cap.
			bud, _ := s.board.AgentBudget(ctx, s.campaignID, agent.Name())
			if bud.Exceeded() {
				s.emit(Event{
					Type: "agent_budget_exceeded", Timestamp: time.Now(), CampaignID: s.campaignID,
					AgentName: agent.Name(),
					Detail:    fmt.Sprintf("%d/%d tokens", bud.TokensUsed, bud.MaxTokens),
				})
				continue
			}
			if bud.ShouldWarn() {
				s.emit(Event{
					Type: "agent_budget_warn", Timestamp: time.Now(), CampaignID: s.campaignID,
					AgentName: agent.Name(),
					Detail:    fmt.Sprintf("%d/%d tokens (soft threshold)", bud.TokensUsed, bud.WarnAtTokens),
				})
				// Flip the warned flag with a no-op charge so we only warn once.
				_ = s.board.ChargeAgent(ctx, s.campaignID, agent.Name(), 0)
			}
			// Per-agent rate limit (3.4.4). Take blocks if the bucket is
			// empty; ctx.Err on cancel exits the dispatch loop cleanly.
			if lim := s.agentLimits[agent.Name()]; lim != nil {
				if err := lim.Take(ctx); err != nil {
					inflight.Wait()
					return
				}
			}
			sem <- struct{}{}
			inflight.Add(1)
			atomic.AddInt64(&s.inFlight, 1)
			s.touchActivity()
			go func(finding blackboard.Finding) {
				defer inflight.Done()
				defer func() { <-sem }()
				defer func() {
					atomic.AddInt64(&s.inFlight, -1)
					s.touchActivity()
				}()
				start := time.Now()
				s.emit(Event{
					Type: "agent_started", Timestamp: start, CampaignID: s.campaignID,
					AgentName: agent.Name(), FindingID: finding.ID,
				})
				spanCtx, end := s.tracer.StartSpan(ctx, "swarm.agent.handle",
					Attr{"agent", agent.Name()},
					Attr{"finding.id", finding.ID.String()},
					Attr{"finding.type", string(finding.Type)},
				)
				err := agent.Handle(spanCtx, finding, s.board)
				end(err)
				duration := time.Since(start)
				// Always commit cursor and charge budget regardless of success.
				_ = s.board.CommitCursor(ctx, s.campaignID, agent.Name(), finding.ID)
				_ = s.board.UpdateBudget(ctx, s.campaignID, duration.Hours(), 0)

				if err != nil {
					s.emit(Event{
						Type: "agent_error", Timestamp: time.Now(), CampaignID: s.campaignID,
						AgentName: agent.Name(), FindingID: finding.ID, Detail: err.Error(),
					})
					// Emit error finding so other agents can react (e.g. an
					// error-recovery agent, or reports that surface failures).
					errData, _ := json.Marshal(map[string]string{
						"agent": agent.Name(), "error": err.Error(),
					})
					_, _ = s.board.Write(ctx, blackboard.Finding{
						CampaignID:    s.campaignID,
						AgentName:     agent.Name(),
						Type:          blackboard.TypeAgentError,
						Target:        finding.Target,
						Data:          errData,
						PheromoneBase: 0.3,
						HalfLifeSec:   600,
					})
					return
				}
				s.emit(Event{
					Type: "agent_finished", Timestamp: time.Now(), CampaignID: s.campaignID,
					AgentName: agent.Name(), FindingID: finding.ID,
					Detail: duration.Round(time.Millisecond).String(),
				})
			}(f)
		}
	}
}

func (s *Scheduler) emit(e Event) {
	// Structured log for every scheduler event (plumbs to Grafana/Loki etc).
	log := logger.Get().With(
		zap.String("subsystem", "scheduler"),
		zap.String("campaign_id", e.CampaignID.String()),
	)
	fields := []zap.Field{zap.String("event", e.Type)}
	if e.AgentName != "" {
		fields = append(fields, zap.String("agent", e.AgentName))
	}
	if e.FindingID != uuid.Nil {
		fields = append(fields, zap.String("finding_id", e.FindingID.String()))
	}
	if e.Detail != "" {
		fields = append(fields, zap.String("detail", e.Detail))
	}
	switch e.Type {
	case "agent_error", "budget_exceeded":
		log.Warn("scheduler.event", fields...)
	default:
		log.Info("scheduler.event", fields...)
	}

	if s.onEvent != nil {
		s.onEvent(e)
	}
}

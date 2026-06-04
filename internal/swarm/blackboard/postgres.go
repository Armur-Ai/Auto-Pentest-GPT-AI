package blackboard

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresBoard is the durable Postgres-backed blackboard.
// All writes are transactional; reads compute pheromone at query time via
// the swarm_pheromone SQL function.
type PostgresBoard struct {
	pool *pgxpool.Pool

	// Subscribe uses a poll loop since we don't want to take a hard
	// dependency on LISTEN/NOTIFY here. pollInterval controls the cadence.
	pollInterval time.Duration

	// Subscribers are tracked so Close can tear them down cleanly.
	subs struct {
		sync.Mutex
		ch []chan Finding
	}
}

// NewPostgresBoard creates a new blackboard backed by the given pool.
func NewPostgresBoard(pool *pgxpool.Pool) *PostgresBoard {
	return &PostgresBoard{
		pool:         pool,
		pollInterval: 500 * time.Millisecond,
	}
}

// Write inserts a new finding. The assigned ID is returned even if the
// caller provides one — the DB authoritatively assigns IDs.
func (b *PostgresBoard) Write(ctx context.Context, f Finding, opts ...WriteOption) (uuid.UUID, error) {
	o := writeOpts{
		pheromoneBase: 1.0,
		halfLifeSec:   3600,
	}
	// Honor the Finding fields if already set (explicit wins).
	if f.PheromoneBase != 0 {
		o.pheromoneBase = f.PheromoneBase
	}
	if f.HalfLifeSec != 0 {
		o.halfLifeSec = f.HalfLifeSec
	}
	for _, opt := range opts {
		opt(&o)
	}

	if f.CampaignID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("finding requires campaign_id")
	}
	if f.Type == "" {
		return uuid.Nil, fmt.Errorf("finding requires type")
	}
	if f.AgentName == "" {
		return uuid.Nil, fmt.Errorf("finding requires agent_name")
	}
	if len(f.Data) == 0 {
		// Default to an empty JSON object so the jsonb column is well-formed.
		f.Data = []byte(`{}`)
	}

	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var id uuid.UUID
	err = tx.QueryRow(ctx,
		`INSERT INTO swarm_findings
		 (campaign_id, agent_name, finding_type, target, data,
		  pheromone_base, half_life_sec, embedding)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)
		 RETURNING id`,
		f.CampaignID, f.AgentName, string(f.Type), f.Target,
		string(f.Data),
		o.pheromoneBase, o.halfLifeSec, embeddingArg(o.embedding),
	).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert finding: %w", err)
	}

	if o.supersedes != nil {
		_, err = tx.Exec(ctx,
			`UPDATE swarm_findings SET superseded_by = $1 WHERE id = $2`,
			id, *o.supersedes,
		)
		if err != nil {
			return uuid.Nil, fmt.Errorf("supersede: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("commit: %w", err)
	}
	return id, nil
}

// Query returns findings matching the predicate, newest first.
func (b *PostgresBoard) Query(ctx context.Context, p Predicate) ([]Finding, error) {
	where := []string{"superseded_by IS NULL"}
	args := []any{}
	i := 1

	if len(p.Types) > 0 {
		types := make([]string, len(p.Types))
		for j, t := range p.Types {
			types[j] = string(t)
		}
		where = append(where, fmt.Sprintf("finding_type = ANY($%d)", i))
		args = append(args, types)
		i++
	}
	if p.TargetPrefix != "" {
		where = append(where, fmt.Sprintf("target LIKE $%d", i))
		args = append(args, p.TargetPrefix+"%")
		i++
	}
	if p.SinceID != uuid.Nil {
		where = append(where, fmt.Sprintf(
			"created_at > (SELECT created_at FROM swarm_findings WHERE id = $%d)", i))
		args = append(args, p.SinceID)
		i++
	}
	if p.MinPheromone > 0 {
		where = append(where, fmt.Sprintf(
			"swarm_pheromone(pheromone_base, half_life_sec, EXTRACT(EPOCH FROM (NOW() - created_at))) >= $%d",
			i))
		args = append(args, p.MinPheromone)
		i++
	}

	limit := "100"
	if p.Limit > 0 {
		limit = fmt.Sprintf("%d", p.Limit)
	}

	q := fmt.Sprintf(`
		SELECT id, campaign_id, agent_name, finding_type, target, data,
		       pheromone_base, half_life_sec, superseded_by, created_at,
		       swarm_pheromone(pheromone_base, half_life_sec,
		                        EXTRACT(EPOCH FROM (NOW() - created_at))) AS pheromone
		FROM swarm_findings
		WHERE %s
		ORDER BY created_at DESC
		LIMIT %s
	`, strings.Join(where, " AND "), limit)

	rows, err := b.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var out []Finding
	for rows.Next() {
		var f Finding
		var ftype string
		var data []byte
		if err := rows.Scan(
			&f.ID, &f.CampaignID, &f.AgentName, &ftype, &f.Target, &data,
			&f.PheromoneBase, &f.HalfLifeSec, &f.SupersededBy, &f.CreatedAt,
			&f.Pheromone,
		); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		f.Type = FindingType(ftype)
		f.Data = data
		out = append(out, f)
	}
	return out, rows.Err()
}

// Subscribe polls for new findings at the configured interval.
// Delivery is at-least-once; use CommitCursor for exactly-once semantics.
func (b *PostgresBoard) Subscribe(ctx context.Context, p Predicate) (<-chan Finding, error) {
	ch := make(chan Finding, 32)

	b.subs.Lock()
	b.subs.ch = append(b.subs.ch, ch)
	b.subs.Unlock()

	go func() {
		defer close(ch)
		ticker := time.NewTicker(b.pollInterval)
		defer ticker.Stop()

		cursor := p.SinceID
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			probe := p
			probe.SinceID = cursor
			findings, err := b.Query(ctx, probe)
			if err != nil {
				continue
			}
			// Newest-first from Query — iterate oldest-first for delivery.
			for j := len(findings) - 1; j >= 0; j-- {
				select {
				case <-ctx.Done():
					return
				case ch <- findings[j]:
					cursor = findings[j].ID
				}
			}
		}
	}()
	return ch, nil
}

// Cursor returns the last committed cursor for an agent.
func (b *PostgresBoard) Cursor(ctx context.Context, campaignID uuid.UUID, agentName string) (uuid.UUID, error) {
	var id uuid.UUID
	err := b.pool.QueryRow(ctx,
		`SELECT last_seen_id FROM swarm_agent_cursors WHERE campaign_id = $1 AND agent_name = $2`,
		campaignID, agentName,
	).Scan(&id)
	if err == pgx.ErrNoRows {
		return uuid.Nil, nil
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("read cursor: %w", err)
	}
	return id, nil
}

// CommitCursor upserts the cursor for an agent.
func (b *PostgresBoard) CommitCursor(ctx context.Context, campaignID uuid.UUID, agentName string, findingID uuid.UUID) error {
	_, err := b.pool.Exec(ctx,
		`INSERT INTO swarm_agent_cursors (campaign_id, agent_name, last_seen_id, last_seen_at)
		 VALUES ($1, $2, $3, NOW())
		 ON CONFLICT (campaign_id, agent_name)
		 DO UPDATE SET last_seen_id = EXCLUDED.last_seen_id, last_seen_at = EXCLUDED.last_seen_at`,
		campaignID, agentName, findingID,
	)
	if err != nil {
		return fmt.Errorf("commit cursor: %w", err)
	}
	return nil
}

// Pheromone returns the current decayed weight of a single finding.
func (b *PostgresBoard) Pheromone(ctx context.Context, findingID uuid.UUID) (float64, error) {
	var p float64
	err := b.pool.QueryRow(ctx,
		`SELECT swarm_pheromone(pheromone_base, half_life_sec,
		                       EXTRACT(EPOCH FROM (NOW() - created_at)))
		 FROM swarm_findings WHERE id = $1`,
		findingID,
	).Scan(&p)
	if err != nil {
		return 0, fmt.Errorf("pheromone: %w", err)
	}
	return p, nil
}

// Supersede marks oldID as superseded by newID.
func (b *PostgresBoard) Supersede(ctx context.Context, oldID, newID uuid.UUID) error {
	_, err := b.pool.Exec(ctx,
		`UPDATE swarm_findings SET superseded_by = $1 WHERE id = $2`,
		newID, oldID,
	)
	if err != nil {
		return fmt.Errorf("supersede: %w", err)
	}
	return nil
}

// Budget reads the current budget for a campaign, creating a default row if absent.
func (b *PostgresBoard) Budget(ctx context.Context, campaignID uuid.UUID) (Budget, error) {
	var bud Budget
	bud.CampaignID = campaignID
	err := b.pool.QueryRow(ctx,
		`INSERT INTO swarm_budgets (campaign_id) VALUES ($1)
		 ON CONFLICT (campaign_id) DO UPDATE SET updated_at = NOW()
		 RETURNING max_agent_hours, max_tokens, agent_hours_used, tokens_used`,
		campaignID,
	).Scan(&bud.MaxAgentHours, &bud.MaxTokens, &bud.AgentHoursUsed, &bud.TokensUsed)
	if err != nil {
		return bud, fmt.Errorf("budget: %w", err)
	}
	return bud, nil
}

// UpdateBudget increments usage counters atomically.
func (b *PostgresBoard) UpdateBudget(ctx context.Context, campaignID uuid.UUID, deltaHours float64, deltaTokens int64) error {
	_, err := b.pool.Exec(ctx,
		`UPDATE swarm_budgets
		 SET agent_hours_used = agent_hours_used + $1,
		     tokens_used = tokens_used + $2,
		     updated_at = NOW()
		 WHERE campaign_id = $3`,
		deltaHours, deltaTokens, campaignID,
	)
	if err != nil {
		return fmt.Errorf("update budget: %w", err)
	}
	return nil
}

// SetBudgetLimits overrides the caps for a campaign.
func (b *PostgresBoard) SetBudgetLimits(ctx context.Context, campaignID uuid.UUID, maxHours float64, maxTokens int64) error {
	_, err := b.pool.Exec(ctx,
		`INSERT INTO swarm_budgets (campaign_id, max_agent_hours, max_tokens)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (campaign_id) DO UPDATE
		   SET max_agent_hours = EXCLUDED.max_agent_hours,
		       max_tokens = EXCLUDED.max_tokens,
		       updated_at = NOW()`,
		campaignID, maxHours, maxTokens,
	)
	if err != nil {
		return fmt.Errorf("set budget limits: %w", err)
	}
	return nil
}

// AgentBudget reads (or creates-with-defaults) the per-agent budget row.
func (b *PostgresBoard) AgentBudget(ctx context.Context, campaignID uuid.UUID, agent string) (AgentBudget, error) {
	var bud AgentBudget
	bud.CampaignID = campaignID
	bud.Agent = agent
	err := b.pool.QueryRow(ctx,
		`INSERT INTO swarm_agent_budgets (campaign_id, agent_name)
		 VALUES ($1, $2)
		 ON CONFLICT (campaign_id, agent_name) DO UPDATE SET updated_at = NOW()
		 RETURNING max_tokens, warn_at_tokens, tokens_used, warned`,
		campaignID, agent,
	).Scan(&bud.MaxTokens, &bud.WarnAtTokens, &bud.TokensUsed, &bud.Warned)
	if err != nil {
		return bud, fmt.Errorf("agent budget: %w", err)
	}
	return bud, nil
}

// ChargeAgent increments tokens_used and flips Warned when the soft
// threshold is first crossed. Atomic via a single UPDATE.
func (b *PostgresBoard) ChargeAgent(ctx context.Context, campaignID uuid.UUID, agent string, tokens int64) error {
	// Ensure the row exists first.
	if _, err := b.AgentBudget(ctx, campaignID, agent); err != nil {
		return err
	}
	_, err := b.pool.Exec(ctx,
		`UPDATE swarm_agent_budgets
		   SET tokens_used = tokens_used + $3,
		       warned = warned OR (tokens_used + $3 >= warn_at_tokens),
		       updated_at = NOW()
		 WHERE campaign_id = $1 AND agent_name = $2`,
		campaignID, agent, tokens,
	)
	if err != nil {
		return fmt.Errorf("charge agent: %w", err)
	}
	return nil
}

// SetAgentBudget overrides the caps (and clears Warned if usage is now
// below the new soft threshold).
func (b *PostgresBoard) SetAgentBudget(ctx context.Context, campaignID uuid.UUID, agent string, maxTokens, warnAt int64) error {
	_, err := b.pool.Exec(ctx,
		`INSERT INTO swarm_agent_budgets (campaign_id, agent_name, max_tokens, warn_at_tokens)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (campaign_id, agent_name) DO UPDATE
		   SET max_tokens = EXCLUDED.max_tokens,
		       warn_at_tokens = EXCLUDED.warn_at_tokens,
		       warned = swarm_agent_budgets.tokens_used >= EXCLUDED.warn_at_tokens,
		       updated_at = NOW()`,
		campaignID, agent, maxTokens, warnAt,
	)
	if err != nil {
		return fmt.Errorf("set agent budget: %w", err)
	}
	return nil
}

// embeddingArg converts a float32 vector into the string literal pgvector accepts.
// Returns nil (which pgx will send as NULL) for an empty slice.
func embeddingArg(v []float32) any {
	if len(v) == 0 {
		return nil
	}
	var sb strings.Builder
	sb.WriteByte('[')
	for i, x := range v {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, "%g", x)
	}
	sb.WriteByte(']')
	return sb.String()
}

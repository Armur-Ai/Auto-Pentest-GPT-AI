package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// SqlmapTool talks to a running sqlmapapi daemon (started via `sqlmapapi -s`)
// via HTTP. The daemon's default port is 8775; override via
// `opts["sqlmap_endpoint"] = "http://host:port"`. The adapter never shells
// out to the sqlmap binary directly — all control goes through the REST API
// so results are structured JSON and cleanup (task kill + delete) is explicit.
//
// We redact credentials / DB-user passwords from surfaced findings — the
// full data is still in sqlmap's own output directory if the operator
// needs it, but the blackboard and reports must never include cleartext.
type SqlmapTool struct {
	endpoint   string
	httpClient *http.Client
}

// NewSqlmapTool builds an adapter pointed at the default sqlmapapi endpoint.
func NewSqlmapTool() *SqlmapTool {
	return &SqlmapTool{
		endpoint:   "http://127.0.0.1:8775",
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Name implements Tool.
func (s *SqlmapTool) Name() string { return "sqlmap" }

// IsAvailable returns true when either the `sqlmap` binary is in PATH or
// a sqlmapapi daemon at the configured endpoint responds to /scan/list.
// We accept either because sqlmapapi can be pre-started by the operator.
func (s *SqlmapTool) IsAvailable() bool {
	if IsCommandAvailable("sqlmap") || IsCommandAvailable("sqlmapapi") {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+"/scan/list", nil)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Run drives the daemon through the task-create / option-set / scan-start /
// scan-status / scan-data lifecycle and returns a ToolResult with redacted
// findings.
func (s *SqlmapTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("sqlmap", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in sqlmap: %w", err)
		}
	}

	// Per-call endpoint override.
	endpoint := opts.GetString("sqlmap_endpoint", s.endpoint)
	client := s.httpClient
	timeout := time.Duration(opts.GetInt("timeout", 600)) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	result := &ToolResult{ToolName: s.Name(), Target: target}

	// 1. Create task.
	var newResp struct {
		Success bool   `json:"success"`
		TaskID  string `json:"taskid"`
	}
	if err := apiGet(runCtx, client, endpoint+"/task/new", &newResp); err != nil || !newResp.Success {
		return result, fmt.Errorf("sqlmap task/new: %w", err)
	}
	taskID := newResp.TaskID

	// Always clean up — delete the task even if scan fails partway.
	defer func() {
		delCtx, delCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer delCancel()
		_ = apiGet(delCtx, client, endpoint+"/task/"+taskID+"/delete", nil)
	}()

	// 2. Configure options (URL + sensible-defaults for an authorized pentest).
	optsPayload := map[string]any{
		"url":          target,
		"level":        opts.GetInt("level", 2),
		"risk":         opts.GetInt("risk", 1),
		"batch":        true,
		"flushSession": true,
		"technique":    opts.GetString("technique", "BEUSTQ"),
		"timeout":      opts.GetInt("req_timeout", 30),
	}
	if err := apiPost(runCtx, client, endpoint+"/option/"+taskID+"/set", optsPayload, nil); err != nil {
		return result, fmt.Errorf("sqlmap option/set: %w", err)
	}

	// 3. Start the scan.
	if err := apiPost(runCtx, client, endpoint+"/scan/"+taskID+"/start", map[string]any{"url": target}, nil); err != nil {
		return result, fmt.Errorf("sqlmap scan/start: %w", err)
	}

	// 4. Poll status.
	poll := time.NewTicker(3 * time.Second)
	defer poll.Stop()
	for {
		select {
		case <-runCtx.Done():
			return result, fmt.Errorf("sqlmap scan timed out after %s", timeout)
		case <-poll.C:
		}
		var status struct {
			Status     string `json:"status"`
			ReturnCode int    `json:"returncode"`
		}
		if err := apiGet(runCtx, client, endpoint+"/scan/"+taskID+"/status", &status); err != nil {
			return result, fmt.Errorf("sqlmap scan/status: %w", err)
		}
		if status.Status == "terminated" {
			break
		}
	}

	// 5. Retrieve and redact data.
	var data struct {
		Success bool             `json:"success"`
		Data    []map[string]any `json:"data"`
	}
	if err := apiGet(runCtx, client, endpoint+"/scan/"+taskID+"/data", &data); err != nil {
		return result, fmt.Errorf("sqlmap scan/data: %w", err)
	}

	for i := range data.Data {
		redactSecretsInPlace(data.Data[i])
	}
	result.ParsedFindings = data.Data
	b, _ := json.MarshalIndent(data.Data, "", "  ")
	result.RawOutput = string(b)
	result.Duration = time.Since(start)
	return result, nil
}

// --- HTTP helpers ---

func apiGet(ctx context.Context, c *http.Client, url string, into any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	if into == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

func apiPost(ctx context.Context, c *http.Client, url string, body any, into any) error {
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	if into == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

// --- Redaction ---

// secretKeyPattern matches obvious credential-adjacent keys regardless of
// casing / punctuation. We redact the VALUE of any such key before the
// finding leaves this adapter.
var secretKeyPattern = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|db[_-]?cred)`)

func redactSecretsInPlace(m map[string]any) {
	for k, v := range m {
		if secretKeyPattern.MatchString(k) {
			m[k] = "[REDACTED]"
			continue
		}
		switch child := v.(type) {
		case map[string]any:
			redactSecretsInPlace(child)
		case []any:
			for _, item := range child {
				if sub, ok := item.(map[string]any); ok {
					redactSecretsInPlace(sub)
				}
			}
		case string:
			// Redact anything in "key=value" form that looks secret.
			if idx := strings.Index(child, "="); idx > 0 && secretKeyPattern.MatchString(child[:idx]) {
				m[k] = child[:idx+1] + "[REDACTED]"
			}
		}
	}
}

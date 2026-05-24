// Package metasploit is a thin HTTP/JSON client for msfrpcd, the daemon
// that ships with Metasploit. The MessagePack transport is more canonical
// but harder to debug; msfrpcd has supported JSON for years and it's
// perfectly adequate for orchestration.
//
// Launch the daemon once per engagement:
//
//	msfrpcd -P s3cret -U msf -a 127.0.0.1 -f
//
// Every session / job created via this client is the swarm's responsibility
// to clean up — callers MUST register a cleanup via the pipeline.CleanupRegistry
// before persisting the session id to the blackboard.
package metasploit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Client talks to msfrpcd over HTTP/JSON.
type Client struct {
	endpoint string
	http     *http.Client
	user     string
	pass     string

	mu    sync.Mutex
	token string // valid for the session — re-logged-in on 401
}

// Config customises a Client.
type Config struct {
	Endpoint string // default https://127.0.0.1:55553/api/
	User     string
	Pass     string
	Timeout  time.Duration // default 30s
}

// NewClient creates a client; no network I/O yet.
func NewClient(cfg Config) *Client {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://127.0.0.1:55553/api/"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if !strings.HasSuffix(cfg.Endpoint, "/") {
		cfg.Endpoint += "/"
	}
	return &Client{
		endpoint: cfg.Endpoint,
		http:     &http.Client{Timeout: cfg.Timeout},
		user:     cfg.User,
		pass:     cfg.Pass,
	}
}

// Login establishes a token and caches it.
func (c *Client) Login(ctx context.Context) error {
	var out struct {
		Result string `json:"result"`
		Token  string `json:"token"`
		Error  bool   `json:"error"`
		ErrMsg string `json:"error_message"`
	}
	err := c.rpc(ctx, "auth.login", []any{c.user, c.pass}, &out)
	if err != nil {
		return err
	}
	if out.Error {
		return fmt.Errorf("msfrpcd auth failed: %s", out.ErrMsg)
	}
	c.mu.Lock()
	c.token = out.Token
	c.mu.Unlock()
	return nil
}

// ExecuteModule runs a Metasploit module (exploit/aux/post) with options
// and returns the job id + session id (if a shell is created).
func (c *Client) ExecuteModule(ctx context.Context, modType, module string, opts map[string]any) (ExecuteResult, error) {
	if err := c.ensureToken(ctx); err != nil {
		return ExecuteResult{}, err
	}
	var out ExecuteResult
	if err := c.authRPC(ctx, "module.execute", []any{modType, module, opts}, &out); err != nil {
		return ExecuteResult{}, err
	}
	return out, nil
}

// ExecuteResult is what module.execute returns.
type ExecuteResult struct {
	JobID     int    `json:"job_id"`
	UUID      string `json:"uuid"`
	SessionID int    `json:"session_id,omitempty"`
	Error     bool   `json:"error"`
	ErrMsg    string `json:"error_message,omitempty"`
}

// ListSessions returns the live sessions keyed by numeric id.
func (c *Client) ListSessions(ctx context.Context) (map[string]Session, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}
	out := map[string]Session{}
	if err := c.authRPC(ctx, "session.list", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Session is a live msfrpcd session.
type Session struct {
	Type        string `json:"type"`
	TunnelLP    string `json:"tunnel_local"`
	TunnelPP    string `json:"tunnel_peer"`
	ViaEx       string `json:"via_exploit"`
	ViaPay      string `json:"via_payload"`
	Desc        string `json:"desc"`
	Info        string `json:"info"`
	Workspace   string `json:"workspace"`
	SessionHost string `json:"session_host"`
	SessionPort int    `json:"session_port"`
	TargetHost  string `json:"target_host"`
	Username    string `json:"username"`
	UUID        string `json:"uuid"`
}

// StopSession kills a session by id. Safe to call on already-dead sessions.
func (c *Client) StopSession(ctx context.Context, sessionID int) error {
	if err := c.ensureToken(ctx); err != nil {
		return err
	}
	var out struct {
		Result string `json:"result"`
	}
	return c.authRPC(ctx, "session.stop", []any{sessionID}, &out)
}

// StopJob kills a background module job.
func (c *Client) StopJob(ctx context.Context, jobID int) error {
	if err := c.ensureToken(ctx); err != nil {
		return err
	}
	var out struct {
		Result string `json:"result"`
	}
	return c.authRPC(ctx, "job.stop", []any{fmt.Sprintf("%d", jobID)}, &out)
}

// --- transport ---

func (c *Client) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	t := c.token
	c.mu.Unlock()
	if t != "" {
		return nil
	}
	return c.Login(ctx)
}

// rpc sends a msfrpcd call with no token.
func (c *Client) rpc(ctx context.Context, method string, params []any, out any) error {
	args := append([]any{method}, params...)
	body, _ := json.Marshal(args)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "binary/message-pack") // msfrpcd inspects Content-Type loosely
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("msfrpcd transport: %w", err)
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("msfrpcd status %d: %s", resp.StatusCode, string(buf))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(buf, out)
}

// authRPC is rpc with the cached token prepended.
func (c *Client) authRPC(ctx context.Context, method string, params []any, out any) error {
	c.mu.Lock()
	t := c.token
	c.mu.Unlock()
	args := append([]any{method, t}, params...)
	body, _ := json.Marshal(args)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "binary/message-pack")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("msfrpcd transport: %w", err)
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		// Token went stale — log back in once and retry.
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
		if err := c.Login(ctx); err != nil {
			return err
		}
		return c.authRPC(ctx, method, params, out)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("msfrpcd status %d: %s", resp.StatusCode, string(buf))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(buf, out)
}

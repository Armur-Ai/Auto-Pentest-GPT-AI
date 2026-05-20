// Package prompts provides offensive-security prompt scaffolding for the
// swarm — curated system-prompt templates, a few-shot example library,
// and a refusal-detector + retry/fallback wrapper around llm.Provider.
//
// The intent (plan item 1.4.7) is to lift Cybench-class scores without
// fine-tuning a model. Pure prompt engineering, zero training cost.
// Templates and examples are embedded into the binary so the tool
// stays self-contained — drop a new .tmpl or .json file in the right
// directory and the next build picks it up, no path resolution at
// runtime. Community contributors can extend the example library by
// PR-ing a single JSON file.
package prompts

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"text/template"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
)

//go:embed templates
var templateFS embed.FS

//go:embed examples
var exampleFS embed.FS

// Context is the data passed into prompt templates. Fields are
// optional — templates fall back to neutral phrasing when fields are
// empty so a partially-populated Context still renders cleanly.
type Context struct {
	// Engagement is a free-form description of the authorized context,
	// e.g. "HackerOne program example-corp (handle: H1-12345)".
	Engagement string

	// Scope is a one-line summary of what's in scope (the swarm enforces
	// scope at the tool layer separately; this is for the LLM's own
	// reasoning).
	Scope string

	// Role is the agent's role in the swarm: "recon", "classifier",
	// "exploit", "report", or any custom string.
	Role string

	// Tools is the list of tools available to this agent, used by
	// templates that want to enumerate capabilities in the system
	// prompt. Optional.
	Tools []ToolDescription
}

// ToolDescription is a minimal struct for template rendering. Provider
// tool definitions (llm.Tool) include JSON Schema for arguments which
// is too verbose for the system prompt; this struct keeps only what
// the LLM needs at the planning level.
type ToolDescription struct {
	Name        string
	Description string
}

// Cybench-aligned category names. Examples live in examples/<category>/.
const (
	CategoryWeb        = "web"
	CategoryCrypto     = "crypto"
	CategoryPwn        = "pwn"
	CategoryReverseEng = "rev"
	CategoryForensics  = "forensics"
	CategoryAuth       = "auth"
	CategoryAPI        = "api"
	CategoryCloud      = "cloud"
)

// Load renders a named template with the given context. The name is
// the basename of the template file in templates/ without the .tmpl
// extension, e.g. Load("offsec_system", ctx).
//
// Returns an error if the template doesn't exist or fails to parse —
// callers should treat that as a programming bug, not a runtime
// failure (templates ship in the binary).
func Load(name string, ctx Context) (string, error) {
	data, err := templateFS.ReadFile(path.Join("templates", name+".tmpl"))
	if err != nil {
		return "", fmt.Errorf("loading template %q: %w", name, err)
	}

	tmpl, err := template.New(name).Parse(string(data))
	if err != nil {
		return "", fmt.Errorf("parsing template %q: %w", name, err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return "", fmt.Errorf("executing template %q: %w", name, err)
	}
	return buf.String(), nil
}

// FewShot returns up to n examples from the given category as a slice
// of user→assistant message pairs ready to prepend to a real request.
//
// Never errors — a missing category or filesystem hiccup returns nil,
// so scaffolding stays optional / degrades gracefully. If you need to
// know whether examples were loaded, check len(returned).
//
// Examples are sorted by filename so ordering is deterministic across
// builds — important if the LLM is sensitive to example ordering.
func FewShot(category string, n int) []llm.Message {
	if n <= 0 {
		return nil
	}
	entries, err := fs.ReadDir(exampleFS, path.Join("examples", category))
	if err != nil {
		return nil
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		files = append(files, e.Name())
	}
	sort.Strings(files)

	if len(files) > n {
		files = files[:n]
	}

	var messages []llm.Message
	for _, f := range files {
		ex, err := loadExample(category, f)
		if err != nil {
			// Skip malformed examples rather than poisoning the prompt;
			// surface via logs at the call site if needed.
			continue
		}
		messages = append(messages,
			llm.Message{Role: "user", Content: ex.User},
			llm.Message{Role: "assistant", Content: ex.Assistant},
		)
	}
	return messages
}

// example is the on-disk representation of a few-shot example.
// Title/VulnClass are metadata used by docs and tooling; only User
// and Assistant feed into the LLM prompt.
type example struct {
	Category  string `json:"category"`
	VulnClass string `json:"vuln_class"`
	Title     string `json:"title"`
	User      string `json:"user"`
	Assistant string `json:"assistant"`
}

func loadExample(category, filename string) (*example, error) {
	data, err := exampleFS.ReadFile(path.Join("examples", category, filename))
	if err != nil {
		return nil, err
	}
	var ex example
	if err := json.Unmarshal(data, &ex); err != nil {
		return nil, fmt.Errorf("unmarshal example %s/%s: %w", category, filename, err)
	}
	if ex.User == "" || ex.Assistant == "" {
		return nil, fmt.Errorf("example %s/%s missing user or assistant field", category, filename)
	}
	return &ex, nil
}

// CategoryCount returns the number of examples available in a category.
// Useful for tests, docs, and the eval-harness extension that compares
// before/after scaffolding lift.
func CategoryCount(category string) int {
	entries, err := fs.ReadDir(exampleFS, path.Join("examples", category))
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n
}

// Package shellsafe provides a quote-aware command parser that rejects
// shell metacharacters outside of quoted regions. Every place in the
// codebase that fires an LLM-authored command goes through this so the
// same safety policy applies everywhere — the exploit executor, the
// confirmation agent's reproduction re-runs, the cleanup registry's
// default exec path.
//
// Callers that genuinely need a shell must wrap their command in
// `sh -c "..."` as a single quoted argument — that makes the intent
// explicit at the call site instead of implicit in the parser.
//
// Plan reference: #44.4 (extracted from internal/agent/exploit/shellparse.go).
package shellsafe

import (
	"fmt"
	"strings"
	"unicode"
)

// Parse splits a command string into argv, respecting single and double
// quotes. It rejects any unquoted shell metacharacters (|, >, <, &, ;,
// backtick, $(), newlines). This is defence-in-depth — scope and
// allowlist checks still run separately.
func Parse(cmd string) ([]string, error) {
	if err := rejectUnsafe(cmd); err != nil {
		return nil, err
	}

	var (
		args []string
		cur  strings.Builder
		in   rune // 0, '\'', or '"'
		esc  bool // previous char was backslash (inside double quotes only)
	)
	flush := func() {
		if cur.Len() > 0 {
			args = append(args, cur.String())
			cur.Reset()
		}
	}

	for _, r := range cmd {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case in == '"' && r == '\\':
			esc = true
		case in == 0 && (r == '\'' || r == '"'):
			in = r
		case in != 0 && r == in:
			in = 0
		case in == 0 && unicode.IsSpace(r):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	if in != 0 {
		return nil, fmt.Errorf("unterminated %c quote", in)
	}
	flush()
	if len(args) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	return args, nil
}

// rejectUnsafe scans for shell metacharacters outside of quoted regions.
// It's intentionally strict — false positives are a feature, not a bug,
// since any caller that needs those characters should wrap in sh -c
// explicitly.
func rejectUnsafe(cmd string) error {
	var (
		in  rune
		esc bool
	)
	for i, r := range cmd {
		switch {
		case esc:
			esc = false
			continue
		case in == '"' && r == '\\':
			esc = true
			continue
		case in == 0 && (r == '\'' || r == '"'):
			in = r
			continue
		case in != 0 && r == in:
			in = 0
			continue
		}
		if in != 0 {
			continue
		}
		switch r {
		case '|', '>', '<', '&', ';', '`':
			return fmt.Errorf("disallowed shell metachar %q at position %d", r, i)
		case '\n', '\r':
			return fmt.Errorf("newline in command at position %d", i)
		case '$':
			// Reject `$(...)` command substitution. A literal $ followed
			// by a letter or { is allowed (env-var expansion happens
			// inside exec.Cmd, not via the shell, so it's inert anyway).
			if i+1 < len(cmd) && cmd[i+1] == '(' {
				return fmt.Errorf("command substitution $( at position %d", i)
			}
		}
	}
	return nil
}

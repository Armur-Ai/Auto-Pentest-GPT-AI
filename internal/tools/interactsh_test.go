package tools

import "testing"

// TestInteractshTool_Name — adapter id matches the binary on PATH so
// scope guards and the coordinator's tool lookup find it.
func TestInteractshTool_Name(t *testing.T) {
	if n := NewInteractshTool().Name(); n != "interactsh-client" {
		t.Errorf("Name() = %q, want \"interactsh-client\"", n)
	}
}

// TestInteractshTool_IsAvailable — value is host-dependent, just
// exercises the code path.
func TestInteractshTool_IsAvailable(t *testing.T) {
	_ = NewInteractshTool().IsAvailable()
}

// TestParseInteractshURL_ExtractsSubdomain — interactsh-client's
// banner contains the assigned subdomain mixed with log noise. The
// regex pulls out the first DNS-shaped token.
func TestParseInteractshURL_ExtractsSubdomain(t *testing.T) {
	cases := map[string]struct {
		stderr string
		want   string
	}{
		"banner_with_url": {
			stderr: "[INF] Current interactsh-client version v1.2.3\n[INF] Listing 1 payload for OOB Testing\n[INF] c8r7lkp40h8jjfu4o3l0.oast.fun\n",
			want:   "c8r7lkp40h8jjfu4o3l0.oast.fun",
		},
		"url_inside_log_line": {
			stderr: "[INF] abc1234567890def.oast.online started listening for callbacks",
			want:   "abc1234567890def.oast.online",
		},
		"no_url_present": {
			stderr: "[ERR] failed to connect to server\n",
			want:   "",
		},
		"empty": {
			stderr: "",
			want:   "",
		},
	}
	for name, c := range cases {
		got := parseInteractshURL(c.stderr)
		if got != c.want {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
}

// TestParseInteractshInteractions_ValidJSONL — each line is one
// interaction object; the parser flattens them to findings with the
// protocol, source IP, and the full callback URL.
func TestParseInteractshInteractions_ValidJSONL(t *testing.T) {
	stdout := `{"protocol":"dns","unique-id":"c8r7lk","full-id":"c8r7lk.oast.fun","raw-request":"DNS query for c8r7lk.oast.fun","remote-address":"203.0.113.10","timestamp":"2026-06-05T12:00:00Z"}
{"protocol":"http","unique-id":"c8r7lk","full-id":"c8r7lk.oast.fun","raw-request":"GET / HTTP/1.1","remote-address":"203.0.113.10","timestamp":"2026-06-05T12:00:05Z"}
`
	findings := parseInteractshInteractions(stdout)
	if len(findings) != 2 {
		t.Fatalf("expected 2 interactions, got %d", len(findings))
	}
	for _, f := range findings {
		if f["tool"] != "interactsh-client" || f["type"] != "interaction" {
			t.Errorf("unexpected shape: %+v", f)
		}
		if f["oob_url"] != "c8r7lk.oast.fun" {
			t.Errorf("oob_url = %v", f["oob_url"])
		}
		if f["remote_address"] != "203.0.113.10" {
			t.Errorf("remote_address = %v", f["remote_address"])
		}
	}
	if findings[0]["protocol"] != "dns" || findings[1]["protocol"] != "http" {
		t.Errorf("protocols out of order: %v / %v", findings[0]["protocol"], findings[1]["protocol"])
	}
}

// TestParseInteractshInteractions_SkipsNonInteractionLines — startup
// banners, blank lines, and malformed JSON should not produce
// findings. Only objects with full-id or unique-id count.
func TestParseInteractshInteractions_SkipsNonInteractionLines(t *testing.T) {
	stdout := `[INF] not json at all
{"banner": "interactsh-client v1.2.3"}
{not json}

{"protocol":"dns","full-id":"valid.oast.fun","remote-address":"1.2.3.4"}
`
	findings := parseInteractshInteractions(stdout)
	if len(findings) != 1 {
		t.Fatalf("expected 1 valid finding, got %d (%+v)", len(findings), findings)
	}
	if findings[0]["oob_url"] != "valid.oast.fun" {
		t.Errorf("expected only the valid interaction to survive; got %+v", findings[0])
	}
}

// TestParseInteractshInteractions_EmptyStdout — silent listen window
// (no callbacks) produces no findings, no panic.
func TestParseInteractshInteractions_EmptyStdout(t *testing.T) {
	if got := parseInteractshInteractions(""); got != nil {
		t.Errorf("empty stdout should produce nil, got %v", got)
	}
}

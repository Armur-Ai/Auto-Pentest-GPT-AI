package tools

import (
	"testing"
)

// TestDalfoxTool_Name — adapter advertises its tool name as "dalfox"
// (no typo to "dalflox"). The coordinator + scope guard both look up
// findings by this string, so a typo would silently disable scope
// enforcement for the tool.
func TestDalfoxTool_Name(t *testing.T) {
	d := NewDalfoxTool()
	if d.Name() != "dalfox" {
		t.Errorf("Name() = %q, want \"dalfox\"", d.Name())
	}
}

// TestDalfoxTool_IsAvailable — IsAvailable mirrors IsCommandAvailable
// and returns false when the binary isn't on PATH. We assert only the
// non-panic + bool-returning contract; the actual presence depends on
// the host so we can't pin a value.
func TestDalfoxTool_IsAvailable(t *testing.T) {
	d := NewDalfoxTool()
	// Just exercises the code path — value is host-dependent.
	_ = d.IsAvailable()
}

// TestParseDalfoxJSON_ValidArray — dalfox --format=json emits a single
// JSON array of finding objects. parseDalfoxJSON must accept that
// shape and return the findings as []map[string]any.
func TestParseDalfoxJSON_ValidArray(t *testing.T) {
	input := `[
		{"type": "R", "param": "q", "evidence": "<script>alert(1)</script>", "severity": "H"},
		{"type": "V", "param": "name", "evidence": "alert(2)", "severity": "M"}
	]`
	findings := parseDalfoxJSON(input)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0]["type"] != "R" || findings[0]["param"] != "q" {
		t.Errorf("first finding mis-parsed: %+v", findings[0])
	}
	if findings[1]["severity"] != "M" {
		t.Errorf("second finding severity = %v, want M", findings[1]["severity"])
	}
}

// TestParseDalfoxJSON_EmptyOutput — dalfox produces `[]` (or empty
// string) when no XSS is found. Both should parse to a non-nil empty
// slice or nil — callers must not crash.
func TestParseDalfoxJSON_EmptyOutput(t *testing.T) {
	cases := []string{
		"",
		"   \n\n",
		"[]",
	}
	for _, c := range cases {
		findings := parseDalfoxJSON(c)
		if len(findings) != 0 {
			t.Errorf("input %q produced %d findings, want 0", c, len(findings))
		}
	}
}

// TestParseDalfoxJSON_MalformedReturnsNil — broken JSON returns nil
// rather than erroring up the call chain. RawOutput is always
// preserved on the ToolResult, so an LLM can still reason over
// unstructured text if structured parsing fails.
func TestParseDalfoxJSON_MalformedReturnsNil(t *testing.T) {
	cases := []string{
		"{not json}",
		"truncated array [",
		"this is not json at all",
		`{"single": "object", "not": "array"}`,
	}
	for _, c := range cases {
		if findings := parseDalfoxJSON(c); findings != nil {
			t.Errorf("input %q should produce nil, got %v", c, findings)
		}
	}
}

// TestParseDalfoxJSON_LogSpamReturnsNil — if dalfox output is
// contaminated with log lines (`[INFO] ...`) before the JSON array,
// the parser deliberately gives up and returns nil. RawOutput is
// preserved on the ToolResult so an LLM can still reason over it.
// We tried being clever with prefix-stripping; it mis-fires more
// often than it helps because log brackets look identical to JSON
// brackets at the byte level.
func TestParseDalfoxJSON_LogSpamReturnsNil(t *testing.T) {
	input := `[INFO] starting scan on example.com
[INFO] mining parameters...
[{"type": "R", "param": "q", "severity": "H"}]`
	if findings := parseDalfoxJSON(input); findings != nil {
		t.Errorf("log-spam-prefixed output should return nil, got %d findings", len(findings))
	}
}

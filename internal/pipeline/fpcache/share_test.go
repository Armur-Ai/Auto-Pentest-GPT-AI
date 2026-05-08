package fpcache

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnonymize_StripsTargetAndReason(t *testing.T) {
	p := Pattern{
		Target:         "secret-customer.com",
		AttackCategory: "SQLi",
		TitleContains:  "SQL Injection in /search",
		Reason:         "internal: triage said this is a known WAF false positive",
	}
	got := Anonymize(p)
	raw, _ := json.Marshal(got)
	body := string(raw)
	if strings.Contains(body, "secret-customer") {
		t.Errorf("share payload leaked target: %s", body)
	}
	if strings.Contains(body, "WAF false positive") {
		t.Errorf("share payload leaked reason: %s", body)
	}
	if got.TitleHash == "" {
		t.Error("TitleHash should be populated")
	}
	if got.AttackCategory != "sqli" {
		t.Errorf("category should be lowercased: got %q", got.AttackCategory)
	}
}

func TestTitleHash_NormalizesEquivalentTitles(t *testing.T) {
	a := titleHash("SQL Injection in /search")
	b := titleHash("Sql injection ON THE search ENDPOINTS")
	if a != b {
		t.Errorf("equivalent titles should hash equal:\n  a=%s\n  b=%s", a, b)
	}
}

func TestTitleHash_DistinguishesDifferentTitles(t *testing.T) {
	a := titleHash("SQL injection in /search")
	b := titleHash("Cross-site scripting in /comment")
	if a == b {
		t.Errorf("different titles should hash differently:\n  both=%s", a)
	}
}

func TestExportShare_RoundtripIsValidJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fp.jsonl")
	s := &Store{path: path, patterns: []Pattern{
		{Target: "a.com", AttackCategory: "XSS", TitleContains: "XSS in /q", Reason: "skip"},
		{Target: "b.com", AttackCategory: "SQLi", TitleContains: "SQLi via search"},
	}}

	out := filepath.Join(dir, "share.jsonl")
	n, err := s.ExportShare(out)
	if err != nil {
		t.Fatalf("ExportShare: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 records, got %d", n)
	}
	f, _ := os.Open(out)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		var p SharedPattern
		if err := json.Unmarshal(scanner.Bytes(), &p); err != nil {
			t.Errorf("malformed line: %v", err)
		}
		if p.TitleHash == "" {
			t.Errorf("missing TitleHash in: %s", scanner.Text())
		}
		count++
	}
	if count != 2 {
		t.Errorf("re-read got %d records, want 2", count)
	}
}

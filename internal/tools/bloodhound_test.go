package tools

import "testing"

func TestBloodHoundTool_Name(t *testing.T) {
	if n := NewBloodHoundTool().Name(); n != "bloodhound" {
		t.Errorf("Name() = %q, want \"bloodhound\"", n)
	}
}

func TestBloodHoundTool_IsAvailable(t *testing.T) { _ = NewBloodHoundTool().IsAvailable() }

// TestParseBloodHoundUsers_RoastableEmitted — AS-REP-roastable and
// Kerberoastable users each become a HIGH finding, plus a summary count.
func TestParseBloodHoundUsers_RoastableEmitted(t *testing.T) {
	input := []byte(`{
		"data": [
			{"Properties": {"name": "SVC_SQL@CORP.LOCAL", "hasspn": true, "enabled": true}},
			{"Properties": {"name": "LEGACY@CORP.LOCAL", "dontreqpreauth": true, "enabled": true}},
			{"Properties": {"name": "NORMAL@CORP.LOCAL", "enabled": true}}
		],
		"meta": {"count": 3, "type": "users"}
	}`)
	findings := parseBloodHoundUsers(input)

	var asrep, kerb, summary int
	for _, f := range findings {
		switch f["category"] {
		case "asrep_roasting":
			asrep++
			if f["severity"] != "high" || f["user"] != "LEGACY@CORP.LOCAL" {
				t.Errorf("asrep finding wrong: %+v", f)
			}
		case "kerberoasting":
			kerb++
			if f["severity"] != "high" || f["user"] != "SVC_SQL@CORP.LOCAL" {
				t.Errorf("kerberoast finding wrong: %+v", f)
			}
		case "ad_enumeration":
			summary++
			if f["count"] != 3 {
				t.Errorf("summary count = %v, want 3", f["count"])
			}
		}
	}
	if asrep != 1 || kerb != 1 || summary != 1 {
		t.Errorf("counts asrep=%d kerb=%d summary=%d; want 1 each", asrep, kerb, summary)
	}
}

// TestParseBloodHoundComputers_DelegationEmitted — computers with
// unconstrained delegation surface as HIGH findings, plus a count.
func TestParseBloodHoundComputers_DelegationEmitted(t *testing.T) {
	input := []byte(`{
		"data": [
			{"Properties": {"name": "DC01.CORP.LOCAL", "unconstraineddelegation": true}},
			{"Properties": {"name": "WS02.CORP.LOCAL", "unconstraineddelegation": false}}
		],
		"meta": {"count": 2, "type": "computers"}
	}`)
	findings := parseBloodHoundComputers(input)

	var deleg, summary int
	for _, f := range findings {
		switch f["category"] {
		case "unconstrained_delegation":
			deleg++
			if f["severity"] != "high" || f["computer"] != "DC01.CORP.LOCAL" {
				t.Errorf("delegation finding wrong: %+v", f)
			}
		case "ad_enumeration":
			summary++
			if f["count"] != 2 {
				t.Errorf("summary count = %v, want 2", f["count"])
			}
		}
	}
	if deleg != 1 || summary != 1 {
		t.Errorf("counts deleg=%d summary=%d; want 1 each", deleg, summary)
	}
}

// TestParseBloodHound_MalformedAndEmpty — malformed JSON and empty input
// return nil rather than panicking.
func TestParseBloodHound_MalformedAndEmpty(t *testing.T) {
	if got := parseBloodHoundUsers([]byte("not json")); got != nil {
		t.Errorf("expected nil for malformed users, got %v", got)
	}
	if got := parseBloodHoundComputers([]byte("")); got != nil {
		t.Errorf("expected nil for empty computers, got %v", got)
	}
}

package tools

import "testing"

func TestCrackMapExecTool_Name(t *testing.T) {
	if n := NewCrackMapExecTool().Name(); n != "crackmapexec" {
		t.Errorf("Name() = %q, want \"crackmapexec\"", n)
	}
}

func TestCrackMapExecTool_IsAvailable(t *testing.T) { _ = NewCrackMapExecTool().IsAvailable() }

// TestParseCrackMapExecText_Findings — valid creds, admin ("Pwn3d!")
// access, disabled SMB signing, and SMBv1 exposure each surface as
// distinct findings with the right severity.
func TestParseCrackMapExecText_Findings(t *testing.T) {
	input := `SMB         10.0.0.5        445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:CORP.LOCAL) (signing:False) (SMBv1:True)
SMB         10.0.0.5        445    DC01             [+] CORP.LOCAL\jsmith:Summer2024
SMB         10.0.0.6        445    WS02             [+] CORP.LOCAL\admin:P@ssw0rd (Pwn3d!)
SMB         10.0.0.7        445    WS03             [-] CORP.LOCAL\guest:guest STATUS_LOGON_FAILURE`
	findings := parseCrackMapExecText(input)

	var admin, creds, signing, smbv1 int
	for _, f := range findings {
		if f["tool"] != "crackmapexec" {
			t.Errorf("tool = %v", f["tool"])
		}
		switch f["category"] {
		case "admin_access":
			admin++
			if f["severity"] != "high" {
				t.Errorf("admin severity = %v, want high", f["severity"])
			}
		case "valid_credentials":
			creds++
			if f["severity"] != "medium" {
				t.Errorf("creds severity = %v, want medium", f["severity"])
			}
		case "smb_signing_disabled":
			signing++
		case "smbv1_enabled":
			smbv1++
		}
	}
	if admin != 1 || creds != 1 || signing != 1 || smbv1 != 1 {
		t.Errorf("counts admin=%d creds=%d signing=%d smbv1=%d; want 1 each", admin, creds, signing, smbv1)
	}
}

// TestParseCrackMapExecText_HostMetadata — proto/host/port/name are
// carried onto findings so downstream consumers can attribute them.
func TestParseCrackMapExecText_HostMetadata(t *testing.T) {
	input := `SMB         10.0.0.6        445    WS02             [+] CORP\admin:pw (Pwn3d!)`
	findings := parseCrackMapExecText(input)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f["protocol"] != "SMB" || f["host"] != "10.0.0.6" || f["port"] != "445" || f["name"] != "WS02" {
		t.Errorf("metadata not carried through: %+v", f)
	}
}

// TestParseCrackMapExecText_Empty — empty output and pure failure lines
// yield no findings.
func TestParseCrackMapExecText_Empty(t *testing.T) {
	if got := parseCrackMapExecText(""); got != nil {
		t.Errorf("expected nil for empty input, got %v", got)
	}
	if got := parseCrackMapExecText("SMB 10.0.0.7 445 WS03 [-] CORP\\guest:guest STATUS_LOGON_FAILURE"); got != nil {
		t.Errorf("expected nil for failure-only output, got %v", got)
	}
}

package engine

import "testing"

// TestBuildScopeBareIP pins the fix for the bare-IP scope bug: a target
// like "192.168.1.10" (no mask) must land in AllowedCIDRs as a /32, not
// in AllowedDomains. When filed as a domain, IP scope validation (which
// only consults AllowedCIDRs) rejects the target and every recon tool
// skips it, yielding 0 findings.
func TestBuildScopeBareIP(t *testing.T) {
	tests := []struct {
		name      string
		in        []string
		wantCIDRs []string
		wantDoms  []string
	}{
		{
			name:      "bare IPv4 becomes /32 CIDR",
			in:        []string{"192.168.1.10"},
			wantCIDRs: []string{"192.168.1.10/32"},
			wantDoms:  nil,
		},
		{
			name:      "bare IPv6 becomes /128 CIDR",
			in:        []string{"2001:db8::1"},
			wantCIDRs: []string{"2001:db8::1/128"},
			wantDoms:  nil,
		},
		{
			name:      "explicit CIDR is preserved",
			in:        []string{"10.0.0.0/24"},
			wantCIDRs: []string{"10.0.0.0/24"},
			wantDoms:  nil,
		},
		{
			name:      "domain stays a domain",
			in:        []string{"example.com"},
			wantCIDRs: nil,
			wantDoms:  []string{"example.com"},
		},
		{
			name:      "mixed scope is split correctly",
			in:        []string{"192.168.1.10", "example.com", "10.0.0.0/24"},
			wantCIDRs: []string{"192.168.1.10/32", "10.0.0.0/24"},
			wantDoms:  []string{"example.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			def, err := buildScope(tc.in)
			if err != nil {
				t.Fatalf("buildScope(%v) returned error: %v", tc.in, err)
			}
			if !equalStrings(def.AllowedCIDRs, tc.wantCIDRs) {
				t.Errorf("AllowedCIDRs = %v, want %v", def.AllowedCIDRs, tc.wantCIDRs)
			}
			if !equalStrings(def.AllowedDomains, tc.wantDoms) {
				t.Errorf("AllowedDomains = %v, want %v", def.AllowedDomains, tc.wantDoms)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

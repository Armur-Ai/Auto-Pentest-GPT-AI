package scope

import "testing"

func TestCompare_FindsAddsAndRemoves(t *testing.T) {
	prev := ScopeDefinition{
		AllowedDomains: []string{"api.acme.corp", "www.acme.corp"},
		AllowedCIDRs:   []string{"10.0.0.0/24"},
	}
	cur := ScopeDefinition{
		AllowedDomains: []string{"api.acme.corp", "shop.acme.corp"}, // -www, +shop
		AllowedCIDRs:   []string{"10.0.0.0/24", "10.0.1.0/24"},      // +10.0.1.0/24
	}
	d := Compare(prev, cur)
	if len(d.AddedDomains) != 1 || d.AddedDomains[0] != "shop.acme.corp" {
		t.Errorf("added domains: %v", d.AddedDomains)
	}
	if len(d.RemovedDomains) != 1 || d.RemovedDomains[0] != "www.acme.corp" {
		t.Errorf("removed domains: %v", d.RemovedDomains)
	}
	if len(d.AddedCIDRs) != 1 || d.AddedCIDRs[0] != "10.0.1.0/24" {
		t.Errorf("added cidrs: %v", d.AddedCIDRs)
	}
	if !d.HasChanges() {
		t.Error("HasChanges should be true")
	}
}

func TestCompare_Identical(t *testing.T) {
	a := ScopeDefinition{AllowedDomains: []string{"x.com", "y.com"}}
	d := Compare(a, a)
	if d.HasChanges() {
		t.Fatalf("identical scopes should report no changes; got %+v", d)
	}
}

func TestCompare_OutputIsSorted(t *testing.T) {
	prev := ScopeDefinition{AllowedDomains: []string{}}
	cur := ScopeDefinition{AllowedDomains: []string{"z.com", "a.com", "m.com"}}
	d := Compare(prev, cur)
	if d.AddedDomains[0] != "a.com" || d.AddedDomains[2] != "z.com" {
		t.Fatalf("output not sorted: %v", d.AddedDomains)
	}
}

package plugins

import (
	"reflect"
	"testing"
)

func TestOverlay_NilBaseReturnsOverlay(t *testing.T) {
	o := &Playbook{Name: "x"}
	if got := Overlay(nil, o); got != o {
		t.Errorf("nil base should return overlay verbatim")
	}
}

func TestOverlay_NilOverlayReturnsBaseCopy(t *testing.T) {
	b := &Playbook{Name: "base"}
	got := Overlay(b, nil)
	if got == b {
		t.Error("should return a copy, not the same pointer")
	}
	if got.Name != "base" {
		t.Errorf("name lost: %q", got.Name)
	}
}

func TestOverlay_OverlayWinsForScalars(t *testing.T) {
	b := &Playbook{Name: "base", Description: "b", Version: "1"}
	o := &Playbook{Name: "shopify", Description: "", Version: "2"}
	got := Overlay(b, o)
	if got.Name != "shopify" {
		t.Errorf("Name not overridden: %q", got.Name)
	}
	if got.Description != "b" {
		t.Errorf("empty overlay should not blank base: %q", got.Description)
	}
	if got.Version != "2" {
		t.Errorf("Version not overridden: %q", got.Version)
	}
}

func TestOverlay_TagsUnionDeduped(t *testing.T) {
	b := &Playbook{Tags: []string{"web", "bugbounty"}}
	o := &Playbook{Tags: []string{"bugbounty", "graphql"}}
	got := Overlay(b, o)
	want := []string{"web", "bugbounty", "graphql"}
	if !reflect.DeepEqual(got.Tags, want) {
		t.Errorf("tags merge wrong: %v != %v", got.Tags, want)
	}
}

func TestOverlay_VariablesOverlayWinsPerKey(t *testing.T) {
	b := &Playbook{Variables: map[string]Variable{
		"target":  {Type: "string", Required: true},
		"timeout": {Type: "int", Default: "300"},
	}}
	o := &Playbook{Variables: map[string]Variable{
		"timeout": {Type: "int", Default: "60"},  // overrides
		"focus":   {Type: "string", Default: "graphql"}, // adds
	}}
	got := Overlay(b, o)
	if got.Variables["timeout"].Default != "60" {
		t.Errorf("override missed: %+v", got.Variables["timeout"])
	}
	if got.Variables["target"].Required != true {
		t.Errorf("base var dropped: %+v", got.Variables["target"])
	}
	if got.Variables["focus"].Default != "graphql" {
		t.Errorf("overlay var missing")
	}
}

func TestOverlay_PhasesReplaceByName(t *testing.T) {
	b := &Playbook{Phases: []Phase{
		{Name: "recon", Tools: []ToolConfig{{Name: "subfinder"}}},
		{Name: "exploit"},
	}}
	o := &Playbook{Phases: []Phase{
		{Name: "recon", Tools: []ToolConfig{{Name: "amass"}}}, // replaces
		{Name: "report"},                                      // appends
	}}
	got := Overlay(b, o)
	if len(got.Phases) != 3 {
		t.Fatalf("want 3 phases (recon-replaced, exploit, report); got %d", len(got.Phases))
	}
	if got.Phases[0].Tools[0].Name != "amass" {
		t.Errorf("recon phase not replaced: %+v", got.Phases[0])
	}
	if got.Phases[1].Name != "exploit" {
		t.Errorf("base order disturbed: %+v", got.Phases)
	}
	if got.Phases[2].Name != "report" {
		t.Errorf("appended phase missing")
	}
}

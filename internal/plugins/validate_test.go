package plugins

import "testing"

func minimalOK() *Playbook {
	return &Playbook{
		Name:        "demo",
		Version:     "1.0.0",
		Author:      PlaybookAuthor{Name: "a"},
		Description: "demo playbook",
		Phases: []Phase{
			{Name: "recon", Tools: []ToolConfig{{Name: "httpx"}}},
		},
	}
}

func TestValidate_AcceptsMinimal(t *testing.T) {
	r := Validate(minimalOK(), []string{"httpx"})
	if !r.OK() {
		t.Fatalf("minimal playbook should validate: %s", r.Format())
	}
}

func TestValidate_RejectsNoName(t *testing.T) {
	pb := minimalOK()
	pb.Name = ""
	r := Validate(pb, []string{"httpx"})
	if r.OK() {
		t.Fatal("missing name should error")
	}
}

func TestValidate_RejectsNoPhases(t *testing.T) {
	pb := minimalOK()
	pb.Phases = nil
	r := Validate(pb, []string{"httpx"})
	if r.OK() {
		t.Fatal("no phases should error")
	}
}

func TestValidate_DuplicatePhaseNames(t *testing.T) {
	pb := minimalOK()
	pb.Phases = append(pb.Phases, Phase{Name: "recon"})
	r := Validate(pb, []string{"httpx"})
	if r.OK() {
		t.Fatal("duplicate phase name should error")
	}
}

func TestValidate_UndeclaredVariableRef(t *testing.T) {
	pb := minimalOK()
	pb.Phases[0].Tools[0].Options = map[string]any{"url": "https://{{ missing_var }}/"}
	r := Validate(pb, []string{"httpx"})
	if r.OK() {
		t.Fatal("undeclared var reference must error")
	}
}

func TestValidate_UnknownToolWarns(t *testing.T) {
	pb := minimalOK()
	pb.Phases[0].Tools = []ToolConfig{{Name: "custom-thing"}}
	r := Validate(pb, []string{"httpx"})
	if !r.OK() {
		t.Fatalf("unknown tool should warn (not error): %s", r.Format())
	}
	if len(r.Warnings) == 0 {
		t.Fatalf("expected a warning for unknown tool")
	}
}

func TestValidate_RequiredPlusDefaultWarns(t *testing.T) {
	pb := minimalOK()
	pb.Variables = map[string]Variable{"x": {Type: "string", Required: true, Default: "foo"}}
	r := Validate(pb, []string{"httpx"})
	if len(r.Warnings) == 0 {
		t.Fatal("required+default combo should warn")
	}
}

func TestValidate_InvalidVariableType(t *testing.T) {
	pb := minimalOK()
	pb.Variables = map[string]Variable{"x": {Type: "int64"}}
	r := Validate(pb, []string{"httpx"})
	if r.OK() {
		t.Fatal("invalid variable type should error")
	}
}

func TestValidate_InvalidSemverWarns(t *testing.T) {
	pb := minimalOK()
	pb.Version = "one-point-oh"
	r := Validate(pb, []string{"httpx"})
	if len(r.Warnings) == 0 {
		t.Fatal("non-semver version should warn")
	}
}

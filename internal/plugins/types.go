package plugins

// Playbook defines a YAML-based attack playbook.
type Playbook struct {
	Name        string              `yaml:"name" json:"name"`
	Description string              `yaml:"description" json:"description"`
	Author      PlaybookAuthor      `yaml:"author" json:"author"`
	Version     string              `yaml:"version" json:"version"`
	Tags        []string            `yaml:"tags" json:"tags"`
	Variables   map[string]Variable `yaml:"variables" json:"variables"`
	Phases      []Phase             `yaml:"phases" json:"phases"`
	Include     []string            `yaml:"include,omitempty" json:"include,omitempty"`
}

// PlaybookAuthor identifies who created the playbook.
type PlaybookAuthor struct {
	Name   string `yaml:"name" json:"name"`
	GitHub string `yaml:"github" json:"github"`
}

// Variable is a configurable parameter in a playbook.
type Variable struct {
	Type     string `yaml:"type" json:"type"`
	Required bool   `yaml:"required" json:"required"`
	Default  string `yaml:"default,omitempty" json:"default,omitempty"`
}

// Phase is a stage of a playbook execution.
type Phase struct {
	Name         string       `yaml:"name" json:"name"`
	Tools        []ToolConfig `yaml:"tools" json:"tools"`
	PostAnalysis string       `yaml:"post_analysis,omitempty" json:"post_analysis,omitempty"`
	Conditions   []string     `yaml:"conditions,omitempty" json:"conditions,omitempty"`
	Strategy     string       `yaml:"strategy,omitempty" json:"strategy,omitempty"`
}

// ToolConfig defines how a tool should be run in a phase.
type ToolConfig struct {
	Name    string         `yaml:"name" json:"name"`
	Options map[string]any `yaml:"options,omitempty" json:"options,omitempty"`
	Command string         `yaml:"command,omitempty" json:"command,omitempty"` // for custom scripts
}

// CustomToolDef defines an external tool via YAML.
type CustomToolDef struct {
	Name          string           `yaml:"name" json:"name"`
	Description   string           `yaml:"description" json:"description"`
	Command       string           `yaml:"command" json:"command"`
	OutputFormat  string           `yaml:"output_format" json:"output_format"`
	FindingParser FindingParserDef `yaml:"finding_parser" json:"finding_parser"`
	ScopeCheck    bool             `yaml:"scope_check" json:"scope_check"`
}

// FindingParserDef describes how to parse tool output into findings.
type FindingParserDef struct {
	TypeField     string `yaml:"type_field" json:"type_field"`
	Severity      string `yaml:"severity" json:"severity"`
	TitleTemplate string `yaml:"title_template" json:"title_template"`
}

// PlaybookStats tracks community usage.
type PlaybookStats struct {
	Name          string  `json:"name"`
	TimesUsed     int     `json:"times_used"`
	FindingsFound int     `json:"findings_found"`
	AvgSeverity   string  `json:"avg_severity"`
	Rating        float64 `json:"rating"`
}

package parser

// SlitherOutput is the top-level structure of Slither's JSON output.
// Slither produces this when run with --json flag.
type SlitherOutput struct {
	Success bool          `json:"success"`
	Error   *string       `json:"error"`
	Results SlitherResult `json:"results"`
}

type SlitherResult struct {
	Detectors []SlitherDetector `json:"detectors"`
}

// SlitherDetector represents a single finding from Slither's detector engine.
type SlitherDetector struct {
	Check          string            `json:"check"`
	Impact         string            `json:"impact"`       // High, Medium, Low, Informational, Optimization
	Confidence     string            `json:"confidence"`   // High, Medium, Low
	Description    string            `json:"description"`
	Elements       []DetectorElement `json:"elements"`
	MarkdownInfo   string            `json:"markdown"`
	FirstMarkdown  string            `json:"first_markdown_element"`
	ID             string            `json:"id"`
}

// DetectorElement is a code location referenced by a finding.
type DetectorElement struct {
	Type             string           `json:"type"`
	Name             string           `json:"name"`
	SourceMapping    SourceMapping    `json:"source_mapping"`
	TypeSpecificInfo TypeSpecificInfo `json:"type_specific_fields"`
}

type SourceMapping struct {
	Start    int    `json:"start"`
	Length   int    `json:"length"`
	Filename string `json:"filename_absolute"`
	Lines    []int  `json:"lines"`
}

type TypeSpecificInfo struct {
	Parent *ParentInfo `json:"parent,omitempty"`
}

type ParentInfo struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// ─── Unified Finding ─────────────────────────────────────────────────────────
// Finding is the normalized internal representation used across all packages.
// Both Slither findings and custom Go checks produce this struct.

type Finding struct {
	ID          string   `json:"id"`
	Source      string   `json:"source"`      // "slither" or "custom"
	Check       string   `json:"check"`       // detector name / check name
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Confidence  string   `json:"confidence"`
	File        string   `json:"file"`
	Lines       []int    `json:"lines"`
	Remediation string   `json:"remediation"`
	SWCRef      string   `json:"swc_ref"`     // SWC registry reference e.g. "SWC-107"
	References  []string `json:"references"`
}

// Severity represents the risk level of a finding.
type Severity string

const (
	SeverityCritical      Severity = "Critical"
	SeverityHigh          Severity = "High"
	SeverityMedium        Severity = "Medium"
	SeverityLow           Severity = "Low"
	SeverityInformational Severity = "Informational"
	SeverityOptimization  Severity = "Optimization"
)

// SeverityRank returns a numeric rank for sorting (lower = more severe).
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	case SeverityInformational:
		return 4
	case SeverityOptimization:
		return 5
	default:
		return 6
	}
}

// AnalysisReport is the final output produced after all checks are complete.
type AnalysisReport struct {
	Target      string    `json:"target"`
	GeneratedAt string    `json:"generated_at"`
	Summary     Summary   `json:"summary"`
	Findings    []Finding `json:"findings"`
}

type Summary struct {
	Total         int `json:"total"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Informational int `json:"informational"`
	Optimization  int `json:"optimization"`
}
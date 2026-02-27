package reporter

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Zubimendi/solsec/internal/parser"
)

// SARIF 2.1.0 — the format GitHub uses for Security tab annotations.
// https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

type sarifOutput struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	ShortDescription sarifMessage       `json:"shortDescription"`
	HelpURI          string             `json:"helpUri,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type SARIFReporter struct{}

func (r *SARIFReporter) Name() string { return "sarif" }

func (r *SARIFReporter) Write(report *parser.AnalysisReport, score int, outputPath string) error {
	// Build rule index from findings
	ruleMap := map[string]sarifRule{}
	for _, f := range report.Findings {
		if _, exists := ruleMap[f.Check]; !exists {
			ruleMap[f.Check] = sarifRule{
				ID:   f.Check,
				Name: f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
				HelpURI: func() string {
					if len(f.References) > 0 {
						return f.References[0]
					}
					return ""
				}(),
			}
		}
	}

	rules := make([]sarifRule, 0, len(ruleMap))
	for _, r := range ruleMap {
		rules = append(rules, r)
	}

	// Build results
	results := make([]sarifResult, 0, len(report.Findings))
	for _, f := range report.Findings {
		startLine := 1
		if len(f.Lines) > 0 {
			startLine = f.Lines[0]
		}

		results = append(results, sarifResult{
			RuleID: f.Check,
			Level:  severityToSARIFLevel(f.Severity),
			Message: sarifMessage{
				Text: fmt.Sprintf("%s\n\nRemediation: %s", f.Description, f.Remediation),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifact{URI: f.File},
						Region:           sarifRegion{StartLine: startLine},
					},
				},
			},
		})
	}

	output := sarifOutput{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "solsec",
						Version: "1.0.0",
						Rules:   rules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling SARIF: %w", err)
	}

	return os.WriteFile(outputPath, data, 0640)
}

func severityToSARIFLevel(s parser.Severity) string {
	switch s {
	case parser.SeverityCritical, parser.SeverityHigh:
		return "error"
	case parser.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
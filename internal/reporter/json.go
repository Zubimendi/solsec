package reporter

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Zubimendi/solsec/internal/parser"
	"github.com/Zubimendi/solsec/internal/scorer"
)

type JSONReporter struct{}

func (r *JSONReporter) Name() string { return "json" }

func (r *JSONReporter) Write(report *parser.AnalysisReport, score int, outputPath string) error {
	out := struct {
		*parser.AnalysisReport
		RiskScore int    `json:"risk_score"`
		Grade     string `json:"grade"`
		Verdict   string `json:"verdict"`
	}{
		AnalysisReport: report,
		RiskScore:       score,
		Grade:           scorer.Grade(score),
		Verdict:         scorer.Verdict(score),
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling JSON report: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0640); err != nil {
		return fmt.Errorf("writing JSON report to %s: %w", outputPath, err)
	}

	return nil
}
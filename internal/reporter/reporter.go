package reporter

import "github.com/Zubimendi/solsec/internal/parser"

// Reporter is implemented by every output format.
// Adding a new format means implementing this one interface — nothing else changes.
type Reporter interface {
	Write(report *parser.AnalysisReport, score int, outputPath string) error
	Name() string
}
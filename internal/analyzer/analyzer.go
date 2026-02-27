package analyzer

import (
	"fmt"
	"sort"
	"time"

	"github.com/Zubimendi/solsec/internal/analyzer/checks"
	"github.com/Zubimendi/solsec/internal/parser"
)

// Analyze runs all custom Go checks against the target and merges the results
// with already-parsed Slither findings into a complete AnalysisReport.
func Analyze(target string, slitherFindings []parser.Finding) (*parser.AnalysisReport, error) {
	allFindings := make([]parser.Finding, 0, len(slitherFindings))
	allFindings = append(allFindings, slitherFindings...)

	// Run each custom check
	type checkFn func(string) ([]parser.Finding, error)
	customChecks := []struct {
		name string
		fn   checkFn
	}{
		{"reentrancy", checks.CheckReentrancy},
		{"access-control", checks.CheckAccessControl},
		{"integer-overflow", checks.CheckIntegerOverflow},
	}

	for _, c := range customChecks {
		findings, err := c.fn(target)
		if err != nil {
			// Non-fatal: log and continue rather than aborting the whole analysis
			fmt.Printf("⚠️  Custom check '%s' encountered an error: %v\n", c.name, err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	// Deduplicate: remove custom findings that duplicate Slither findings
	// (same file + overlapping lines + same SWC reference)
	allFindings = deduplicate(allFindings)

	// Sort: most severe first
	sort.Slice(allFindings, func(i, j int) bool {
		ri := parser.SeverityRank(allFindings[i].Severity)
		rj := parser.SeverityRank(allFindings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return allFindings[i].File < allFindings[j].File
	})

	report := &parser.AnalysisReport{
		Target:      target,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Findings:    allFindings,
		Summary:     buildSummary(allFindings),
	}

	return report, nil
}

func buildSummary(findings []parser.Finding) parser.Summary {
	s := parser.Summary{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case parser.SeverityCritical:
			s.Critical++
		case parser.SeverityHigh:
			s.High++
		case parser.SeverityMedium:
			s.Medium++
		case parser.SeverityLow:
			s.Low++
		case parser.SeverityInformational:
			s.Informational++
		case parser.SeverityOptimization:
			s.Optimization++
		}
	}
	return s
}

// deduplicate removes custom findings that overlap significantly with Slither findings.
func deduplicate(findings []parser.Finding) []parser.Finding {
	seen := map[string]bool{}
	result := make([]parser.Finding, 0, len(findings))

	for _, f := range findings {
		// Key: SWC ref + file + first line
		key := f.SWCRef + "|" + f.File
		if len(f.Lines) > 0 {
			key += fmt.Sprintf("|%d", f.Lines[0])
		}

		// If we've already seen a finding with the same key from a different source, skip
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, f)
	}

	return result
}
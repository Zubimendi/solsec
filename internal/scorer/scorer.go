package scorer

import "github.com/Zubimendi/solsec/internal/parser"

// Score calculates an overall risk score from 0 (perfect) to 100 (critical risk).
// The scoring model is inspired by CVSS but simplified for smart contract context.
//
// Weights:
//   Critical: 40 points each (capped at 100)
//   High:     20 points each
//   Medium:   10 points each
//   Low:       3 points each
//   Info:      0 points
func Score(report *parser.AnalysisReport) int {
	score := 0
	score += report.Summary.Critical * 40
	score += report.Summary.High * 20
	score += report.Summary.Medium * 10
	score += report.Summary.Low * 3

	if score > 100 {
		return 100
	}
	return score
}

// Grade returns a letter grade based on the score.
//
//	0–9:   A  (Low risk — review before deployment)
//	10–24: B  (Minor issues found)
//	25–49: C  (Moderate risk — fix before deployment)
//	50–74: D  (High risk — do not deploy)
//	75–100: F (Critical risk — do not deploy)
func Grade(score int) string {
	switch {
	case score < 10:
		return "A"
	case score < 25:
		return "B"
	case score < 50:
		return "C"
	case score < 75:
		return "D"
	default:
		return "F"
	}
}

// Verdict returns a human-readable deployment recommendation.
func Verdict(score int) string {
	switch Grade(score) {
	case "A":
		return "✅ Low risk. Review findings before deployment."
	case "B":
		return "⚠️  Minor issues found. Address before mainnet deployment."
	case "C":
		return "🟠 Moderate risk. Fix all Medium+ findings before deployment."
	case "D":
		return "🔴 High risk. Do not deploy until Critical/High findings are resolved."
	default:
		return "🚨 Critical risk. This contract must not be deployed."
	}
}
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/Zubimendi/solsec/internal/analyzer"
	"github.com/Zubimendi/solsec/internal/parser"
	"github.com/Zubimendi/solsec/internal/reporter"
	"github.com/Zubimendi/solsec/internal/runner"
	"github.com/Zubimendi/solsec/internal/scorer"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze <target>",
	Short: "Analyze a Solidity contract or directory for security vulnerabilities",
	Long: `Run security analysis on a Solidity file or directory.

Combines Slither's detector engine with custom Go checks for reentrancy,
access control gaps, and integer overflow patterns.

Examples:
  solsec analyze ./contracts/Token.sol
  solsec analyze ./contracts --format html --output report.html
  solsec analyze ./contracts --format sarif --output results.sarif
  solsec analyze ./contracts --fail-on high --ci`,
	Args: cobra.ExactArgs(1),
	RunE: runAnalyze,
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	f := analyzeCmd.Flags()
	f.StringP("format", "f", "html", "Output format: json | html | sarif")
	f.StringP("output", "o", "", "Output file path (default: solsec-report.<format>)")
	f.StringP("fail-on", "", "high", "Exit with code 1 if findings at this severity or above are found: critical | high | medium | low | none")
	f.BoolP("ci", "", false, "CI mode: minimal output, exit code reflects findings")
	f.StringSlice("exclude", nil, "Slither detector names to exclude e.g. --exclude timestamp,tautology")
	f.String("solc", "", "Pin a specific solc version e.g. --solc 0.8.24")
	f.Bool("no-slither", false, "Skip Slither, run only custom Go checks")
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	target := args[0]
	format, _ := cmd.Flags().GetString("format")
	outputPath, _ := cmd.Flags().GetString("output")
	failOn, _ := cmd.Flags().GetString("fail-on")
	ciMode, _ := cmd.Flags().GetBool("ci")
	exclude, _ := cmd.Flags().GetStringSlice("exclude")
	solcVersion, _ := cmd.Flags().GetString("solc")
	noSlither, _ := cmd.Flags().GetBool("no-slither")

	if outputPath == "" {
		outputPath = fmt.Sprintf("solsec-report.%s", format)
	}

	// Validate target
	if err := runner.ValidateTarget(target); err != nil {
		return err
	}

	if !ciMode {
		fmt.Printf("🔍 Analyzing: %s\n", target)
	}

	var slitherFindings []parser.Finding

	if !noSlither {
		// Step 1: Detect environment
		if !ciMode {
			fmt.Println("   Checking environment...")
		}
		env, err := runner.DetectEnvironment()
		if err != nil {
			return fmt.Errorf("environment check failed:\n%w", err)
		}
		if !ciMode {
			fmt.Printf("   ✅ %s | Slither %s\n", env.PythonVersion, env.SlitherVersion)
		}

		// Step 2: Run Slither
		if !ciMode {
			fmt.Println("   Running Slither analysis...")
		}
		tmpJSON := filepath.Join(os.TempDir(), "solsec-slither-output.json")
		result, err := runner.Run(env, runner.Options{
			Target:           target,
			OutputPath:       tmpJSON,
			ExcludeDetectors: exclude,
			SolcVersion:      solcVersion,
		})
		if err != nil {
			return fmt.Errorf("slither execution failed: %w", err)
		}
		if !ciMode {
			fmt.Printf("   ✅ Slither completed in %s\n", result.Duration.Round(1000000))
		}
		defer os.Remove(tmpJSON)

		// Step 3: Parse Slither output
		slitherFindings, err = parser.Parse(tmpJSON)
		if err != nil {
			return fmt.Errorf("parsing slither output: %w", err)
		}
	}

	// Step 4: Run custom checks + merge
	if !ciMode {
		fmt.Println("   Running custom security checks...")
	}
	report, err := analyzer.Analyze(target, slitherFindings)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Step 5: Score
	score := scorer.Score(report)
	grade := scorer.Grade(score)
	verdict := scorer.Verdict(score)

	// Step 6: Write report
	var rep reporter.Reporter
	switch strings.ToLower(format) {
	case "json":
		rep = &reporter.JSONReporter{}
	case "sarif":
		rep = &reporter.SARIFReporter{}
	default:
		rep = &reporter.HTMLReporter{}
	}

	if err := rep.Write(report, score, outputPath); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}

	// Step 7: Print summary
	if !ciMode {
		fmt.Printf("\n%s\n", strings.Repeat("─", 60))
		fmt.Printf("  Grade: %s   Score: %d/100\n", grade, score)
		fmt.Printf("  %s\n", verdict)
		fmt.Printf("  Findings: %d total (%d critical, %d high, %d medium, %d low)\n",
			report.Summary.Total,
			report.Summary.Critical,
			report.Summary.High,
			report.Summary.Medium,
			report.Summary.Low,
		)
		fmt.Printf("  Report: %s\n", outputPath)
		fmt.Printf("%s\n\n", strings.Repeat("─", 60))
	}

	// Step 8: Exit code for CI
	if failOn != "none" {
		failSeverity := parser.Severity(capitalize(failOn))
		for _, f := range report.Findings {
			if parser.SeverityRank(f.Severity) <= parser.SeverityRank(failSeverity) {
				if ciMode {
					fmt.Printf("FAIL: %d finding(s) at %s severity or above\n",
						countAtOrAbove(report.Findings, failSeverity), failOn)
				}
				os.Exit(1)
			}
		}
	}

	return nil
}

func capitalize(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

func countAtOrAbove(findings []parser.Finding, threshold parser.Severity) int {
	count := 0
	for _, f := range findings {
		if parser.SeverityRank(f.Severity) <= parser.SeverityRank(threshold) {
			count++
		}
	}
	return count
}
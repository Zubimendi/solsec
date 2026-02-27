package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const defaultTimeout = 5 * time.Minute

// Options configures a Slither analysis run.
type Options struct {
	// Target is the path to a .sol file or a directory of contracts.
	Target string

	// OutputPath is where the JSON output file will be written.
	// If empty, a temp file is used.
	OutputPath string

	// Timeout overrides the default 5-minute subprocess timeout.
	Timeout time.Duration

	// ExcludeDetectors lists Slither detector names to skip.
	ExcludeDetectors []string

	// SolcVersion pins a specific solc compiler version e.g. "0.8.24".
	SolcVersion string
}

// Result holds everything captured from a Slither subprocess run.
type Result struct {
	JSONOutputPath string
	Stdout         string
	Stderr         string
	Duration       time.Duration
}

// Run executes Slither against the target, writes JSON output, and returns
// the path to the JSON file plus captured stdio for debugging.
func Run(env *Environment, opts Options) (*Result, error) {
	if opts.Timeout == 0 {
		opts.Timeout = defaultTimeout
	}

	// Determine output file path
	outputPath := opts.OutputPath
	if outputPath == "" {
		tmp, err := os.CreateTemp("", "solsec-slither-*.json")
		if err != nil {
			return nil, fmt.Errorf("creating temp file: %w", err)
		}
		tmp.Close()
		outputPath = tmp.Name()
	}

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(outputPath), 0750); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	// Build Slither command
	// slither <target> --json <output> [--exclude <detectors>] [--solc-args ...]
	args := []string{
		opts.Target,
		"--json", outputPath,
		"--json-types", "detectors",   // only include detector results, not AST
		"--no-fail-pedantic",           // don't exit non-zero on findings
	}

	if len(opts.ExcludeDetectors) > 0 {
		for _, d := range opts.ExcludeDetectors {
			args = append(args, "--exclude", d)
		}
	}

	if opts.SolcVersion != "" {
		args = append(args, "--solc-remaps", fmt.Sprintf("solc=%s", opts.SolcVersion))
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, env.SlitherPath, args...)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	start := time.Now()
	// Slither exits with code 1 when findings are present — this is normal.
	// We only treat it as a real error if the JSON file wasn't produced.
	_ = cmd.Run()
	duration := time.Since(start)

	// Confirm the JSON output file exists — if not, Slither truly failed
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		return nil, fmt.Errorf(
			"slither did not produce output\nstderr: %s",
			stderrBuf.String(),
		)
	}

	return &Result{
		JSONOutputPath: outputPath,
		Stdout:         stdoutBuf.String(),
		Stderr:         stderrBuf.String(),
		Duration:       duration,
	}, nil
}

// ValidateTarget checks that the target exists and looks like Solidity.
func ValidateTarget(target string) error {
	info, err := os.Stat(target)
	if os.IsNotExist(err) {
		return fmt.Errorf("target not found: %s", target)
	}
	if err != nil {
		return fmt.Errorf("accessing target: %w", err)
	}

	if info.IsDir() {
		// Accept directories — Slither handles them
		return nil
	}

	if filepath.Ext(target) != ".sol" {
		return fmt.Errorf("target must be a .sol file or a directory, got: %s", target)
	}

	return nil
}

// IsValidJSON does a quick sanity check that the output file contains valid JSON.
// Used to catch cases where Slither wrote an error message instead of JSON.
func IsValidJSON(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return json.Valid(data)
}
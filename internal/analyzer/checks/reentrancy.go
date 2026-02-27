package checks

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Zubimendi/solsec/internal/parser"
)

// CheckReentrancy scans Solidity source for the classic reentrancy anti-pattern:
// an external call followed by a state change, without a reentrancy guard.
//
// This check catches patterns that Slither's reentrancy detector sometimes misses
// at Low confidence — particularly in newer Solidity syntax styles.
func CheckReentrancy(target string) ([]parser.Finding, error) {
	files, err := solidityFiles(target)
	if err != nil {
		return nil, err
	}

	var findings []parser.Finding
	for _, file := range files {
		fileFindings, err := checkReentrancyInFile(file)
		if err != nil {
			return nil, err
		}
		findings = append(findings, fileFindings...)
	}
	return findings, nil
}

func checkReentrancyInFile(path string) ([]parser.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var (
		findings       []parser.Finding
		lines          []string
		inFunction     bool
		functionName   string
		sawExternalCall bool
		callLine       int
		hasGuard       bool
		lineNum        int
	)

	// Signals of an external call
	externalCallPatterns := []string{
		".call{", ".call(",
		".delegatecall(",
		".transfer(",
		".send(",
	}

	// Signals of state changes after a call
	stateChangePatterns := []string{
		"balances[",
		"balanceOf[",
		"= 0;",
		"-= ",
		"+= ",
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		lines = append(lines, line)

		// Track function boundaries
		if strings.Contains(trimmed, "function ") && strings.Contains(trimmed, "(") {
			inFunction = true
			sawExternalCall = false
			hasGuard = false
			functionName = extractFunctionName(trimmed)
		}

		if !inFunction {
			continue
		}

		// Detect reentrancy guard
		if strings.Contains(trimmed, "nonReentrant") ||
			strings.Contains(trimmed, "ReentrancyGuard") ||
			strings.Contains(trimmed, "mutex") {
			hasGuard = true
		}

		// Detect external call
		for _, pattern := range externalCallPatterns {
			if strings.Contains(trimmed, pattern) && !strings.HasPrefix(trimmed, "//") {
				sawExternalCall = true
				callLine = lineNum
			}
		}

		// Detect state change AFTER an external call — the dangerous ordering
		if sawExternalCall && !hasGuard {
			for _, pattern := range stateChangePatterns {
				if strings.Contains(trimmed, pattern) && !strings.HasPrefix(trimmed, "//") {
					findings = append(findings, parser.Finding{
						ID:     fmt.Sprintf("CUSTOM-REENTRANT-%d", len(findings)+1),
						Source: "custom",
						Check:  "custom-reentrancy-ordering",
						Title:  "State Change After External Call (Reentrancy Risk)",
						Description: fmt.Sprintf(
							"In function '%s' (%s line %d): state variable modified after external call on line %d. "+
								"If the callee re-enters this function before the state update, it can exploit the stale state.",
							functionName, path, lineNum, callLine,
						),
						Severity:   parser.SeverityHigh,
						Confidence: "Medium",
						File:       path,
						Lines:      []int{callLine, lineNum},
						Remediation: "Move all state changes BEFORE the external call (checks-effects-interactions). " +
							"Alternatively, add OpenZeppelin's nonReentrant modifier.",
						SWCRef:     "SWC-107",
						References: []string{
							"https://swcregistry.io/docs/SWC-107",
							"https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard",
						},
					})
					break
				}
			}
		}

		// Reset at closing brace
		if trimmed == "}" {
			inFunction = false
			sawExternalCall = false
		}
	}

	return findings, scanner.Err()
}

func extractFunctionName(line string) string {
	// "function transfer(address to, uint256 amount)" → "transfer"
	start := strings.Index(line, "function ") + len("function ")
	rest := line[start:]
	end := strings.IndexAny(rest, "( ")
	if end < 0 {
		return rest
	}
	return rest[:end]
}
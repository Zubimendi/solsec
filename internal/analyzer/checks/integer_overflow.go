package checks

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Zubimendi/solsec/internal/parser"
)

// CheckIntegerOverflow scans for unchecked arithmetic in Solidity < 0.8.0
// and dangerous use of unchecked{} blocks in 0.8.0+.
func CheckIntegerOverflow(target string) ([]parser.Finding, error) {
	files, err := solidityFiles(target)
	if err != nil {
		return nil, err
	}

	var findings []parser.Finding
	for _, file := range files {
		fileFindings, err := checkIntegerOverflowInFile(file)
		if err != nil {
			return nil, err
		}
		findings = append(findings, fileFindings...)
	}
	return findings, nil
}

func checkIntegerOverflowInFile(path string) ([]parser.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var (
		findings      []parser.Finding
		lineNum       int
		solidityMajor int
		solidityMinor int
		inUnchecked   bool
		uncheckedLine int
	)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Extract Solidity version from pragma
		if strings.HasPrefix(trimmed, "pragma solidity") {
			solidityMajor, solidityMinor = extractSolidityVersion(trimmed)
		}

		// Track unchecked blocks (valid in 0.8.0+, dangerous if misused)
		if trimmed == "unchecked {" || trimmed == "unchecked{" {
			inUnchecked = true
			uncheckedLine = lineNum
		}
		if inUnchecked && trimmed == "}" {
			inUnchecked = false
		}

		// For Solidity < 0.8: flag arithmetic without SafeMath
		if solidityMajor == 0 && solidityMinor < 8 {
			if containsArithmetic(trimmed) && !strings.Contains(trimmed, "SafeMath") && !strings.HasPrefix(trimmed, "//") {
				findings = append(findings, parser.Finding{
					ID:     fmt.Sprintf("CUSTOM-OVERFLOW-%d", len(findings)+1),
					Source: "custom",
					Check:  "custom-integer-overflow",
					Title:  "Potential Integer Overflow (Solidity < 0.8)",
					Description: fmt.Sprintf(
						"%s:%d — Arithmetic operation in Solidity %d.%d.x without SafeMath. "+
							"Integer overflow/underflow silently wraps in versions before 0.8.0.",
						path, lineNum, solidityMajor, solidityMinor,
					),
					Severity:   parser.SeverityHigh,
					Confidence: "Medium",
					File:       path,
					Lines:      []int{lineNum},
					Remediation: "Upgrade to Solidity ^0.8.0 where overflow/underflow revert by default. " +
						"If upgrading is not possible, use OpenZeppelin SafeMath for all arithmetic.",
					SWCRef: "SWC-101",
					References: []string{
						"https://swcregistry.io/docs/SWC-101",
						"https://docs.openzeppelin.com/contracts/4.x/api/utils#SafeMath",
					},
				})
			}
		}

		// For Solidity >= 0.8: flag unchecked blocks containing arithmetic on user-supplied values
		if solidityMajor == 0 && solidityMinor >= 8 && inUnchecked {
			if containsArithmetic(trimmed) && !strings.HasPrefix(trimmed, "//") {
				findings = append(findings, parser.Finding{
					ID:     fmt.Sprintf("CUSTOM-UNCHECKED-%d", len(findings)+1),
					Source: "custom",
					Check:  "custom-unchecked-arithmetic",
					Title:  "Arithmetic Inside unchecked{} Block",
					Description: fmt.Sprintf(
						"%s:%d — Arithmetic operation inside an unchecked{} block (started line %d). "+
							"Overflow protection is deliberately disabled here. Verify this is intentional.",
						path, lineNum, uncheckedLine,
					),
					Severity:   parser.SeverityLow,
					Confidence: "High",
					File:       path,
					Lines:      []int{uncheckedLine, lineNum},
					Remediation: "Only use unchecked{} when overflow is mathematically impossible " +
						"(e.g. loop counter bounded by array length). Add a comment explaining why it is safe.",
					SWCRef: "SWC-101",
					References: []string{
						"https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic",
					},
				})
			}
		}
	}

	return findings, scanner.Err()
}

func containsArithmetic(line string) bool {
	ops := []string{" + ", " - ", " * ", " / ", " % ", "++", "--", "+=", "-=", "*=", "/="}
	for _, op := range ops {
		if strings.Contains(line, op) {
			return true
		}
	}
	return false
}

func extractSolidityVersion(pragma string) (major, minor int) {
	// "pragma solidity ^0.8.24;" → 0, 8
	for _, part := range strings.Fields(pragma) {
		cleaned := strings.TrimLeft(part, "^>=<~")
		cleaned = strings.Trim(cleaned, ";")
		parts := strings.Split(cleaned, ".")
		if len(parts) >= 2 {
			fmt.Sscanf(parts[0], "%d", &major)
			fmt.Sscanf(parts[1], "%d", &minor)
			if major == 0 && minor > 0 {
				return
			}
		}
	}
	return 0, 8 // default to 0.8 (safe)
}
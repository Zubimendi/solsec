package checks

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Zubimendi/solsec/internal/parser"
)

// CheckAccessControl scans for mint, burn, pause, and upgrade functions
// that lack any access control modifier.
func CheckAccessControl(target string) ([]parser.Finding, error) {
	files, err := solidityFiles(target)
	if err != nil {
		return nil, err
	}

	var findings []parser.Finding
	for _, file := range files {
		fileFindings, err := checkAccessControlInFile(file)
		if err != nil {
			return nil, err
		}
		findings = append(findings, fileFindings...)
	}
	return findings, nil
}

// sensitivePatterns are function name patterns that should always be access-controlled.
var sensitivePatterns = []struct {
	keyword  string
	severity parser.Severity
	note     string
}{
	{"mint", parser.SeverityCritical, "Unrestricted minting allows anyone to inflate token supply to infinity."},
	{"burn", parser.SeverityHigh, "Unrestricted burning allows anyone to destroy any holder's tokens."},
	{"pause", parser.SeverityHigh, "Unrestricted pause allows any caller to halt all transfers (griefing attack)."},
	{"unpause", parser.SeverityHigh, "Unrestricted unpause can bypass emergency stops."},
	{"upgradeTo", parser.SeverityCritical, "Unrestricted upgrades allow full contract takeover."},
	{"upgradeToAndCall", parser.SeverityCritical, "Unrestricted upgrades allow full contract takeover."},
	{"setOwner", parser.SeverityCritical, "Unrestricted owner changes allow full protocol takeover."},
	{"transferOwnership", parser.SeverityHigh, "Should be guarded — accidental calls transfer admin rights."},
	{"withdraw", parser.SeverityHigh, "Unrestricted withdrawals allow draining of contract funds."},
	{"selfdestruct", parser.SeverityCritical, "Unrestricted selfdestruct permanently destroys the contract."},
}

// accessModifiers are known Solidity/OpenZeppelin access guard signals.
var accessModifiers = []string{
	"onlyOwner",
	"onlyRole",
	"onlyAdmin",
	"onlyMinter",
	"onlyPauser",
	"requiresAuth",
	"restricted",
	"auth",
	"isOwner",
}

func checkAccessControlInFile(path string) ([]parser.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var findings []parser.Finding
	lineNum := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		// Only look at function declarations
		if !strings.Contains(trimmed, "function ") {
			continue
		}

		// Check each sensitive function pattern
		for _, sp := range sensitivePatterns {
			if !containsFunctionNamed(trimmed, sp.keyword) {
				continue
			}

			// Check if this function signature (may span multiple lines — check this line)
			// has a known access modifier
			if hasAccessModifier(trimmed) {
				continue
			}

			// Check visibility — internal/private functions can't be called externally
			if strings.Contains(trimmed, " internal ") || strings.Contains(trimmed, " private ") {
				continue
			}

			findings = append(findings, parser.Finding{
				ID:     fmt.Sprintf("CUSTOM-ACCESS-%d", len(findings)+1),
				Source: "custom",
				Check:  "custom-missing-access-control",
				Title:  fmt.Sprintf("Missing Access Control on %s()", extractFunctionName(trimmed)),
				Description: fmt.Sprintf(
					"%s:%d — Function '%s' appears to be missing an access control modifier. %s",
					path, lineNum, extractFunctionName(trimmed), sp.note,
				),
				Severity:   sp.severity,
				Confidence: "Medium",
				File:       path,
				Lines:      []int{lineNum},
				Remediation: fmt.Sprintf(
					"Add an access control modifier to '%s()'. Use onlyOwner (OpenZeppelin Ownable) "+
						"or onlyRole(ROLE) (OpenZeppelin AccessControl) depending on your access model.",
					extractFunctionName(trimmed),
				),
				SWCRef: "SWC-105",
				References: []string{
					"https://swcregistry.io/docs/SWC-105",
					"https://docs.openzeppelin.com/contracts/4.x/access-control",
				},
			})
		}
	}

	return findings, scanner.Err()
}

func containsFunctionNamed(line, keyword string) bool {
	lower := strings.ToLower(line)
	// Match "function mint(" or "function mintTokens(" etc.
	idx := strings.Index(lower, "function "+keyword)
	if idx < 0 {
		return false
	}
	// Confirm next char after keyword is ( or uppercase (to avoid partial matches)
	after := lower[idx+len("function ")+len(keyword):]
	return strings.HasPrefix(after, "(") ||
		(len(after) > 0 && after[0] >= 'A' && after[0] <= 'Z')
}

func hasAccessModifier(line string) bool {
	lower := strings.ToLower(line)
	for _, mod := range accessModifiers {
		if strings.Contains(lower, strings.ToLower(mod)) {
			return true
		}
	}
	return false
}
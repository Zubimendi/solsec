package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// remediations maps Slither detector check names to human-readable fix guidance.
// This is the "opinionated output" that makes solsec more useful than raw Slither.
var remediations = map[string]string{
	"reentrancy-eth":        "Apply the checks-effects-interactions pattern. Move all state changes before external calls. Consider using ReentrancyGuard from OpenZeppelin.",
	"reentrancy-no-eth":     "Apply the checks-effects-interactions pattern. Move all state changes before external calls.",
	"reentrancy-benign":     "Although impact is low, apply checks-effects-interactions pattern as defence in depth.",
	"reentrancy-unlimited-gas": "Apply the checks-effects-interactions pattern and use ReentrancyGuard.",
	"unprotected-upgrade":   "Add access control to upgrade functions. Use OpenZeppelin's OwnableUpgradeable.",
	"controlled-delegatecall": "Avoid passing user-controlled data to delegatecall. Whitelist allowed targets.",
	"arbitrary-send-eth":    "Restrict which addresses can receive ETH. Use a withdrawal pattern with explicit recipient validation.",
	"suicidal":              "Remove selfdestruct or gate it behind a multi-sig with a timelock.",
	"backdoor":              "Remove any functions that allow unauthorized state manipulation.",
	"tx-origin":             "Replace tx.origin with msg.sender for authentication. tx.origin is vulnerable to phishing attacks.",
	"weak-prng":             "Do not use block.timestamp or blockhash for randomness. Use Chainlink VRF or commit-reveal schemes.",
	"timestamp":             "Avoid using block.timestamp for critical logic. Miners can manipulate it by ~15 seconds.",
	"unchecked-transfer":    "Always check the return value of ERC-20 transfer() and transferFrom(). Use SafeERC20 from OpenZeppelin.",
	"uninitialized-local":   "Initialize all local variables before use. Uninitialized storage pointers in older Solidity versions can corrupt state.",
	"shadowing-state":       "Rename the local variable to avoid shadowing the state variable. This causes silent bugs.",
	"abiencoderv2-array":    "Upgrade to Solidity 0.8.x where ABIEncoderV2 is stable, or avoid nested dynamic arrays.",
	"msg-value-loop":        "Do not use msg.value inside a loop — it does not change per iteration and causes logic errors.",
	"divide-before-multiply": "Perform multiplications before divisions to avoid precision loss due to integer truncation.",
	"tautology":             "Remove the tautological condition — it always evaluates to true/false and may hide a logic error.",
	"boolean-equality":      "Compare bool directly (if flag) instead of (if flag == true). The latter is redundant and reduces readability.",
}

// swcRefs maps detector names to SWC registry IDs for professional report references.
var swcRefs = map[string]string{
	"reentrancy-eth":          "SWC-107",
	"reentrancy-no-eth":       "SWC-107",
	"reentrancy-benign":       "SWC-107",
	"tx-origin":               "SWC-115",
	"weak-prng":               "SWC-120",
	"timestamp":               "SWC-116",
	"unprotected-upgrade":     "SWC-112",
	"arbitrary-send-eth":      "SWC-105",
	"suicidal":                "SWC-106",
	"unchecked-transfer":      "SWC-104",
	"divide-before-multiply":  "SWC-101",
}

// Parse reads a Slither JSON output file and converts it into unified Finding structs.
func Parse(slitherJSONPath string) ([]Finding, error) {
	data, err := os.ReadFile(slitherJSONPath)
	if err != nil {
		return nil, fmt.Errorf("reading slither output: %w", err)
	}
	return ParseBytes(data)
}

// ParseBytes parses raw Slither JSON bytes — used in tests.
func ParseBytes(data []byte) ([]Finding, error) {
	var output SlitherOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("parsing slither JSON: %w", err)
	}

	if !output.Success {
		errMsg := "unknown error"
		if output.Error != nil {
			errMsg = *output.Error
		}
		return nil, fmt.Errorf("slither analysis failed: %s", errMsg)
	}

	findings := make([]Finding, 0, len(output.Results.Detectors))
	for i, d := range output.Results.Detectors {
		f := Finding{
			ID:          fmt.Sprintf("SLITHER-%03d", i+1),
			Source:      "slither",
			Check:       d.Check,
			Title:       formatTitle(d.Check),
			Description: strings.TrimSpace(d.Description),
			Severity:    mapImpact(d.Impact),
			Confidence:  d.Confidence,
			Remediation: remediationFor(d.Check),
			SWCRef:      swcRefs[d.Check],
			References:  referencesFor(d.Check),
		}

		// Extract file and line info from the first element
		if len(d.Elements) > 0 {
			el := d.Elements[0]
			f.File = el.SourceMapping.Filename
			f.Lines = el.SourceMapping.Lines
		}

		findings = append(findings, f)
	}

	return findings, nil
}

// mapImpact converts Slither's impact string to our Severity type.
func mapImpact(impact string) Severity {
	switch strings.ToLower(impact) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "informational":
		return SeverityInformational
	case "optimization":
		return SeverityOptimization
	default:
		return SeverityInformational
	}
}

// formatTitle converts a detector check name like "reentrancy-eth" to "Reentrancy (ETH)".
func formatTitle(check string) string {
	check = strings.ReplaceAll(check, "-", " ")
	parts := strings.Fields(check)
	for i, p := range parts {
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

func remediationFor(check string) string {
	if r, ok := remediations[check]; ok {
		return r
	}
	return "Review the Slither documentation for this detector and apply the recommended fix."
}

func referencesFor(check string) []string {
	refs := []string{
		fmt.Sprintf("https://github.com/crytic/slither/wiki/Detector-Documentation#%s", check),
	}
	if swc, ok := swcRefs[check]; ok {
		refs = append(refs, fmt.Sprintf("https://swcregistry.io/docs/%s", swc))
	}
	return refs
}
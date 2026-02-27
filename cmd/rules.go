package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List all built-in custom security checks",
	Run: func(cmd *cobra.Command, args []string) {
		rules := []struct {
			Name        string
			Severity    string
			Description string
		}{
			{"custom-reentrancy-ordering", "High", "State change after external call without reentrancy guard"},
			{"custom-missing-access-control", "Critical/High", "Sensitive functions (mint, burn, pause, upgrade) without access modifiers"},
			{"custom-integer-overflow", "High", "Arithmetic without SafeMath in Solidity <0.8"},
			{"custom-unchecked-arithmetic", "Low", "Arithmetic inside unchecked{} blocks"},
		}

		fmt.Println("\n📋 solsec Built-in Custom Checks")
		for _, r := range rules {
			fmt.Printf("  %-40s [%s]\n    %s\n\n", r.Name, r.Severity, r.Description)
		}
		fmt.Println("  Plus all Slither detectors: https://github.com/crytic/slither/wiki/Detector-Documentation")
	},
}

func init() { rootCmd.AddCommand(rulesCmd) }
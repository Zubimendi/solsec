package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	appName    = "solsec"
	appVersion = "1.0.0"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   appName,
	Short: "Smart Contract Static Analyzer — security-first Solidity auditing",
	Long: `
███████╗ ██████╗ ██╗      ███████╗███████╗ ██████╗
██╔════╝██╔═══██╗██║      ██╔════╝██╔════╝██╔════╝
███████╗██║   ██║██║      ███████╗█████╗  ██║
╚════██║██║   ██║██║      ╚════██║██╔══╝  ██║
███████║╚██████╔╝███████╗ ███████║███████╗╚██████╗
╚══════╝ ╚═════╝ ╚══════╝ ╚══════╝╚══════╝ ╚═════╝

Security-first Solidity static analysis.
Wraps Slither with opinionated output, custom checks, and
severity-ranked reports in JSON, HTML, and SARIF formats.
`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: $HOME/.solsec.yaml)")
	_ = viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, _ := os.UserHomeDir()
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".solsec")
	}
	viper.AutomaticEnv()
	_ = viper.ReadInConfig()
}
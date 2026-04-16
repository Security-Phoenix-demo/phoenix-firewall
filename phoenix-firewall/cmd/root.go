// Package cmd implements the CLI commands for the Phoenix Security Supply Chain Firewall.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "phoenix-firewall",
	Short: "Phoenix Security Supply Chain Firewall",
	Long: `A MITM proxy that intercepts package manager registry requests
(npm, pip, cargo, gem, maven), checks packages against the Phoenix
Security firewall API, and blocks or warns on malicious packages.`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().String("api-url", "http://localhost:8000", "Phoenix firewall API base URL")
	rootCmd.PersistentFlags().String("api-key", "", "Phoenix firewall API key")
	rootCmd.PersistentFlags().Int("port", 8080, "Proxy listen port")
	rootCmd.PersistentFlags().Bool("verbose", false, "Enable verbose logging")
	rootCmd.PersistentFlags().String("log-format", "text", "Log format (json|text)")
	rootCmd.PersistentFlags().Bool("ci", false, "CI mode: non-interactive, exit code 1 if any package blocked")
	rootCmd.PersistentFlags().Bool("strict", false, "Strict mode: treat warn actions as block")
	rootCmd.PersistentFlags().String("fallback-feed", "", "Path to local JSON feed file for offline mode")
	rootCmd.PersistentFlags().String("report-path", "", "Path to write JSON scan report")

	_ = viper.BindPFlag("api_url", rootCmd.PersistentFlags().Lookup("api-url"))
	_ = viper.BindPFlag("api_key", rootCmd.PersistentFlags().Lookup("api-key"))
	_ = viper.BindPFlag("port", rootCmd.PersistentFlags().Lookup("port"))
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	_ = viper.BindPFlag("log_format", rootCmd.PersistentFlags().Lookup("log-format"))
	_ = viper.BindPFlag("ci_mode", rootCmd.PersistentFlags().Lookup("ci"))
	_ = viper.BindPFlag("strict_mode", rootCmd.PersistentFlags().Lookup("strict"))
	_ = viper.BindPFlag("fallback_feed", rootCmd.PersistentFlags().Lookup("fallback-feed"))
	_ = viper.BindPFlag("report_path", rootCmd.PersistentFlags().Lookup("report-path"))
}

func initConfig() {
	viper.SetEnvPrefix("PHOENIX")
	viper.AutomaticEnv()
}

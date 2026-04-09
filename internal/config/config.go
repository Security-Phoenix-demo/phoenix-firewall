// Package config provides configuration loading for the Phoenix firewall proxy.
// Configuration is resolved from environment variables (PHOENIX_ prefix) and CLI flags.
package config

import "github.com/spf13/viper"

// Config holds all runtime configuration for the firewall proxy.
type Config struct {
	// APIUrl is the base URL of the Phoenix firewall API.
	APIUrl string
	// APIKey is the authentication key for the firewall API.
	APIKey string
	// Port is the local port the proxy listens on.
	Port int
	// Verbose enables debug-level logging.
	Verbose bool
	// LogFormat controls log output format ("json" or "text").
	LogFormat string
	// StrictMode blocks packages on any API error (fail-closed).
	StrictMode bool
	// CIMode enables CI-friendly output (exit codes, structured reports).
	CIMode bool
	// FallbackFeed is the path to a local JSON feed used when the API is unreachable.
	FallbackFeed string
	// ReportPath is the file path where scan reports are written.
	ReportPath string
}

// Load reads configuration from viper (flags + env vars) and returns a Config.
func Load() *Config {
	return &Config{
		APIUrl:       viper.GetString("api_url"),
		APIKey:       viper.GetString("api_key"),
		Port:         viper.GetInt("port"),
		Verbose:      viper.GetBool("verbose"),
		LogFormat:    viper.GetString("log_format"),
		StrictMode:   viper.GetBool("strict_mode"),
		CIMode:       viper.GetBool("ci_mode"),
		FallbackFeed: viper.GetString("fallback_feed"),
		ReportPath:   viper.GetString("report_path"),
	}
}

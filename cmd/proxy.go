package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/nicokoenig/phoenix-firewall/internal/config"
	"github.com/nicokoenig/phoenix-firewall/internal/proxy"
	"github.com/spf13/cobra"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start the MITM proxy server",
	Long:  `Start an HTTP proxy that intercepts package manager requests and checks them against the Phoenix firewall API.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Load()

		// Resolve CA directory
		caDir, _ := cmd.Flags().GetString("ca-dir")
		if caDir == "" {
			caDir = proxy.DefaultCADir()
		}

		trust, _ := cmd.Flags().GetBool("trust")

		// Ensure CA exists
		fmt.Printf("CA directory: %s\n", caDir)
		ca, err := proxy.EnsureCA(caDir)
		if err != nil {
			return fmt.Errorf("ensure CA: %w", err)
		}
		fmt.Println("CA certificate ready.")

		// Optionally inject into system trust store
		if trust {
			certPath := filepath.Join(caDir, "phoenix-ca.crt")
			if err := proxy.InjectCA(certPath); err != nil {
				fmt.Printf("Warning: auto trust injection failed: %v\n", err)
				fmt.Println("The proxy will still work if you configure your package manager to trust the CA manually.")
			}
		}

		// Load fallback feed if configured
		var fallbackFeed *proxy.FallbackFeed
		if cfg.FallbackFeed != "" {
			feed, feedErr := proxy.LoadFallbackFeed(cfg.FallbackFeed)
			if feedErr != nil {
				return fmt.Errorf("load fallback feed: %w", feedErr)
			}
			log.Printf("Loaded fallback feed with %d entries from %s", feed.Len(), cfg.FallbackFeed)
			fallbackFeed = feed
		}

		// Create reporter if report path configured or CI mode enabled
		var reporter *proxy.Reporter
		if cfg.ReportPath != "" || cfg.CIMode {
			reporter = proxy.NewReporter()
		}

		fmt.Printf("Starting proxy on :%d\n", cfg.Port)
		if cfg.StrictMode {
			fmt.Println("Strict mode: warn actions will be treated as block")
		}
		if cfg.CIMode {
			fmt.Println("CI mode: will exit with code 1 if any packages blocked")
		}

		srv := proxy.NewServer(cfg)
		srv.SetCA(ca)

		// Configure the handler with new features after server creation
		srv.ConfigureHandler(func(h *proxy.RequestHandler) {
			if cfg.StrictMode {
				h.SetStrictMode(true)
			}
			if reporter != nil {
				h.SetReporter(reporter)
			}
			if fallbackFeed != nil {
				h.SetFallbackFeed(fallbackFeed)
			}
		})

		// Set up graceful shutdown via signal
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			log.Println("Received shutdown signal")
			cancel()
		}()

		srvErr := srv.StartWithContext(ctx)

		// Write report on shutdown
		if reporter != nil && cfg.ReportPath != "" {
			if writeErr := reporter.Write(cfg.ReportPath); writeErr != nil {
				log.Printf("Warning: failed to write report: %v", writeErr)
			} else {
				log.Printf("Report written to %s", cfg.ReportPath)
			}
		}

		// Print summary if reporter exists
		if reporter != nil {
			summary := reporter.Summary()
			fmt.Printf("\nScan Summary: %d total, %d blocked, %d warned, %d allowed\n",
				summary.TotalPackages, summary.Blocked, summary.Warned, summary.Allowed)
		}

		// CI mode: exit with code 1 if any packages were blocked
		if cfg.CIMode && reporter != nil && reporter.HasBlocked() {
			fmt.Fprintln(os.Stderr, "CI mode: blocked packages detected, exiting with code 1")
			os.Exit(1)
		}

		return srvErr
	},
}

func init() {
	rootCmd.AddCommand(proxyCmd)

	proxyCmd.Flags().String("ca-dir", "", "Directory for CA certificate and key (default: ~/.phoenix-firewall/ca/)")
	proxyCmd.Flags().Bool("trust", false, "Attempt to inject CA into system trust store (requires sudo)")
}

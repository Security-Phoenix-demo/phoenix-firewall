package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/nicokoenig/phoenix-firewall/internal/client"
	"github.com/nicokoenig/phoenix-firewall/internal/config"
	"github.com/nicokoenig/phoenix-firewall/internal/proxy"
	"github.com/nicokoenig/phoenix-firewall/internal/registry"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "One-shot lockfile scan",
	Long:  `Parse a lockfile (package-lock.json, requirements.txt, Cargo.lock), check all packages against the Phoenix firewall, and output a report.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Load()

		lockfile, _ := cmd.Flags().GetString("lockfile")
		if lockfile == "" {
			return fmt.Errorf("--lockfile is required")
		}

		// Detect ecosystem from filename
		packages, err := parseLockfile(lockfile)
		if err != nil {
			return fmt.Errorf("parse lockfile: %w", err)
		}

		if len(packages) == 0 {
			fmt.Println("No packages found in lockfile.")
			return nil
		}

		fmt.Printf("Found %d packages in %s\n", len(packages), lockfile)

		// Load fallback feed if configured
		var fallbackFeed *proxy.FallbackFeed
		if cfg.FallbackFeed != "" {
			feed, feedErr := proxy.LoadFallbackFeed(cfg.FallbackFeed)
			if feedErr != nil {
				return fmt.Errorf("load fallback feed: %w", feedErr)
			}
			log.Printf("Loaded fallback feed with %d entries", feed.Len())
			fallbackFeed = feed
		}

		// Create firewall client
		fwClient := client.New(cfg.APIUrl, cfg.APIKey)
		reporter := proxy.NewReporter()

		// Check each package
		for _, pkg := range packages {
			var result *client.CheckResult

			// Try fallback feed first
			if fallbackFeed != nil {
				if fbResult, found := fallbackFeed.Check(pkg.Ecosystem, pkg.Name, pkg.Version); found {
					result = fbResult
				}
			}

			// Fall back to API
			if result == nil {
				apiResult, apiErr := fwClient.Check(pkg.Ecosystem, pkg.Name, pkg.Version)
				if apiErr != nil {
					log.Printf("Warning: API error for %s/%s@%s: %v", pkg.Ecosystem, pkg.Name, pkg.Version, apiErr)
					// Record as allowed on error (fail-open)
					result = &client.CheckResult{
						Allowed: true,
						Verdict: "unknown",
						Reason:  fmt.Sprintf("API error: %v", apiErr),
						Action:  "allow",
					}
				} else {
					result = apiResult
				}
			}

			// Apply strict mode
			if cfg.StrictMode && result.Action == "warn" {
				result = &client.CheckResult{
					Allowed:    false,
					Verdict:    "malicious",
					Reason:     fmt.Sprintf("strict mode: %s", result.Reason),
					Action:     "block",
					Score:      result.Score,
					Confidence: result.Confidence,
				}
			}

			reporter.Record(&pkg, result)

			// Print inline status
			status := "ALLOW"
			if result.Action == "block" {
				status = "BLOCK"
			} else if result.Action == "warn" {
				status = "WARN "
			}
			fmt.Printf("  [%s] %s/%s@%s — %s\n", status, pkg.Ecosystem, pkg.Name, pkg.Version, result.Reason)
		}

		// Print summary
		summary := reporter.Summary()
		fmt.Printf("\nScan Summary: %d total, %d blocked, %d warned, %d allowed\n",
			summary.TotalPackages, summary.Blocked, summary.Warned, summary.Allowed)

		// Write report if configured
		if cfg.ReportPath != "" {
			if writeErr := reporter.Write(cfg.ReportPath); writeErr != nil {
				log.Printf("Warning: failed to write report: %v", writeErr)
			} else {
				fmt.Printf("Report written to %s\n", cfg.ReportPath)
			}
		}

		// Exit code
		if reporter.HasBlocked() {
			fmt.Fprintln(os.Stderr, "Blocked packages detected, exiting with code 1")
			os.Exit(1)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().String("lockfile", "", "Path to lockfile (package-lock.json, requirements.txt, Cargo.lock)")
	_ = scanCmd.MarkFlagRequired("lockfile")
}

// parseLockfile detects the lockfile format and parses packages from it.
func parseLockfile(path string) ([]registry.PackageRef, error) {
	base := strings.ToLower(path)
	switch {
	case strings.HasSuffix(base, "package-lock.json"):
		return parseNpmLockfile(path)
	case strings.HasSuffix(base, "requirements.txt"):
		return parseRequirementsTxt(path)
	case strings.HasSuffix(base, "cargo.lock"):
		return parseCargoLock(path)
	default:
		return nil, fmt.Errorf("unsupported lockfile format: %s (supported: package-lock.json, requirements.txt, Cargo.lock)", path)
	}
}

// parseNpmLockfile parses a package-lock.json (v2/v3 format).
func parseNpmLockfile(path string) ([]registry.PackageRef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lockfile struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}

	var packages []registry.PackageRef

	// v2/v3 format uses "packages"
	for key, pkg := range lockfile.Packages {
		if key == "" {
			continue // skip root package
		}
		// key is like "node_modules/express" or "node_modules/@babel/core"
		name := strings.TrimPrefix(key, "node_modules/")
		// Handle nested: node_modules/foo/node_modules/bar
		if idx := strings.LastIndex(name, "node_modules/"); idx >= 0 {
			name = name[idx+len("node_modules/"):]
		}
		if name != "" && pkg.Version != "" {
			packages = append(packages, registry.PackageRef{
				Ecosystem: "npm",
				Name:      name,
				Version:   pkg.Version,
			})
		}
	}

	// v1 format uses "dependencies"
	if len(packages) == 0 {
		for name, dep := range lockfile.Dependencies {
			if dep.Version != "" {
				packages = append(packages, registry.PackageRef{
					Ecosystem: "npm",
					Name:      name,
					Version:   dep.Version,
				})
			}
		}
	}

	return packages, nil
}

// parseRequirementsTxt parses a pip requirements.txt file.
func parseRequirementsTxt(path string) ([]registry.PackageRef, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Match lines like: package==1.0.0 or package>=1.0.0
	re := regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)\s*[=!><~]+\s*([a-zA-Z0-9_\-\.]+)`)

	var packages []registry.PackageRef
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 3 {
			packages = append(packages, registry.PackageRef{
				Ecosystem: "pypi",
				Name:      strings.ToLower(matches[1]),
				Version:   matches[2],
			})
		}
	}

	return packages, scanner.Err()
}

// parseCargoLock parses a Cargo.lock file.
func parseCargoLock(path string) ([]registry.PackageRef, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var packages []registry.PackageRef
	var currentName, currentVersion string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			// Save previous package
			if currentName != "" && currentVersion != "" {
				packages = append(packages, registry.PackageRef{
					Ecosystem: "crates",
					Name:      currentName,
					Version:   currentVersion,
				})
			}
			currentName = ""
			currentVersion = ""
			continue
		}

		if strings.HasPrefix(line, "name = ") {
			currentName = strings.Trim(strings.TrimPrefix(line, "name = "), "\"")
		} else if strings.HasPrefix(line, "version = ") {
			currentVersion = strings.Trim(strings.TrimPrefix(line, "version = "), "\"")
		}
	}

	// Don't forget last package
	if currentName != "" && currentVersion != "" {
		packages = append(packages, registry.PackageRef{
			Ecosystem: "crates",
			Name:      currentName,
			Version:   currentVersion,
		})
	}

	return packages, scanner.Err()
}

// Package proxy — reporter.go provides JSON scan report generation.
package proxy

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/nicokoenig/phoenix-firewall/internal/client"
	"github.com/nicokoenig/phoenix-firewall/internal/registry"
)

// PackageResult holds the outcome of a single package check for reporting.
type PackageResult struct {
	Ecosystem  string  `json:"ecosystem"`
	Name       string  `json:"name"`
	Version    string  `json:"version"`
	Action     string  `json:"action"`
	Verdict    string  `json:"verdict"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
}

// ScanReport is the top-level JSON report structure.
type ScanReport struct {
	Timestamp     string          `json:"timestamp"`
	TotalPackages int             `json:"total_packages"`
	Blocked       int             `json:"blocked"`
	Warned        int             `json:"warned"`
	Allowed       int             `json:"allowed"`
	Results       []PackageResult `json:"results"`
}

// Reporter collects package check results and writes a JSON report.
type Reporter struct {
	mu      sync.Mutex
	results []PackageResult
}

// NewReporter creates a new Reporter.
func NewReporter() *Reporter {
	return &Reporter{
		results: make([]PackageResult, 0),
	}
}

// Record adds a package check result to the report.
func (r *Reporter) Record(pkg *registry.PackageRef, result *client.CheckResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.results = append(r.results, PackageResult{
		Ecosystem:  pkg.Ecosystem,
		Name:       pkg.Name,
		Version:    pkg.Version,
		Action:     result.Action,
		Verdict:    result.Verdict,
		Reason:     result.Reason,
		Confidence: result.Confidence,
	})
}

// Summary returns the current scan report.
func (r *Reporter) Summary() *ScanReport {
	r.mu.Lock()
	defer r.mu.Unlock()

	report := &ScanReport{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		TotalPackages: len(r.results),
		Results:       make([]PackageResult, len(r.results)),
	}
	copy(report.Results, r.results)

	for _, res := range r.results {
		switch res.Action {
		case "block":
			report.Blocked++
		case "warn":
			report.Warned++
		default:
			report.Allowed++
		}
	}

	return report
}

// Write marshals the current report to JSON and writes it to the given file path.
func (r *Reporter) Write(path string) error {
	report := r.Summary()
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// HasBlocked returns true if any package was blocked.
func (r *Reporter) HasBlocked() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, res := range r.results {
		if res.Action == "block" {
			return true
		}
	}
	return false
}

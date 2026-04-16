package registry

import (
	"net/url"
	"regexp"
)

// cargoPattern matches crates.io download URLs.
// Example: https://crates.io/api/v1/crates/serde/1.0.193/download
var cargoPattern = regexp.MustCompile(
	`^https?://crates\.io/api/v1/crates/([A-Za-z0-9_-]+)/([^/]+)/download$`,
)

// Also match static.crates.io which is the CDN for actual downloads.
// Format: static.crates.io/crates/{name}/{name}-{version}.crate
var cargoStaticPattern = regexp.MustCompile(
	`^https?://static\.crates\.io/crates/([A-Za-z0-9_-]+)/[A-Za-z0-9_-]+-([^/]+)\.crate$`,
)

// CargoMatcher identifies Cargo (crates.io) package downloads.
type CargoMatcher struct{}

// Match checks if the URL is a crates.io download and extracts package info.
func (m *CargoMatcher) Match(rawURL string) (*PackageRef, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil
	}

	if u.Host != "crates.io" && u.Host != "static.crates.io" {
		return nil, nil
	}

	// Try main pattern first
	matches := cargoPattern.FindStringSubmatch(rawURL)
	if matches == nil {
		matches = cargoStaticPattern.FindStringSubmatch(rawURL)
	}
	if matches == nil {
		return nil, nil
	}

	return &PackageRef{
		Ecosystem: "crates",
		Name:      matches[1],
		Version:   matches[2],
	}, nil
}

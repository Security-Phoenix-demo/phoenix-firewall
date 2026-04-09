// Package proxy — fallback.go provides offline fallback feed support.
package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/nicokoenig/phoenix-firewall/internal/client"
)

// FallbackEntry represents a single entry in the fallback feed JSON file.
type FallbackEntry struct {
	PackageName string `json:"package_name"`
	Version     string `json:"version"`
	Ecosystem   string `json:"ecosystem"`
	Action      string `json:"action"`
}

// FallbackFeed provides offline package checking against a local JSON feed.
type FallbackFeed struct {
	entries map[string]string // "ecosystem:name:version" → action
}

// LoadFallbackFeed reads a JSON file containing an array of FallbackEntry and
// builds a lookup map. Expected format:
//
//	[{"package_name": "evil-pkg", "version": "1.0.0", "ecosystem": "npm", "action": "block"}]
func LoadFallbackFeed(path string) (*FallbackFeed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fallback feed: %w", err)
	}

	var entries []FallbackEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse fallback feed: %w", err)
	}

	feed := &FallbackFeed{
		entries: make(map[string]string, len(entries)),
	}
	for _, e := range entries {
		key := feedKey(e.Ecosystem, e.PackageName, e.Version)
		feed.entries[key] = e.Action
	}

	return feed, nil
}

// Check looks up a package in the fallback feed. Returns a CheckResult and true
// if the package is found, or nil and false if not found (treat as allowed).
func (f *FallbackFeed) Check(ecosystem, name, version string) (*client.CheckResult, bool) {
	// Try exact match first
	key := feedKey(ecosystem, name, version)
	action, ok := f.entries[key]
	if !ok {
		// Try wildcard version match (version = "*")
		wildcardKey := feedKey(ecosystem, name, "*")
		action, ok = f.entries[wildcardKey]
		if !ok {
			return nil, false
		}
	}

	allowed := action != "block"
	verdict := "safe"
	if action == "block" {
		verdict = "malicious"
	} else if action == "warn" {
		verdict = "suspicious"
	}

	return &client.CheckResult{
		Allowed:    allowed,
		Verdict:    verdict,
		Reason:     fmt.Sprintf("fallback feed: action=%s", action),
		Action:     action,
		Confidence: 1.0,
	}, true
}

// Len returns the number of entries in the fallback feed.
func (f *FallbackFeed) Len() int {
	return len(f.entries)
}

// feedKey builds a canonical lookup key.
func feedKey(ecosystem, name, version string) string {
	return strings.ToLower(fmt.Sprintf("%s:%s:%s", ecosystem, name, version))
}

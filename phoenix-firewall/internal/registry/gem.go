package registry

import (
	"net/url"
	"regexp"
)

// gemPattern matches RubyGems download URLs.
// Examples:
//
//	https://rubygems.org/downloads/rails-7.1.2.gem
//	https://index.rubygems.org/gems/rails-7.1.2.gem
var gemPattern = regexp.MustCompile(
	`^https?://rubygems\.org/downloads/(.+)-([0-9][^/]*)\.gem$`,
)

var gemIndexPattern = regexp.MustCompile(
	`^https?://index\.rubygems\.org/gems/(.+)-([0-9][^/]*)\.gem$`,
)

// GemMatcher identifies RubyGems package downloads.
type GemMatcher struct{}

// Match checks if the URL is a RubyGems download and extracts package info.
func (m *GemMatcher) Match(rawURL string) (*PackageRef, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil
	}

	if u.Host != "rubygems.org" && u.Host != "index.rubygems.org" {
		return nil, nil
	}

	matches := gemPattern.FindStringSubmatch(rawURL)
	if matches == nil {
		matches = gemIndexPattern.FindStringSubmatch(rawURL)
	}
	if matches == nil {
		return nil, nil
	}

	return &PackageRef{
		Ecosystem: "rubygems",
		Name:      matches[1],
		Version:   matches[2],
	}, nil
}

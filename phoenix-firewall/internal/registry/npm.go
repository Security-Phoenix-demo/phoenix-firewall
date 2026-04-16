package registry

import (
	"net/url"
	"regexp"
	"strings"
)

// npmTarballPattern matches npm registry tarball URLs.
// Examples:
//
//	https://registry.npmjs.org/express/-/express-4.18.2.tgz
//	https://registry.npmjs.org/@babel/core/-/core-7.23.0.tgz
var npmTarballPattern = regexp.MustCompile(
	`^https?://registry\.npmjs\.org/(.+)/-/[^/]+-(\d+\.\d+\.\d+[^/]*)\.tgz$`,
)

// NpmMatcher identifies npm registry package downloads.
type NpmMatcher struct{}

// Match checks if the URL is an npm registry tarball download and extracts package info.
func (m *NpmMatcher) Match(rawURL string) (*PackageRef, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil
	}

	if u.Host != "registry.npmjs.org" {
		return nil, nil
	}

	matches := npmTarballPattern.FindStringSubmatch(rawURL)
	if matches == nil {
		return nil, nil
	}

	name := matches[1]
	version := matches[2]

	// Decode scoped package names (e.g. %40scope/name -> @scope/name)
	name = strings.ReplaceAll(name, "%40", "@")

	return &PackageRef{
		Ecosystem: "npm",
		Name:      name,
		Version:   version,
	}, nil
}

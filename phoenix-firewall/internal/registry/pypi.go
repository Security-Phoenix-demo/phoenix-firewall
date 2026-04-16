package registry

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

// pypiFilePattern matches PyPI file download URLs.
// Examples:
//
//	https://files.pythonhosted.org/packages/ab/cd/ef/requests-2.31.0.tar.gz
//	https://files.pythonhosted.org/packages/ab/cd/ef/requests-2.31.0-py3-none-any.whl
var pypiFilePattern = regexp.MustCompile(
	`^https?://files\.pythonhosted\.org/packages/`,
)

// pypiNameVersionPattern extracts name and version from a PyPI sdist filename.
var pypiNameVersionPattern = regexp.MustCompile(
	`^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)-(\d+\.\d+[A-Za-z0-9._-]*)$`,
)

// PypiMatcher identifies PyPI file downloads.
type PypiMatcher struct{}

// Match checks if the URL is a PyPI file download and extracts package info.
func (m *PypiMatcher) Match(rawURL string) (*PackageRef, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil
	}

	if u.Host != "files.pythonhosted.org" {
		return nil, nil
	}

	if !pypiFilePattern.MatchString(rawURL) {
		return nil, nil
	}

	filename := path.Base(u.Path)

	var name, version string

	if strings.HasSuffix(filename, ".whl") {
		// Wheel format: {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl
		cleanName := strings.TrimSuffix(filename, ".whl")
		parts := strings.SplitN(cleanName, "-", 3)
		if len(parts) < 2 {
			return nil, nil
		}
		name = parts[0]
		version = parts[1]
	} else {
		// sdist: {name}-{version}.tar.gz or .zip
		cleanName := filename
		if strings.HasSuffix(cleanName, ".tar.gz") {
			cleanName = strings.TrimSuffix(cleanName, ".tar.gz")
		} else if strings.HasSuffix(cleanName, ".zip") {
			cleanName = strings.TrimSuffix(cleanName, ".zip")
		} else {
			return nil, nil
		}
		matches := pypiNameVersionPattern.FindStringSubmatch(cleanName)
		if matches == nil {
			return nil, nil
		}
		name = matches[1]
		version = matches[3]
	}

	return &PackageRef{
		Ecosystem: "pypi",
		Name:      normalizePypiName(name),
		Version:   version,
	}, nil
}

// normalizePypiName normalizes a PyPI package name: lowercase, replace [-_.] with -.
func normalizePypiName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}

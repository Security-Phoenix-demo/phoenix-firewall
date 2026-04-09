package registry

import (
	"net/url"
	"regexp"
	"strings"
)

// mavenPattern matches Maven Central repository download URLs.
// Examples:
//
//	https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar
//	https://repo.maven.apache.org/maven2/com/google/guava/guava/32.1.3-jre/guava-32.1.3-jre.jar
//
// The path structure is: /maven2/{group-as-path}/{artifact}/{version}/{artifact}-{version}.{ext}
var mavenPattern = regexp.MustCompile(
	`^https?://(?:repo1\.maven\.org|repo\.maven\.apache\.org)/maven2/(.+)/([^/]+)/([^/]+)/[^/]+-[^/]+\.[a-z]+$`,
)

// MavenMatcher identifies Maven Central package downloads.
type MavenMatcher struct{}

// Match checks if the URL is a Maven Central download and extracts package info.
func (m *MavenMatcher) Match(rawURL string) (*PackageRef, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil
	}

	if u.Host != "repo1.maven.org" && u.Host != "repo.maven.apache.org" {
		return nil, nil
	}

	matches := mavenPattern.FindStringSubmatch(rawURL)
	if matches == nil {
		return nil, nil
	}

	groupPath := matches[1]  // e.g. "org/apache/commons"
	artifact := matches[2]   // e.g. "commons-lang3"
	version := matches[3]    // e.g. "3.14.0"

	// Convert path separators to dots for the group ID
	groupID := strings.ReplaceAll(groupPath, "/", ".")

	// Maven coordinate: groupId:artifactId
	name := groupID + ":" + artifact

	return &PackageRef{
		Ecosystem: "maven",
		Name:      name,
		Version:   version,
	}, nil
}

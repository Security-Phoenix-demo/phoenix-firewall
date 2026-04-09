// Package registry provides URL pattern matching for package manager registries.
// It identifies which ecosystem a request targets and extracts package coordinates.
package registry

// PackageRef represents a resolved package reference extracted from a registry URL.
type PackageRef struct {
	// Ecosystem is the package manager name (e.g. "npm", "pypi", "crates", "rubygems", "maven").
	Ecosystem string
	// Name is the package name.
	Name string
	// Version is the requested package version (may be empty).
	Version string
}

// RegistryMatcher identifies package references from intercepted HTTP request URLs.
type RegistryMatcher interface {
	// Match inspects a URL and returns a PackageRef if it matches a known registry pattern.
	// Returns nil and no error if the URL does not match any known registry.
	Match(url string) (*PackageRef, error)
}

package registry

// CompositeMatchers tries multiple RegistryMatcher implementations in order.
type CompositeMatchers struct {
	matchers []RegistryMatcher
}

// NewCompositeMatchers creates a CompositeMatchers with all supported registry matchers.
func NewCompositeMatchers() *CompositeMatchers {
	return &CompositeMatchers{
		matchers: []RegistryMatcher{
			&NpmMatcher{},
			&PypiMatcher{},
			&CargoMatcher{},
			&GemMatcher{},
			&MavenMatcher{},
		},
	}
}

// Match tries each registered matcher in order and returns the first match.
func (c *CompositeMatchers) Match(url string) (*PackageRef, error) {
	for _, m := range c.matchers {
		ref, err := m.Match(url)
		if err != nil {
			return nil, err
		}
		if ref != nil {
			return ref, nil
		}
	}
	return nil, nil
}

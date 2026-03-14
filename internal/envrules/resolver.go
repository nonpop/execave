package envrules

import "strings"

// Resolver filters host environment variables against a rule set.
type Resolver struct {
	allowed map[string]struct{}
}

// NewResolver creates a [Resolver] with the given rules.
func NewResolver(rules []Rule) *Resolver {
	allowed := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		allowed[rule.Name] = struct{}{}
	}
	return &Resolver{allowed: allowed}
}

// Resolve filters environ (e.g. from os.Environ()) to the subset permitted by pass rules.
// Each entry in environ must be in "KEY=VALUE" form. Variables with a matching pass rule
// are included; all others are excluded. Variables listed in pass rules but absent from
// environ are silently skipped.
func (r *Resolver) Resolve(environ []string) []string {
	result := make([]string, 0)
	for _, entry := range environ {
		name, _, _ := strings.Cut(entry, "=")
		if _, ok := r.allowed[name]; ok {
			result = append(result, entry)
		}
	}
	return result
}

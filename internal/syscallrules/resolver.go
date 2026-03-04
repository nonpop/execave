package syscallrules

import (
	"sort"
)

// AccessResult represents the outcome of resolving a syscall against rules.
type AccessResult struct {
	// Known is true if this syscall appears in the resolver's rules (allow or blocked).
	Known bool
	// Allowed is true if the syscall is permitted by a matching rule. Meaningful only when Known is true.
	Allowed bool
	// Rule is the RawRule of the matching rule, or nil if blocked or unknown.
	Rule *string
}

// Resolver evaluates syscalls against a set of syscall access rules.
type Resolver struct {
	rules   []Rule
	blocked map[string]bool
}

// NewResolver creates a new Resolver from the given syscall rules.
// ruleableNames is the set of syscall names that can be targeted by rules.
// Blocked syscalls are all ruleable syscalls not covered by an allow rule.
func NewResolver(rules []Rule, ruleableNames []string) *Resolver {
	allowedNames := make(map[string]bool, len(rules))
	for _, rule := range rules {
		allowedNames[rule.Name] = true
	}
	blocked := make(map[string]bool, len(ruleableNames))
	for _, name := range ruleableNames {
		if !allowedNames[name] {
			blocked[name] = true
		}
	}
	return &Resolver{rules: rules, blocked: blocked}
}

// CheckAccess evaluates a syscall name against the rules and returns the result.
// An allow rule match returns {Known: true, Allowed: true, Rule: &rawRule}.
// A blocked name returns {Known: true, Allowed: false, Rule: nil}.
// No match returns {Known: false, Allowed: false, Rule: nil}.
func (r *Resolver) CheckAccess(name string) AccessResult {
	for _, rule := range r.rules {
		if rule.Name == name && rule.action == actionAllow {
			return AccessResult{Known: true, Allowed: true, Rule: &rule.RawRule}
		}
	}
	if r.blocked[name] {
		return AccessResult{Known: true, Allowed: false, Rule: nil}
	}
	return AccessResult{Known: false, Allowed: false, Rule: nil}
}

// Names returns a sorted list of all monitored syscall names (allow + blocked).
// Used to build the strace trace expression.
func (r *Resolver) Names() []string {
	seen := make(map[string]bool)
	for _, rule := range r.rules {
		seen[rule.Name] = true
	}
	for name := range r.blocked {
		seen[name] = true
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// AllowedNames returns a sorted list of syscall names with allow rules.
// Used to build the seccomp filter allowed-syscall set.
func (r *Resolver) AllowedNames() []string {
	names := make([]string, 0, len(r.rules))
	for _, rule := range r.rules {
		if rule.action == actionAllow {
			names = append(names, rule.Name)
		}
	}
	sort.Strings(names)
	return names
}

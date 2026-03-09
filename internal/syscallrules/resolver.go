package syscallrules

import (
	"sort"
)

// AccessResult represents the outcome of [Resolver.CheckAccess].
type AccessResult struct {
	Known   bool    // True if the syscall is in the ruleable set.
	Allowed bool    // True if permitted by an allow rule. Meaningful only when Known is true.
	Rule    *string // Matching rule, or nil if blocked or unknown.
}

// Resolver evaluates syscall names against the rule set and blocked list.
type Resolver struct {
	rules   []Rule
	blocked map[string]bool
}

// NewResolver creates a [Resolver]. Syscalls in ruleableNames without an
// allow rule are implicitly blocked.
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

// CheckAccess evaluates a syscall name. Returns Known=true for names in the
// ruleable set, with Allowed reflecting whether an allow rule exists.
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

// Names returns all monitored syscall names (allowed + blocked), sorted.
// Used to build the strace -e trace= expression.
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

// AllowedNames returns syscall names with allow rules, sorted.
// Used to build the seccomp filter allow set.
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

// Package syscallrules implements syscall rule parsing, validation, and resolution.
//
// This package handles syscall-specific rule syntax (action:name), cross-rule
// validation (duplicate identity, non-ruleable names), and rule resolution
// (linear scan, default-deny).
package syscallrules

import (
	"fmt"
	"strings"

	"github.com/nonpop/execave/internal/seccomp"
)

// action represents the action for a syscall rule.
type action int

const (
	// actionUnknown is the zero value; it must not appear in validated rules.
	actionUnknown action = iota
	// actionAllow permits the named syscall.
	actionAllow
)

// Rule represents a parsed syscall access rule.
type Rule struct {
	action     action
	Name       string // Syscall kernel name.
	RawRule    string // Original rule string (e.g. "allow:ptrace").
	SourcePath string // Config file path that produced this rule.
}

// Canonical returns the canonical version of the rule, suitable for deduplication, comparison, and rendering.
func (r Rule) Canonical() string {
	return fmt.Sprintf("allow:%s", r.Name)
}

// ParseRule parses a syscall rule body in the format "allow:name".
// configPath is set as the SourcePath on the returned rule.
func ParseRule(rawRule, configPath string) (Rule, error) {
	actionStr, name, ok := strings.Cut(rawRule, ":")
	if !ok || name == "" {
		return Rule{}, fmt.Errorf("malformed syscall rule %q (expected format: action:name)", rawRule)
	}

	parsedAction, err := parseAction(actionStr)
	if err != nil {
		return Rule{}, fmt.Errorf("malformed syscall rule %q: %w", rawRule, err)
	}

	return Rule{
		action:     parsedAction,
		Name:       name,
		RawRule:    rawRule,
		SourcePath: configPath,
	}, nil
}

func parseAction(s string) (action, error) {
	switch s {
	case "allow":
		return actionAllow, nil
	default:
		return actionUnknown, fmt.Errorf("unknown syscall action %q (must be 'allow')", s)
	}
}

// ValidateRules checks that all rule names are valid ruleable syscall names and
// that there are no duplicate identities within the rule set.
func ValidateRules(rules []Rule) error {
	ruleableNames := seccomp.RuleableSyscallNames()
	ruleable := make(map[string]bool, len(ruleableNames))
	for _, name := range ruleableNames {
		ruleable[name] = true
	}

	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if !ruleable[rule.Name] {
			return fmt.Errorf("invalid syscall:allow target %q", rule.Name)
		}
		identity := rule.Canonical()
		if seen[identity] {
			return fmt.Errorf("duplicate syscall allow rule: %q", rule.Name)
		}
		seen[identity] = true
	}

	return nil
}

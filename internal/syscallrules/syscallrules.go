// Package syscallrules implements syscall access rule parsing, validation, and
// resolution for the execave sandbox.
//
// Rules have the form "allow:name". All names in the ruleable set
// (from [seccomp.RuleableSyscallNames]) that lack an allow rule are
// implicitly blocked.
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
	Name       string // Kernel syscall name.
	RawRule    string // Original rule string for display.
	SourcePath string // Config file that produced this rule.
}

// Canonical returns the normalized "allow:name" form for deduplication and display.
func (r Rule) Canonical() string {
	return "allow:" + r.Name
}

// ParseRule parses "allow:name" into a [Rule].
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

// ValidateRules checks that all names are in the ruleable set and that there
// are no duplicates.
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

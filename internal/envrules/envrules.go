// Package envrules implements environment variable filtering rule parsing,
// validation, and resolution for the execave sandbox.
//
// Rules have the form "pass:NAME". [Resolver] applies default-deny filtering:
// only variables with a matching pass rule are forwarded into the sandbox.
package envrules

import (
	"fmt"
	"strings"
)

// Rule represents a parsed environment variable filtering rule.
type Rule struct {
	Name       string // Environment variable name.
	RawRule    string // Original rule string for display.
	SourcePath string // Config file that produced this rule.
}

// Canonical returns the normalized "pass:NAME" form for deduplication and display.
func (r Rule) Canonical() string {
	return "pass:" + r.Name
}

// ParseRule parses "pass:NAME" into a [Rule].
// configPath is the source file for provenance tracking.
func ParseRule(rawRule, configPath string) (Rule, error) {
	action, name, ok := strings.Cut(rawRule, ":")
	if !ok {
		return Rule{}, fmt.Errorf("malformed env rule %q (expected format: pass:NAME)", rawRule)
	}

	if action != "pass" {
		return Rule{}, fmt.Errorf("invalid env rule action %q in %q (must be 'pass')", action, rawRule)
	}

	if name == "" {
		return Rule{}, fmt.Errorf("invalid env rule %q: variable name must not be empty", rawRule)
	}

	return Rule{
		Name:       name,
		RawRule:    rawRule,
		SourcePath: configPath,
	}, nil
}

// ValidateRules rejects configurations with duplicate variable names.
func ValidateRules(rules []Rule) error {
	seen := make(map[string]Rule)
	for _, rule := range rules {
		key := rule.Canonical()
		if existing, ok := seen[key]; ok {
			if existing.SourcePath != "" && existing.SourcePath == rule.SourcePath {
				return fmt.Errorf("duplicate env rule %q in %s: %q and %q",
					rule.Name, existing.SourcePath, existing.RawRule, rule.RawRule)
			}
			return fmt.Errorf("duplicate env rule %q: %q (%q) and %q (%q)",
				rule.Name, existing.RawRule, existing.SourcePath, rule.RawRule, rule.SourcePath)
		}
		seen[key] = rule
	}
	return nil
}

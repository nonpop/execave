package fsrules

import (
	"fmt"
	"strings"
)

// LogRule represents a parsed filesystem log visibility rule.
type LogRule struct {
	// Visible is true for log rules (show entry) and false for nolog rules (hide entry).
	Visible bool
	// Path is the normalized absolute path prefix this rule applies to.
	Path string
	// RawRule is the original rule body, for error messages.
	// Initialized to ruleBody by ParseLogRule; the config layer overwrites it
	// with the full rule string including the resource prefix.
	RawRule string
}

// ParseLogRule parses a log rule body in the format "visibility:path".
// The resource prefix (e.g., "fs:") must be stripped by the caller before passing.
// Relative paths are resolved relative to configDir.
func ParseLogRule(ruleBody, configDir string) (LogRule, error) {
	const expectedParts = 2
	parts := strings.SplitN(ruleBody, ":", expectedParts)
	if len(parts) != expectedParts {
		return LogRule{}, fmt.Errorf("malformed rule %q (expected format: visibility:path)", ruleBody)
	}

	visStr := parts[0]
	path := parts[1]

	var visible bool
	switch visStr {
	case "log":
		visible = true
	case "nolog":
		visible = false
	default:
		return LogRule{}, fmt.Errorf("invalid visibility type %q (must be 'log' or 'nolog')", visStr)
	}

	normalizedPath, err := normalizePath(path, configDir)
	if err != nil {
		return LogRule{}, err
	}

	return LogRule{
		Visible: visible,
		Path:    normalizedPath,
		RawRule: ruleBody,
	}, nil
}

// ValidateLogRules rejects log rule sets where multiple rules specify the same normalized path.
func ValidateLogRules(rules []LogRule) error {
	seen := make(map[string]LogRule)
	for _, rule := range rules {
		if existing, ok := seen[rule.Path]; ok {
			return fmt.Errorf("duplicate path %q: rules %q and %q",
				rule.Path, existing.RawRule, rule.RawRule)
		}
		seen[rule.Path] = rule
	}
	return nil
}

// LogResolver determines whether an entry for a given path should be displayed.
// It uses longest-prefix-match resolution over the configured log rules.
type LogResolver struct {
	rules []LogRule
}

// NewLogResolver creates a new LogResolver from the given log rules.
func NewLogResolver(rules []LogRule) *LogResolver {
	return &LogResolver{rules: rules}
}

// Visible returns true if entries for the given path should be displayed.
// The path is matched against log rules using longest-prefix-match.
// If no rule matches, the default is visible (true).
func (r *LogResolver) Visible(path string) bool {
	var bestRule *LogRule
	longestMatch := -1

	for i := range r.rules {
		rule := &r.rules[i]
		if matchesPath(rule.Path, path) {
			matchLen := len(rule.Path)
			if matchLen > longestMatch {
				longestMatch = matchLen
				bestRule = rule
			}
		}
	}

	if bestRule == nil {
		return true // default: visible
	}
	return bestRule.Visible
}

// Package fsrules implements filesystem rule parsing, validation, and resolution.
//
// This package handles FS-specific rule syntax (permission:path), path
// normalization, cross-rule validation (duplicates, managed paths, config
// protection), and rule resolution (longest prefix matching, permission checks).
package fsrules

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/nonpop/execave/internal/pathutil"
)

// Rule represents a parsed filesystem rule.
type Rule struct {
	Permission Permission
	Path       string
	RawRule    string // Original rule for error messages and logging
	SourcePath string // Config file path that produced this rule
}

// Permission represents the access level for a filesystem rule.
// Higher values are more permissive: None < ReadOnly < ReadWrite.
// PermissionUnknown is the zero value and must not appear in validated rules.
type Permission int

const (
	// PermissionUnknown is the zero value; it must not appear in validated rules.
	PermissionUnknown Permission = iota
	// PermissionNone denies all access.
	PermissionNone
	// PermissionReadOnly grants read-only access.
	PermissionReadOnly
	// PermissionReadWrite grants read and write access.
	PermissionReadWrite
)

// Canonical returns the canonical version of the rule, suitable for deduplication, comparison, and rendering.
func (r Rule) Canonical() string {
	var perm string
	switch r.Permission {
	case PermissionReadWrite:
		perm = "rw"
	case PermissionReadOnly:
		perm = "ro"
	case PermissionNone:
		perm = "none"
	default:
		perm = "unknown"
	}
	return fmt.Sprintf("%s:%s", perm, r.Path)
}

// ParseRule parses a rule body in the format "permission:path".
// Relative paths are resolved relative to configDir.
func ParseRule(ruleBody, configDir, configPath string) (Rule, error) {
	parts := strings.SplitN(ruleBody, ":", 2)
	if len(parts) != 2 {
		return Rule{}, fmt.Errorf("malformed rule %q (expected format: permission:path)", ruleBody)
	}

	permStr := parts[0]
	path := parts[1]

	var perm Permission
	switch permStr {
	case "rw":
		perm = PermissionReadWrite
	case "ro":
		perm = PermissionReadOnly
	case "none":
		perm = PermissionNone
	default:
		return Rule{}, fmt.Errorf("invalid permission type %q (must be 'ro', 'rw', or 'none')", permStr)
	}

	normalizedPath, err := pathutil.ExpandPath(path, configDir)
	if err != nil {
		return Rule{}, fmt.Errorf("expand path: %w", err)
	}

	return Rule{
		Permission: perm,
		Path:       normalizedPath,
		RawRule:    ruleBody,
		SourcePath: configPath,
	}, nil
}

// ValidateRules performs cross-rule validation: checks for duplicate paths,
// ensures config files are not writable, and ensures no rules target managed paths.
func ValidateRules(rules []Rule, configPaths []string, managedPaths []string) error {
	if err := validateNoDuplicatePaths(rules); err != nil {
		return err
	}

	if err := validateConfigNotWritable(rules, configPaths); err != nil {
		return err
	}

	if err := validateNoManagedPaths(rules, managedPaths); err != nil {
		return err
	}

	return nil
}

// validateNoDuplicatePaths rejects configs with duplicate paths in rules.
func validateNoDuplicatePaths(rules []Rule) error {
	seen := make(map[string]Rule)
	for _, rule := range rules {
		if existing, ok := seen[rule.Path]; ok {
			if existing.SourcePath != "" && existing.SourcePath == rule.SourcePath {
				return fmt.Errorf("duplicate path %q in %s: %q and %q",
					rule.Path, existing.SourcePath, existing.RawRule, rule.RawRule)
			}
			return fmt.Errorf("duplicate path %q: %q (%q) and %q (%q)",
				rule.Path, existing.RawRule, existing.SourcePath, rule.RawRule, rule.SourcePath)
		}
		seen[rule.Path] = rule
	}
	return nil
}

// validateConfigNotWritable rejects configs that explicitly list the config file as writable.
func validateConfigNotWritable(rules []Rule, configPaths []string) error {
	for _, cfgPath := range configPaths {
		for _, rule := range rules {
			if rule.Path == cfgPath && rule.Permission == PermissionReadWrite {
				return fmt.Errorf("config file %s must not be writable: rule %q from %s",
					cfgPath, rule.RawRule, rule.SourcePath)
			}
		}
	}
	return nil
}

// validateNoManagedPaths rejects rules targeting paths the sandbox manages automatically.
func validateNoManagedPaths(rules []Rule, managedPaths []string) error {
	for _, rule := range rules {
		for _, managed := range managedPaths {
			if rule.Path == managed || strings.HasPrefix(rule.Path, managed+string(filepath.Separator)) {
				return fmt.Errorf("rule %q from %s targets managed path %q", rule.RawRule, rule.SourcePath, managed)
			}
		}
	}
	return nil
}

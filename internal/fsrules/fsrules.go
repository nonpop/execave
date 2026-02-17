// Package fsrules implements filesystem rule parsing, validation, and resolution.
//
// This package handles FS-specific rule syntax (permission:path), path
// normalization, cross-rule validation (duplicates, managed paths, config
// protection), and rule resolution (longest prefix matching, permission checks).
// The resource prefix (e.g., "fs:") is stripped by the config layer before parsing.
package fsrules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Rule represents a parsed filesystem access rule.
type Rule struct {
	Permission Permission
	Path       string
	RawRule    string // Original rule for error messages and logging
}

// Permission represents the access level. Higher values are stricter.
type Permission int

const (
	// PermissionUnknown represents an uninitialized or invalid state.
	PermissionUnknown Permission = iota
	// PermissionReadWrite grants read and write access.
	PermissionReadWrite
	// PermissionReadOnly grants read-only access.
	PermissionReadOnly
	// PermissionNone denies all access.
	PermissionNone
)

// Parse parses a rule body in the format "permission:path".
// The resource prefix (e.g., "fs:") must be stripped by the caller before passing.
// Relative paths are resolved relative to configDir.
func Parse(ruleBody, configDir string) (Rule, error) {
	const expectedParts = 2
	parts := strings.SplitN(ruleBody, ":", expectedParts)
	if len(parts) != expectedParts {
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

	normalizedPath, err := normalizePath(path, configDir)
	if err != nil {
		return Rule{}, err
	}

	return Rule{
		Permission: perm,
		Path:       normalizedPath,
		RawRule:    ruleBody,
	}, nil
}

// normalizePath expands tilde, resolves relative paths against configDir, and cleans the result.
// A leading "~/" or bare "~" expands to os.UserHomeDir(). "~username" returns an error.
// If os.UserHomeDir() fails, an error is returned.
func normalizePath(path, configDir string) (string, error) {
	switch {
	case strings.HasPrefix(path, "~/"):
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand tilde in path %q: %w", path, err)
		}
		path = homeDir + path[1:] // path[1:] = "/" + rest
	case path == "~":
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand tilde in path %q: %w", path, err)
		}
		path = homeDir
	case len(path) > 1 && path[0] == '~':
		return "", fmt.Errorf("~username paths not supported: %q", path)
	}

	if !filepath.IsAbs(path) {
		path = filepath.Join(configDir, path)
	}
	return filepath.Clean(path), nil
}

// Validate performs cross-rule validation: checks for duplicate paths,
// ensures config file is not writable, and ensures no rules target managed paths.
func Validate(rules []Rule, configPath string, managedPaths []string) error {
	if err := validateNoDuplicates(rules); err != nil {
		return err
	}

	if err := validateConfigNotWritable(rules, configPath); err != nil {
		return err
	}

	if err := validateNoManagedPaths(rules, managedPaths); err != nil {
		return err
	}

	return nil
}

// validateNoDuplicates rejects configs with duplicate paths.
func validateNoDuplicates(rules []Rule) error {
	seen := make(map[string]Rule)
	for _, rule := range rules {
		if existing, ok := seen[rule.Path]; ok {
			return fmt.Errorf("duplicate path %q: rules %q and %q",
				rule.Path, existing.RawRule, rule.RawRule)
		}
		seen[rule.Path] = rule
	}
	return nil
}

// validateConfigNotWritable rejects configs that explicitly list the config file as writable.
func validateConfigNotWritable(rules []Rule, configPath string) error {
	for _, rule := range rules {
		if rule.Path == configPath && rule.Permission == PermissionReadWrite {
			return fmt.Errorf("config file must not be writable: rule %q", rule.RawRule)
		}
	}
	return nil
}

// validateNoManagedPaths rejects rules targeting paths the sandbox manages automatically.
func validateNoManagedPaths(rules []Rule, managedPaths []string) error {
	for _, rule := range rules {
		for _, managed := range managedPaths {
			if rule.Path == managed || strings.HasPrefix(rule.Path, managed+string(filepath.Separator)) {
				return fmt.Errorf("rule %q targets managed path %q", rule.RawRule, managed)
			}
		}
	}
	return nil
}

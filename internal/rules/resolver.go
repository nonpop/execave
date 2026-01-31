// Package rules implements rule matching and access control.
package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nonpop/execave/internal/config"
)

// Operation represents a filesystem access operation.
type Operation string

const (
	// OperationRead represents read operations.
	OperationRead Operation = "read"
	// OperationWrite represents write operations.
	OperationWrite Operation = "write"
)

// Resolver handles rule matching and access decisions.
type Resolver struct {
	rules []config.Rule
}

// AccessResult represents the result of an access check.
type AccessResult struct {
	Allowed bool
	Rule    *config.Rule // Matching rule, or nil if no match
}

// New creates a new Resolver.
func New(cfg *config.Config) *Resolver {
	return &Resolver{
		rules: cfg.Rules,
	}
}

// CheckAccess determines if a path can be accessed with the given operation.
// For symlinks, this checks both the symlink path (must be readable) and the
// target path (must have appropriate permission for the operation).
func (r *Resolver) CheckAccess(path string, operation Operation) AccessResult {
	cleanPath := filepath.Clean(path)

	// Attempt to resolve symlinks
	resolvedPath, err := resolveSymlinks(path)
	isSymlink := err == nil && resolvedPath != cleanPath

	if isSymlink {
		// For symlinks, first check if the symlink itself is readable
		// (needed to read the symlink to resolve it)
		symlinkRule := r.findMatchingRule(cleanPath)
		if symlinkRule == nil {
			// Symlink path not mounted - would not exist in sandbox
			return AccessResult{
				Allowed: false,
				Rule:    nil,
			}
		}

		// Check if symlink is readable (need ro or rw to read the symlink)
		if !r.checkPermission(symlinkRule.Permission, OperationRead) {
			// Can't read symlink - access denied
			return AccessResult{
				Allowed: false,
				Rule:    symlinkRule,
			}
		}

		// Symlink is readable, now check the target with the requested operation
		cleanPath = filepath.Clean(resolvedPath)
	}

	// Check the final path (either non-symlink or resolved target)
	matchedRule := r.findMatchingRule(cleanPath)

	if matchedRule == nil {
		return AccessResult{
			Allowed: false,
			Rule:    nil,
		}
	}

	allowed := r.checkPermission(matchedRule.Permission, operation)

	return AccessResult{
		Allowed: allowed,
		Rule:    matchedRule,
	}
}

// PermissionFor returns the permission that would apply to the given path.
// The path must be absolute and clean.
func (r *Resolver) PermissionFor(path string) config.Permission {
	if !filepath.IsAbs(path) {
		panic("internal error: path must be absolute: " + path)
	}
	if path != filepath.Clean(path) {
		panic("internal error: path must be clean: " + path)
	}

	rule := r.findMatchingRule(path)
	if rule == nil {
		return config.PermissionNone
	}
	return rule.Permission
}

func (r *Resolver) findMatchingRule(path string) *config.Rule {
	var bestMatch *config.Rule
	longestMatch := -1

	for i := range r.rules {
		rule := &r.rules[i]

		// Check if the rule path is a prefix of the target path
		if matchesPath(rule.Path, path) {
			matchLen := len(rule.Path)
			if matchLen > longestMatch {
				longestMatch = matchLen
				bestMatch = rule
			}
		}
	}

	return bestMatch
}

func matchesPath(rulePath, targetPath string) bool {
	if rulePath == targetPath {
		return true
	}

	rulePathWithSep := rulePath
	if !strings.HasSuffix(rulePathWithSep, string(filepath.Separator)) {
		rulePathWithSep += string(filepath.Separator)
	}

	return strings.HasPrefix(targetPath, rulePathWithSep)
}

func (r *Resolver) checkPermission(perm config.Permission, operation Operation) bool {
	switch perm {
	case config.PermissionNone:
		return false
	case config.PermissionReadOnly:
		return operation == OperationRead
	case config.PermissionReadWrite:
		return true
	default:
		// Unknown permission - deny
		return false
	}
}

func resolveSymlinks(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		if os.IsNotExist(err) {
			return path, nil
		}
		return "", fmt.Errorf("evaluate symlinks for %s: %w", path, err)
	}
	return resolved, nil
}

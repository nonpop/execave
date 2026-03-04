package fsrules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	rules        []Rule
	managedPaths []string
}

// SymlinkChain captures each hop in a symlink resolution chain.
type SymlinkChain struct {
	Hops               []SymlinkHop
	ResolvedPath       string // Final target path (clean, absolute); empty if unresolvable or depth limit exceeded
	Unresolvable       bool   // True if chain entered an unresolvable path (e.g., managed tmpfs)
	DepthLimitExceeded bool   // True if chain exceeded MAXSYMLINKS
}

// SymlinkHop represents one symlink in the resolution chain.
type SymlinkHop struct {
	Path    string  // The symlink path (clean, absolute)
	Allowed bool    // Was this hop readable?
	Rule    *string // Raw rule string that matched, or nil
}

// AccessResult represents the result of an access check.
type AccessResult struct {
	Allowed      bool
	Rule         *string       // Raw rule string that matched, or nil if no match
	Symlink      *SymlinkChain // Non-nil if path contained symlinks that were resolved
	Uncertain    bool          // True if result could not be determined (e.g., symlink through managed path)
	PathNotFound bool          // True if the path (or a component) does not exist on the host filesystem
}

// NewResolver creates a new Resolver.
func NewResolver(rules []Rule, managedPaths []string) *Resolver {
	return &Resolver{
		rules:        rules,
		managedPaths: managedPaths,
	}
}

// CheckAccess determines if a path can be accessed with the given operation.
// For symlinks, this resolves them component-by-component, recording each hop.
// Symlinks at rule boundaries are not resolved (bwrap handles them at mount time).
func (r *Resolver) CheckAccess(path string, operation Operation) AccessResult {
	cleanPath := filepath.Clean(path)

	// Walk path component-by-component to resolve symlinks
	resolvedPath, symlinks, pathNotFound, err := r.resolvePathComponents(cleanPath)
	// If resolution failed (depth limit, error accessing path, etc.), deny
	if err != nil {
		return AccessResult{
			Allowed:      false,
			Rule:         nil,
			Symlink:      symlinks,
			Uncertain:    false,
			PathNotFound: false,
		}
	}

	// If chain entered a managed path, we can't determine the true target
	if symlinks != nil && symlinks.Unresolvable {
		return AccessResult{
			Allowed:      false,
			Rule:         nil,
			Symlink:      symlinks,
			Uncertain:    true,
			PathNotFound: false,
		}
	}

	// Check if any hop in the chain was denied
	if symlinks != nil {
		for _, hop := range symlinks.Hops {
			if !hop.Allowed {
				// Chain broke at this hop
				return AccessResult{
					Allowed:      false,
					Rule:         nil,
					Symlink:      symlinks,
					Uncertain:    false,
					PathNotFound: false,
				}
			}
		}
	}

	// All hops were OK (or no symlinks), check the final path
	matchedRule := r.findMatchingRule(resolvedPath)

	if matchedRule == nil {
		return AccessResult{
			Allowed:      false,
			Rule:         nil,
			Symlink:      symlinks,
			Uncertain:    false,
			PathNotFound: pathNotFound,
		}
	}

	allowed := r.checkPermission(matchedRule.Permission, operation)

	return AccessResult{
		Allowed:      allowed,
		Rule:         &matchedRule.RawRule,
		Symlink:      symlinks,
		Uncertain:    false,
		PathNotFound: pathNotFound,
	}
}

// PermissionFor returns the permission that would apply to the given path.
// The path must be absolute and clean.
func (r *Resolver) PermissionFor(path string) Permission {
	if !filepath.IsAbs(path) {
		panic("path must be absolute: " + path)
	}
	if path != filepath.Clean(path) {
		panic("path must be clean: " + path)
	}

	rule := r.findMatchingRule(path)
	if rule == nil {
		return PermissionNone
	}
	return rule.Permission
}

func (r *Resolver) findMatchingRule(path string) *Rule {
	var bestMatch *Rule
	longestMatch := -1

	for _, rule := range r.rules {
		if matchesPath(rule.Path, path) {
			matchLen := len(rule.Path)
			if matchLen > longestMatch {
				longestMatch = matchLen
				bestMatch = &rule
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

func (r *Resolver) checkPermission(perm Permission, operation Operation) bool {
	switch perm {
	case PermissionNone:
		return false
	case PermissionReadOnly:
		return operation == OperationRead
	case PermissionReadWrite:
		return true
	default:
		panic(fmt.Sprintf("invalid permission %d", perm))
	}
}

// resolvePathComponents walks the path component-by-component, resolving symlinks.
// Returns the final resolved path, symlink chain info, and any error.
// Symlinks at rule boundaries are not resolved.
//
//nolint:gocognit,cyclop,funlen // Reads better as one function
func (r *Resolver) resolvePathComponents(path string) (string, *SymlinkChain, bool, error) {
	const maxSymlinks = 40 // Linux kernel's MAXSYMLINKS

	if !filepath.IsAbs(path) {
		return "", nil, false, fmt.Errorf("resolve path components %s: path must be absolute", path)
	}

	var hops []SymlinkHop
	symlinkCount := 0
	current := "/"
	pathNotFound := false

	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	// parts[0] is empty (before leading /), so skip it
	parts = parts[1:]

	// Track remaining components for relative symlink targets
	for i := 0; i < len(parts); i++ {
		// Build next path component
		current = filepath.Join(current, parts[i])

		// If the walk has entered a managed path, host-side resolution is unreliable.
		// This catches the case where a symlink target is an ancestor of a managed path
		// and remaining components lead into it.
		if r.isUnresolvablePath(current) {
			chain := &SymlinkChain{
				Hops:               hops,
				ResolvedPath:       "",
				Unresolvable:       true,
				DepthLimitExceeded: false,
			}
			return "", chain, false, nil
		}

		// Check if this is a rule boundary - if so, don't resolve symlinks
		if r.isRuleBoundary(current) {
			continue
		}

		// Check if current component is a symlink
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				// Path doesn't exist - stop resolving, build remaining path
				// but don't try to resolve any more symlinks
				pathNotFound = true
				current = filepath.Join(current, filepath.Join(parts[i+1:]...))
				break
			}
			// Other error - deny access
			return "", nil, false, fmt.Errorf("stat path component %s: %w", current, err)
		}

		// Not a symlink - continue to next component
		if info.Mode()&os.ModeSymlink == 0 {
			continue
		}

		// This is a symlink - check depth limit before processing
		symlinkCount++
		if symlinkCount >= maxSymlinks {
			// Add a denied hop for the path that exceeded the limit
			hops = append(hops, SymlinkHop{
				Path:    current,
				Allowed: false,
				Rule:    nil,
			})
			chain := &SymlinkChain{
				Hops:               hops,
				ResolvedPath:       "",
				Unresolvable:       false,
				DepthLimitExceeded: true,
			}
			return "", chain, false, fmt.Errorf("symlink depth limit exceeded at %s", current)
		}

		// Read the symlink target
		target, err := os.Readlink(current)
		if err != nil {
			return "", nil, false, fmt.Errorf("read symlink %s: %w", current, err)
		}

		// Check if we can read this symlink
		rule := r.findMatchingRule(current)
		hopAllowed := rule != nil && r.checkPermission(rule.Permission, OperationRead)

		var ruleStr *string
		if rule != nil {
			ruleStr = &rule.RawRule
		}
		hops = append(hops, SymlinkHop{
			Path:    current,
			Allowed: hopAllowed,
			Rule:    ruleStr,
		})

		// If hop not allowed, stop resolution
		if !hopAllowed {
			chain := &SymlinkChain{
				Hops:               hops,
				ResolvedPath:       "",
				Unresolvable:       false,
				DepthLimitExceeded: false,
			}
			return "", chain, false, nil
		}

		// Get remaining components to append after the symlink target
		remaining := parts[i+1:]

		// Compute the resolved target path
		var resolvedTarget string
		if filepath.IsAbs(target) {
			resolvedTarget = filepath.Clean(target)
		} else {
			parent := filepath.Dir(current)
			resolvedTarget = filepath.Clean(filepath.Join(parent, target))
		}

		// Both absolute and relative targets: resolvedTarget is already clean and absolute.
		// Restart walk from root so all components of the target are checked.
		current = "/"
		parts = strings.Split(resolvedTarget, string(filepath.Separator))
		parts = parts[1:]
		parts = append(parts, remaining...)
		i = -1 // Will be incremented to 0 at loop start
	}

	// If we recorded any hops, return the chain
	var chain *SymlinkChain
	if len(hops) > 0 {
		chain = &SymlinkChain{
			Hops:               hops,
			ResolvedPath:       current,
			Unresolvable:       false,
			DepthLimitExceeded: false,
		}
	}

	return current, chain, pathNotFound, nil
}

// isUnresolvablePath returns true if the path is under a managed path where
// host-side symlink resolution is unreliable (e.g., sandbox tmpfs).
func (r *Resolver) isUnresolvablePath(path string) bool {
	for _, managed := range r.managedPaths {
		// TODO: this logic is in many places
		if path == managed || strings.HasPrefix(path, managed+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// isRuleBoundary returns true if the path exactly matches a rule path.
// These symlinks are resolved by bwrap at mount time, not at access time.
func (r *Resolver) isRuleBoundary(path string) bool {
	for i := range r.rules {
		if r.rules[i].Path == path {
			return true
		}
	}
	return false
}

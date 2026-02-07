package rules_test

import (
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/rules"
	"github.com/stretchr/testify/assert"
)

// parseOperation converts a string to a rules.Operation for fuzz testing.
// Unknown strings are converted directly to test that arbitrary values don't cause panics.
func parseOperation(opStr string) rules.Operation {
	switch opStr {
	case "read":
		return rules.OperationRead
	case "write":
		return rules.OperationWrite
	default:
		return rules.Operation(opStr)
	}
}

// assertLongestPrefixWins checks that no rule in cfg has a longer matching prefix than result.Rule.
func assertLongestPrefixWins(t *testing.T, cfg *config.Config, result rules.AccessResult, cleanPath string) {
	t.Helper()

	if result.Rule == nil {
		return
	}

	for _, r := range cfg.Rules {
		if rules.MatchesPath(r.Path, cleanPath) {
			assert.LessOrEqual(t, len(r.Path), len(result.Rule.Path))
		}
	}
}

func FuzzCheckAccess(f *testing.F) {
	// Seed corpus with typical paths
	f.Add("/home/user/project/file.txt", "read")
	f.Add("/home/user/project/file.txt", "write")
	f.Add("/etc/passwd", "read")
	f.Add("/tmp/test", "write")
	f.Add("/home/user/.ssh/id_rsa", "read")
	f.Add("/", "read")
	f.Add("", "read")
	f.Add("relative/path", "read")
	f.Add("/path/with/./dots", "read")
	f.Add("/path/with/../parent", "write")
	f.Add("/home/user", "read")
	f.Add("/home/username", "read") // Similar prefix

	// Seed with edge cases
	f.Add("/home/user/", "read")     // Trailing slash
	f.Add("//double//slash", "read") // Double slashes
	f.Add("/path\x00null", "read")   // Null byte

	f.Fuzz(func(t *testing.T, path string, operationStr string) {
		operation := parseOperation(operationStr)
		cleanPath := filepath.Clean(path)

		// Create a test config with various rules
		cfg := &config.Config{
			Rules: []config.Rule{
				{Resource: config.ResourceFS, Path: "/home/user/project", Permission: config.PermissionReadWrite, RawRule: "fs:rw:/home/user/project"},
				{Resource: config.ResourceFS, Path: "/home/user/project/.git", Permission: config.PermissionReadOnly, RawRule: "fs:ro:/home/user/project/.git"},
				{Resource: config.ResourceFS, Path: "/home/user/.ssh", Permission: config.PermissionNone, RawRule: "fs:none:/home/user/.ssh"},
				{Resource: config.ResourceFS, Path: "/etc", Permission: config.PermissionReadOnly, RawRule: "fs:ro:/etc"},
				{Resource: config.ResourceFS, Path: "/tmp", Permission: config.PermissionReadWrite, RawRule: "fs:rw:/tmp"},
			},
			ManagedPaths: nil,
		}

		resolver := rules.New(cfg)
		result := resolver.CheckAccess(path, operation)

		// Invariant 1: Determinism - same input gives same output
		result2 := resolver.CheckAccess(path, operation)
		assert.Equal(t, result.Allowed, result2.Allowed)
		if result.Rule == nil {
			assert.Nil(t, result2.Rule)
		} else {
			assert.Equal(t, result.Rule.Path, result2.Rule.Path)
		}

		// Invariant 2: If rule returned, it must match the cleaned path
		if result.Rule != nil {
			assert.True(t, rules.MatchesPath(result.Rule.Path, cleanPath))
		}

		// Invariant 3: No other rule has a longer matching prefix
		assertLongestPrefixWins(t, cfg, result, cleanPath)

		// Invariant 4: Write allowed only if rw permission
		if result.Allowed && operation == rules.OperationWrite {
			assert.NotNil(t, result.Rule)
			assert.Equal(t, config.PermissionReadWrite, result.Rule.Permission)
		}

		// Invariant 5: No matching rule means denied
		if result.Rule == nil {
			assert.False(t, result.Allowed)
		}

		// Invariant 6: none permission always denies
		if result.Rule != nil && result.Rule.Permission == config.PermissionNone {
			assert.False(t, result.Allowed)
		}
	})
}

func FuzzMatchesPath(f *testing.F) {
	// Seed corpus with typical scenarios
	f.Add("/home/user", "/home/user/file.txt")
	f.Add("/home/user", "/home/user")
	f.Add("/home/user", "/home/username")
	f.Add("/etc/passwd", "/etc/passwd")
	f.Add("/etc/passwd", "/etc/passwd/child")
	f.Add("/home/user/project", "/home/user/project/src/main.go")
	f.Add("/", "/any/path")
	f.Add("", "")

	// Edge cases
	f.Add("/path", "/path/")
	f.Add("/path/", "/path")
	f.Add("/home/user", "/home/user2")

	f.Fuzz(func(t *testing.T, rulePath string, targetPath string) {
		// Normalize inputs like the real code does
		cleanRulePath := filepath.Clean(rulePath)
		cleanTargetPath := filepath.Clean(targetPath)

		result := rules.MatchesPath(cleanRulePath, cleanTargetPath)

		// Invariant 1: Exact match always succeeds
		if cleanRulePath == cleanTargetPath {
			assert.True(t, result)
		}

		// Invariant 2: If match, target must have rule as path prefix (not just string prefix)
		if result && cleanRulePath != cleanTargetPath {
			assert.Greater(t, len(cleanTargetPath), len(cleanRulePath))
		}

		// Invariant 3: Directory boundary - string prefix without path boundary doesn't match
		// e.g., /home/user should not match /home/user2
		if !result && len(cleanTargetPath) > len(cleanRulePath) {
			// If it's a string prefix but not a match, the next char must not be "/"
			if len(cleanRulePath) > 0 && cleanTargetPath[:len(cleanRulePath)] == cleanRulePath {
				nextChar := cleanTargetPath[len(cleanRulePath)]
				assert.NotEqual(t, byte('/'), nextChar)
			}
		}
	})
}

func FuzzCheckAccessWithOverlappingRules(f *testing.F) {
	// Seed with paths that test overlapping rule scenarios
	f.Add("/home/user/project/src/main.go", "write")
	f.Add("/home/user/project/.git/config", "write")
	f.Add("/home/user/.ssh/id_rsa", "read")
	f.Add("/home/username/file", "read")
	f.Add("/etc/shadow", "read")

	f.Fuzz(func(t *testing.T, path string, operationStr string) {
		operation := parseOperation(operationStr)
		cleanPath := filepath.Clean(path)

		// Create config with overlapping rules at different levels
		cfg := &config.Config{
			Rules: []config.Rule{
				{Resource: config.ResourceFS, Path: "/home", Permission: config.PermissionReadOnly, RawRule: "fs:ro:/home"},
				{Resource: config.ResourceFS, Path: "/home/user", Permission: config.PermissionReadWrite, RawRule: "fs:rw:/home/user"},
				{Resource: config.ResourceFS, Path: "/home/user/project", Permission: config.PermissionReadWrite, RawRule: "fs:rw:/home/user/project"},
				{Resource: config.ResourceFS, Path: "/home/user/project/.git", Permission: config.PermissionReadOnly, RawRule: "fs:ro:/home/user/project/.git"},
				{Resource: config.ResourceFS, Path: "/home/user/.ssh", Permission: config.PermissionNone, RawRule: "fs:none:/home/user/.ssh"},
				{Resource: config.ResourceFS, Path: "/etc", Permission: config.PermissionReadOnly, RawRule: "fs:ro:/etc"},
			},
			ManagedPaths: nil,
		}

		resolver := rules.New(cfg)
		result := resolver.CheckAccess(path, operation)

		// Invariant: Longest prefix always wins
		assertLongestPrefixWins(t, cfg, result, cleanPath)

		// Invariant: Permission hierarchy is respected
		if result.Rule != nil {
			switch result.Rule.Permission {
			case config.PermissionNone:
				assert.False(t, result.Allowed)
			case config.PermissionReadOnly:
				if operation == rules.OperationWrite {
					assert.False(t, result.Allowed)
				}
			case config.PermissionReadWrite:
				assert.True(t, result.Allowed)
			case config.PermissionUnknown:
				t.Fatal("resolved rule has PermissionUnknown")
			}
		}
	})
}

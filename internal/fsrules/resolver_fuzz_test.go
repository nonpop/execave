package fsrules_test

import (
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/pathutil"
	"github.com/stretchr/testify/assert"
)

func fsRule(permission fsrules.Permission, path string) fsrules.Rule {
	var permStr string
	switch permission {
	case fsrules.PermissionReadOnly:
		permStr = "ro"
	case fsrules.PermissionReadWrite:
		permStr = "rw"
	case fsrules.PermissionNone:
		permStr = "none"
	case fsrules.PermissionUnknown:
		permStr = "unknown"
	default:
		permStr = "unknown"
	}

	return fsrules.Rule{
		Permission: permission,
		Path:       path,
		RawRule:    permStr + ":" + path,
		SourcePath: "",
	}
}

// testConfig holds rules and managed paths for use by fuzz tests.
type testConfig struct {
	rules        []fsrules.Rule
	managedPaths []string
}

// parseOperation converts a string to an Operation for fuzz testing.
// Unknown strings are converted directly to test that arbitrary values don't cause panics.
func parseOperation(opStr string) fsrules.Operation {
	switch opStr {
	case "read":
		return fsrules.OperationRead
	case "write":
		return fsrules.OperationWrite
	default:
		return fsrules.Operation(opStr)
	}
}

// ruleFor returns the rule whose RawRule equals rawRule, or nil if not found.
func ruleFor(rules []fsrules.Rule, rawRule string) *fsrules.Rule {
	for i := range rules {
		if rules[i].RawRule == rawRule {
			return &rules[i]
		}
	}
	return nil
}

// matchedRule returns the rule identified by result.Rule, or nil if result.Rule is nil.
func matchedRule(rules []fsrules.Rule, result fsrules.AccessResult) *fsrules.Rule {
	if result.Rule == nil {
		return nil
	}
	return ruleFor(rules, *result.Rule)
}

// pathMatchesRule reports whether cleanPath is covered by rulePath.
func pathMatchesRule(cleanPath, rulePath string) bool {
	return pathutil.IsUnder(cleanPath, rulePath)
}

// assertLongestPrefixWins checks that no rule in cfg has a longer matching prefix than result.Rule.
func assertLongestPrefixWins(t *testing.T, cfg *testConfig, result fsrules.AccessResult, cleanPath string) {
	t.Helper()

	matched := matchedRule(cfg.rules, result)
	if matched == nil {
		return
	}

	for _, r := range cfg.rules {
		if pathMatchesRule(cleanPath, r.Path) {
			assert.LessOrEqual(t, len(r.Path), len(matched.Path))
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

	// Seed with paths that test overlapping rule scenarios
	f.Add("/home/user/project/src/main.go", "write")
	f.Add("/home/user/project/.git/config", "write")
	f.Add("/home/username/file", "read")
	f.Add("/etc/shadow", "read")

	f.Fuzz(func(t *testing.T, path string, operationStr string) {
		operation := parseOperation(operationStr)
		cleanPath := filepath.Clean(path)

		// Create a test config with overlapping rules at different levels
		cfg := &testConfig{
			rules: []fsrules.Rule{
				fsRule(fsrules.PermissionReadOnly, "/home"),
				fsRule(fsrules.PermissionReadWrite, "/home/user"),
				fsRule(fsrules.PermissionReadWrite, "/home/user/project"),
				fsRule(fsrules.PermissionReadOnly, "/home/user/project/.git"),
				fsRule(fsrules.PermissionNone, "/home/user/.ssh"),
				fsRule(fsrules.PermissionReadOnly, "/etc"),
			},
			managedPaths: nil,
		}

		resolver := fsrules.NewResolver(cfg.rules, cfg.managedPaths)
		result := resolver.CheckAccess(path, operation)

		// Invariant 1: Determinism - same input gives same output
		result2 := resolver.CheckAccess(path, operation)
		assert.Equal(t, result.Allowed, result2.Allowed)
		if result.Rule == nil {
			assert.Nil(t, result2.Rule)
		} else {
			assert.Equal(t, *result.Rule, *result2.Rule)
		}

		// Invariant 2: If rule returned, it must match the cleaned path
		if result.Rule != nil {
			matched := matchedRule(cfg.rules, result)
			if assert.NotNil(t, matched) {
				assert.True(t, pathMatchesRule(cleanPath, matched.Path))
			}
		}

		// Invariant 3: No other rule has a longer matching prefix
		assertLongestPrefixWins(t, cfg, result, cleanPath)

		// Invariant 4: Write allowed only if rw permission
		if result.Allowed && operation == fsrules.OperationWrite {
			assert.NotNil(t, result.Rule)
			if result.Rule != nil {
				matched := matchedRule(cfg.rules, result)
				if assert.NotNil(t, matched) {
					assert.Equal(t, fsrules.PermissionReadWrite, matched.Permission)
				}
			}
		}

		// Invariant 5: No matching rule means denied
		if result.Rule == nil {
			assert.False(t, result.Allowed)
		}

		// Invariant 6: none permission always denies
		if matched := matchedRule(cfg.rules, result); matched != nil && matched.Permission == fsrules.PermissionNone {
			assert.False(t, result.Allowed)
		}

		// Invariant 7: Permission hierarchy is respected
		if result.Rule != nil {
			matched := matchedRule(cfg.rules, result)
			if assert.NotNil(t, matched) {
				switch matched.Permission {
				case fsrules.PermissionNone:
					assert.False(t, result.Allowed)
				case fsrules.PermissionReadOnly:
					if operation == fsrules.OperationWrite {
						assert.False(t, result.Allowed)
					}
				case fsrules.PermissionReadWrite:
					assert.True(t, result.Allowed)
				default:
					t.Fatalf("fuzz: resolved rule has unexpected permission %d", matched.Permission)
				}
			}
		}
	})
}

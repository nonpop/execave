package rules_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeTestConfig(rules []config.Rule) *config.Config {
	return &config.Config{
		Rules: rules,
	}
}

func fsRule(permission config.Permission, path string) config.Rule {
	var permStr string
	switch permission {
	case config.PermissionReadOnly:
		permStr = "ro"
	case config.PermissionReadWrite:
		permStr = "rw"
	case config.PermissionNone:
		permStr = "none"
	case config.PermissionUnknown:
		permStr = "unknown"
	default:
		permStr = "unknown"
	}

	return config.Rule{
		Resource:   config.ResourceFS,
		Permission: permission,
		Path:       path,
		RawRule:    "fs:" + permStr + ":" + path,
	}
}

func assertNoAccess(t *testing.T, resolver *rules.Resolver, path string) {
	t.Helper()
	readResult := resolver.CheckAccess(path, rules.OperationRead)
	assert.False(t, readResult.Allowed)
	writeResult := resolver.CheckAccess(path, rules.OperationWrite)
	assert.False(t, writeResult.Allowed)
}

func assertReadOnly(t *testing.T, resolver *rules.Resolver, path string) {
	t.Helper()
	readResult := resolver.CheckAccess(path, rules.OperationRead)
	assert.True(t, readResult.Allowed)
	writeResult := resolver.CheckAccess(path, rules.OperationWrite)
	assert.False(t, writeResult.Allowed)
}

func assertReadWrite(t *testing.T, resolver *rules.Resolver, path string) {
	t.Helper()
	readResult := resolver.CheckAccess(path, rules.OperationRead)
	assert.True(t, readResult.Allowed, "read access should be allowed for %s", path)
	writeResult := resolver.CheckAccess(path, rules.OperationWrite)
	assert.True(t, writeResult.Allowed, "write access should be allowed for %s", path)
}

func TestCheckAccess_NoMatchingRule(t *testing.T) {
	cfg := makeTestConfig([]config.Rule{
		fsRule(config.PermissionReadOnly, "/usr/bin"),
	})

	resolver := rules.New(cfg)

	assertNoAccess(t, resolver, "/opt/secret")
}

func TestCheckAccess_ReadOnly(t *testing.T) {
	cfg := makeTestConfig([]config.Rule{
		fsRule(config.PermissionReadOnly, "/etc"),
	})

	resolver := rules.New(cfg)

	assertReadOnly(t, resolver, "/etc/passwd")
}

func TestCheckAccess_ReadWrite(t *testing.T) {
	cfg := makeTestConfig([]config.Rule{
		fsRule(config.PermissionReadWrite, "/home/user/project"),
	})

	resolver := rules.New(cfg)

	assertReadWrite(t, resolver, "/home/user/project/file.txt")
}

func TestCheckAccess_None(t *testing.T) {
	cfg := makeTestConfig([]config.Rule{
		fsRule(config.PermissionReadWrite, "/home/user/project"),
		fsRule(config.PermissionNone, "/home/user/project/.env"),
	})

	resolver := rules.New(cfg)

	assertNoAccess(t, resolver, "/home/user/project/.env")
}

func TestCheckAccess_MostSpecificWins(t *testing.T) {
	cfg := makeTestConfig([]config.Rule{
		fsRule(config.PermissionReadWrite, "/home/user/project"),
		fsRule(config.PermissionReadOnly, "/home/user/project/.git"),
	})

	resolver := rules.New(cfg)

	assertReadWrite(t, resolver, "/home/user/project/file.txt")

	// .git should be read-only (more specific ro rule)
	assertReadOnly(t, resolver, "/home/user/project/.git/config")
}

func TestCheckAccess_ExactPathMatch(t *testing.T) {
	cfg := makeTestConfig([]config.Rule{
		fsRule(config.PermissionReadOnly, "/usr/share/data"),
	})

	resolver := rules.New(cfg)

	// Exact match should work
	assertReadOnly(t, resolver, "/usr/share/data")

	// Descendant path should match
	assertReadOnly(t, resolver, "/usr/share/data/file.txt")

	// Different path should not match
	assertNoAccess(t, resolver, "/usr/share/other")
}

func TestCheckAccess_LongestPrefixMatch(t *testing.T) {
	cfg := makeTestConfig([]config.Rule{
		fsRule(config.PermissionReadOnly, "/home/user"),
		fsRule(config.PermissionReadWrite, "/home/user/project"),
		fsRule(config.PermissionNone, "/home/user/project/secrets"),
	})

	resolver := rules.New(cfg)

	// /home/user/docs should match first rule (ro)
	assertReadOnly(t, resolver, "/home/user/docs/file.txt")

	// /home/user/project/src should match second rule (rw)
	assertReadWrite(t, resolver, "/home/user/project/src/main.go")

	// /home/user/project/secrets/key should match third rule (none)
	assertNoAccess(t, resolver, "/home/user/project/secrets/key")
}

func TestCheckAccess_DirectoryBoundary(t *testing.T) {
	cfg := makeTestConfig([]config.Rule{
		fsRule(config.PermissionReadOnly, "/home/user"),
	})

	resolver := rules.New(cfg)

	// /home/user2 should NOT match /home/user rule
	assertNoAccess(t, resolver, "/home/user2/file.txt")

	// /home/user/file should match
	assertReadOnly(t, resolver, "/home/user/file.txt")
}

func TestCheckAccess_SymlinkResolution_AccessibleLink(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "target.txt")
	linkFile := filepath.Join(tmpDir, "link.txt")

	// Create target file
	err := os.WriteFile(targetFile, []byte("test"), 0o600)
	require.NoError(t, err)

	// Create symlink
	err = os.Symlink(targetFile, linkFile)
	require.NoError(t, err)

	// Rules allow both the link location (parent directory) and the target
	cfg := makeTestConfig([]config.Rule{
		fsRule(config.PermissionReadWrite, tmpDir), // Link location accessible
		fsRule(config.PermissionReadOnly, targetFile),
	})

	resolver := rules.New(cfg)

	// Access via symlink should resolve to target and use target's permission
	assertReadOnly(t, resolver, linkFile)
}

func TestCheckAccess_SymlinkResolution_InaccessibleLink(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "target.txt")
	linkFile := filepath.Join(tmpDir, "link.txt")

	// Create target file
	err := os.WriteFile(targetFile, []byte("test"), 0o600)
	require.NoError(t, err)

	// Create symlink
	err = os.Symlink(targetFile, linkFile)
	require.NoError(t, err)

	// Rule allows target but not link location (link wouldn't exist in sandbox)
	cfg := makeTestConfig([]config.Rule{
		fsRule(config.PermissionReadOnly, targetFile),
	})

	resolver := rules.New(cfg)

	// Access via symlink should fail because link location is not accessible
	assertNoAccess(t, resolver, linkFile)
}

func TestMatchesPath(t *testing.T) {
	tests := []struct {
		name       string
		rulePath   string
		targetPath string
		expected   bool
	}{
		{"exact match", "/home/user", "/home/user", true},
		{"child path", "/home/user", "/home/user/file.txt", true},
		{"deep child", "/home/user", "/home/user/a/b/c/file.txt", true},
		{"different path", "/home/user", "/home/other", false},
		{"prefix but not child", "/home/user", "/home/user2", false},
		{"parent path", "/home/user/dir", "/home/user", false},
		{"rule trailing slash exact", "/home/user/", "/home/user", false},
		{"rule trailing slash child", "/home/user/", "/home/user/file.txt", true},
		// Path component boundary edge cases
		{"shorter sibling - last component", "/data/projects", "/data/project", false},
		{"shorter sibling - middle component", "/usr/local/bin", "/usr/loc/binary", false},
		{"string prefix in first component", "/storage/data", "/stor/database", false},
		{"string prefix in last component", "/var/logs", "/var/log", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rules.MatchesPath(tt.rulePath, tt.targetPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCheckAccess_UnknownPermission(t *testing.T) {
	// Test the fail-closed default case for unknown permissions.
	// This exercises the default case in checkPermission().
	cfg := makeTestConfig([]config.Rule{
		fsRule(config.PermissionUnknown, "/test/path"),
	})

	resolver := rules.New(cfg)

	// All access denied for unknown permission (fail-closed)
	assertNoAccess(t, resolver, "/test/path/file.txt")
}

func TestCheckAccess_PathComponentBoundaries(t *testing.T) {
	cfg := makeTestConfig([]config.Rule{
		fsRule(config.PermissionReadWrite, "/data/projects"),
		fsRule(config.PermissionReadOnly, "/usr/local/bin"),
		fsRule(config.PermissionReadWrite, "/storage/data"),
	})

	resolver := rules.New(cfg)

	// These paths should NOT match - they are siblings with string prefixes
	assertNoAccess(t, resolver, "/data/project/file.txt")   // "project" vs "projects"
	assertNoAccess(t, resolver, "/usr/loc/binary")          // "loc" vs "local"
	assertNoAccess(t, resolver, "/stor/database/db.sqlite") // "stor" vs "storage"
	assertNoAccess(t, resolver, "/storage/dat/file.txt")    // "dat" vs "data"

	// These paths SHOULD match - they are actual children
	assertReadWrite(t, resolver, "/data/projects/myapp/src/main.go")
	assertReadOnly(t, resolver, "/usr/local/bin/executable")
	assertReadWrite(t, resolver, "/storage/data/files/document.txt")
}

func TestCheckAccess_RuleAttribution(t *testing.T) {
	t.Run("no matching rule returns nil", func(t *testing.T) {
		cfg := makeTestConfig([]config.Rule{
			fsRule(config.PermissionReadOnly, "/usr/bin"),
		})
		resolver := rules.New(cfg)

		result := resolver.CheckAccess("/opt/secret", rules.OperationRead)
		assert.False(t, result.Allowed)
		assert.Nil(t, result.Rule)
	})

	t.Run("matching rule is returned", func(t *testing.T) {
		rule := fsRule(config.PermissionReadOnly, "/etc")
		cfg := makeTestConfig([]config.Rule{rule})
		resolver := rules.New(cfg)

		result := resolver.CheckAccess("/etc/passwd", rules.OperationRead)
		assert.True(t, result.Allowed)
		require.NotNil(t, result.Rule)
		assert.Equal(t, rule.Path, result.Rule.Path)
		assert.Equal(t, rule.Permission, result.Rule.Permission)
	})

	t.Run("most specific rule is returned", func(t *testing.T) {
		generalRule := fsRule(config.PermissionReadWrite, "/home/user/project")
		specificRule := fsRule(config.PermissionReadOnly, "/home/user/project/.git")
		cfg := makeTestConfig([]config.Rule{generalRule, specificRule})
		resolver := rules.New(cfg)

		// Access under general rule
		result := resolver.CheckAccess("/home/user/project/file.txt", rules.OperationWrite)
		assert.True(t, result.Allowed)
		require.NotNil(t, result.Rule)
		assert.Equal(t, generalRule.Path, result.Rule.Path)

		// Access under specific rule
		result = resolver.CheckAccess("/home/user/project/.git/config", rules.OperationRead)
		assert.True(t, result.Allowed)
		require.NotNil(t, result.Rule)
		assert.Equal(t, specificRule.Path, result.Rule.Path)
	})

	t.Run("unknown permission rule is returned", func(t *testing.T) {
		rule := fsRule(config.PermissionUnknown, "/test/path")
		cfg := makeTestConfig([]config.Rule{rule})
		resolver := rules.New(cfg)

		result := resolver.CheckAccess("/test/path/file.txt", rules.OperationRead)
		assert.False(t, result.Allowed)
		require.NotNil(t, result.Rule)
		assert.Equal(t, config.PermissionUnknown, result.Rule.Permission)
	})
}

package fsrules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testConfig struct {
	rules        []Rule
	managedPaths []string
}

func makeTestConfig(rules []Rule) *testConfig {
	return &testConfig{
		rules:        rules,
		managedPaths: nil,
	}
}

func newResolver(cfg *testConfig) *Resolver {
	return NewResolver(cfg.rules, cfg.managedPaths)
}

func fsRule(permission Permission, path string) Rule {
	var permStr string
	switch permission {
	case PermissionReadOnly:
		permStr = "ro"
	case PermissionReadWrite:
		permStr = "rw"
	case PermissionNone:
		permStr = "none"
	case PermissionUnknown:
		permStr = "unknown"
	default:
		permStr = "unknown"
	}

	return Rule{
		Permission: permission,
		Path:       path,
		RawRule:    permStr + ":" + path,
		SourcePath: "",
	}
}

func assertNoAccess(t *testing.T, resolver *Resolver, path string) {
	t.Helper()
	readResult := resolver.CheckAccess(path, OperationRead)
	assert.False(t, readResult.Allowed)
	writeResult := resolver.CheckAccess(path, OperationWrite)
	assert.False(t, writeResult.Allowed)
}

func assertReadOnly(t *testing.T, resolver *Resolver, path string) {
	t.Helper()
	readResult := resolver.CheckAccess(path, OperationRead)
	assert.True(t, readResult.Allowed)
	writeResult := resolver.CheckAccess(path, OperationWrite)
	assert.False(t, writeResult.Allowed)
}

func assertReadWrite(t *testing.T, resolver *Resolver, path string) {
	t.Helper()
	readResult := resolver.CheckAccess(path, OperationRead)
	assert.True(t, readResult.Allowed)
	writeResult := resolver.CheckAccess(path, OperationWrite)
	assert.True(t, writeResult.Allowed)
}

func TestCheckAccess_NoMatchingRule(t *testing.T) {
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, "/usr/bin"),
	})

	resolver := newResolver(cfg)

	assertNoAccess(t, resolver, "/opt/secret")
}

func TestCheckAccess_ReadOnly(t *testing.T) {
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, "/etc"),
	})

	resolver := newResolver(cfg)

	assertReadOnly(t, resolver, "/etc/passwd")
}

func TestCheckAccess_ReadWrite(t *testing.T) {
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadWrite, "/home/user/project"),
	})

	resolver := newResolver(cfg)

	assertReadWrite(t, resolver, "/home/user/project/file.txt")
}

func TestCheckAccess_None(t *testing.T) {
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadWrite, "/home/user/project"),
		fsRule(PermissionNone, "/home/user/project/.env"),
	})

	resolver := newResolver(cfg)

	assertNoAccess(t, resolver, "/home/user/project/.env")
}

func TestCheckAccess_MostSpecificWins(t *testing.T) {
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadWrite, "/home/user/project"),
		fsRule(PermissionReadOnly, "/home/user/project/.git"),
	})

	resolver := newResolver(cfg)

	assertReadWrite(t, resolver, "/home/user/project/file.txt")

	// .git should be read-only (more specific ro rule)
	assertReadOnly(t, resolver, "/home/user/project/.git/config")
}

func TestCheckAccess_ExactPathMatch(t *testing.T) {
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, "/usr/share/data"),
	})

	resolver := newResolver(cfg)

	// Exact match should work
	assertReadOnly(t, resolver, "/usr/share/data")

	// Descendant path should match
	assertReadOnly(t, resolver, "/usr/share/data/file.txt")

	// Different path should not match
	assertNoAccess(t, resolver, "/usr/share/other")
}

func TestCheckAccess_LongestPrefixMatch(t *testing.T) {
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, "/home/user"),
		fsRule(PermissionReadWrite, "/home/user/project"),
		fsRule(PermissionNone, "/home/user/project/secrets"),
	})

	resolver := newResolver(cfg)

	// /home/user/docs should match first rule (ro)
	assertReadOnly(t, resolver, "/home/user/docs/file.txt")

	// /home/user/project/src should match second rule (rw)
	assertReadWrite(t, resolver, "/home/user/project/src/main.go")

	// /home/user/project/secrets/key should match third rule (none)
	assertNoAccess(t, resolver, "/home/user/project/secrets/key")
}

func TestCheckAccess_DirectoryBoundary(t *testing.T) {
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, "/home/user"),
	})

	resolver := newResolver(cfg)

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
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadWrite, tmpDir), // Link location accessible
		fsRule(PermissionReadOnly, targetFile),
	})

	resolver := newResolver(cfg)

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
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, targetFile),
	})

	resolver := newResolver(cfg)

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
			result := matchesPath(tt.rulePath, tt.targetPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCheckAccess_UnknownPermission(t *testing.T) {
	// PermissionUnknown in a matched rule is an invariant violation: panic.
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionUnknown, "/test/path"),
	})

	resolver := newResolver(cfg)

	assert.Panics(t, func() { resolver.CheckAccess("/test/path/file.txt", OperationRead) })
}

func TestCheckAccess_PathComponentBoundaries(t *testing.T) {
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadWrite, "/data/projects"),
		fsRule(PermissionReadOnly, "/usr/local/bin"),
		fsRule(PermissionReadWrite, "/storage/data"),
	})

	resolver := newResolver(cfg)

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
		cfg := makeTestConfig([]Rule{
			fsRule(PermissionReadOnly, "/usr/bin"),
		})
		resolver := newResolver(cfg)

		result := resolver.CheckAccess("/opt/secret", OperationRead)
		assert.False(t, result.Allowed)
		assert.Nil(t, result.Rule)
		assert.Nil(t, result.Symlink)
	})

	t.Run("matching rule is returned", func(t *testing.T) {
		rule := fsRule(PermissionReadOnly, "/etc")
		cfg := makeTestConfig([]Rule{rule})
		resolver := newResolver(cfg)

		result := resolver.CheckAccess("/etc/passwd", OperationRead)
		assert.True(t, result.Allowed)
		require.NotNil(t, result.Rule)
		assert.Equal(t, rule.RawRule, *result.Rule)
	})

	t.Run("most specific rule is returned", func(t *testing.T) {
		generalRule := fsRule(PermissionReadWrite, "/home/user/project")
		specificRule := fsRule(PermissionReadOnly, "/home/user/project/.git")
		cfg := makeTestConfig([]Rule{generalRule, specificRule})
		resolver := newResolver(cfg)

		// Access under general rule
		result := resolver.CheckAccess("/home/user/project/file.txt", OperationWrite)
		assert.True(t, result.Allowed)
		require.NotNil(t, result.Rule)
		assert.Equal(t, generalRule.RawRule, *result.Rule)

		// Access under specific rule
		result = resolver.CheckAccess("/home/user/project/.git/config", OperationRead)
		assert.True(t, result.Allowed)
		require.NotNil(t, result.Rule)
		assert.Equal(t, specificRule.RawRule, *result.Rule)
	})

	t.Run("unknown permission panics", func(t *testing.T) {
		rule := fsRule(PermissionUnknown, "/test/path")
		cfg := makeTestConfig([]Rule{rule})
		resolver := newResolver(cfg)

		assert.Panics(t, func() { resolver.CheckAccess("/test/path/file.txt", OperationRead) })
	})
}

func TestCheckAccess_SymlinkWithinMount(t *testing.T) {
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

	// Rule allows the mount directory
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, tmpDir),
	})

	resolver := newResolver(cfg)

	// Access via symlink should resolve and log the hop
	result := resolver.CheckAccess(linkFile, OperationRead)
	assert.True(t, result.Allowed)
	require.NotNil(t, result.Symlink)
	assert.Len(t, result.Symlink.Hops, 1)
	assert.Equal(t, linkFile, result.Symlink.Hops[0].Path)
	assert.True(t, result.Symlink.Hops[0].Allowed)
	assert.Equal(t, targetFile, result.Symlink.ResolvedPath)
	require.NotNil(t, result.Rule)
	assert.Equal(t, "ro:"+tmpDir, *result.Rule)
}

func TestCheckAccess_RelativeSymlinkWithinMount(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "target.txt")
	linkFile := filepath.Join(tmpDir, "link.txt")

	// Create target file
	err := os.WriteFile(targetFile, []byte("test"), 0o600)
	require.NoError(t, err)

	// Create relative symlink (not absolute path)
	err = os.Symlink("target.txt", linkFile)
	require.NoError(t, err)

	// Rule allows the mount directory
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, tmpDir),
	})

	resolver := newResolver(cfg)

	// Access via relative symlink should resolve and log the hop
	result := resolver.CheckAccess(linkFile, OperationRead)
	assert.True(t, result.Allowed)
	require.NotNil(t, result.Symlink)
	assert.Len(t, result.Symlink.Hops, 1)
	assert.Equal(t, linkFile, result.Symlink.Hops[0].Path)
	assert.True(t, result.Symlink.Hops[0].Allowed)
	assert.Equal(t, targetFile, result.Symlink.ResolvedPath)
	require.NotNil(t, result.Rule)
	assert.Equal(t, "ro:"+tmpDir, *result.Rule)
}

func TestCheckAccess_RelativeSymlinkChain(t *testing.T) {
	// Create temp directory structure with relative symlink chain
	tmpDir := t.TempDir()
	link := filepath.Join(tmpDir, "link")
	hop2 := filepath.Join(tmpDir, "hop2")
	final := filepath.Join(tmpDir, "final.txt")

	// Create final target file
	err := os.WriteFile(final, []byte("test"), 0o600)
	require.NoError(t, err)

	// Create relative symlink chain: link -> hop2 -> final.txt
	err = os.Symlink("final.txt", hop2)
	require.NoError(t, err)
	err = os.Symlink("hop2", link)
	require.NoError(t, err)

	// Rule allows the mount directory
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, tmpDir),
	})

	resolver := newResolver(cfg)

	// Access via relative symlink chain
	result := resolver.CheckAccess(link, OperationRead)
	assert.True(t, result.Allowed)
	require.NotNil(t, result.Symlink)
	require.Len(t, result.Symlink.Hops, 2)

	// First hop: link -> hop2
	assert.Equal(t, link, result.Symlink.Hops[0].Path)
	assert.True(t, result.Symlink.Hops[0].Allowed)
	require.NotNil(t, result.Symlink.Hops[0].Rule)

	// Second hop: hop2 -> final.txt
	assert.Equal(t, hop2, result.Symlink.Hops[1].Path)
	assert.True(t, result.Symlink.Hops[1].Allowed)
	require.NotNil(t, result.Symlink.Hops[1].Rule)

	// Final target
	assert.Equal(t, final, result.Symlink.ResolvedPath)
	assert.True(t, result.Allowed)
	require.NotNil(t, result.Rule)
}

func TestCheckAccess_RuleBoundarySymlink(t *testing.T) {
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

	// Rule path exactly matches symlink path (bwrap mounts target at this path)
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, linkFile),
	})

	resolver := newResolver(cfg)

	// Symlink at rule boundary should NOT be resolved
	result := resolver.CheckAccess(linkFile, OperationRead)
	assert.True(t, result.Allowed)
	assert.Nil(t, result.Symlink)
	require.NotNil(t, result.Rule)
	assert.Equal(t, "ro:"+linkFile, *result.Rule)
}

func TestCheckAccess_RuleBoundarySymlinkIntermediateComponent(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()
	realDir := filepath.Join(tmpDir, "real-dir")
	linkDir := filepath.Join(tmpDir, "link-dir")
	targetFile := filepath.Join(realDir, "file.txt")

	// Create real directory and file
	err := os.Mkdir(realDir, 0o700)
	require.NoError(t, err)
	err = os.WriteFile(targetFile, []byte("test"), 0o600)
	require.NoError(t, err)

	// Create symlink to directory
	err = os.Symlink(realDir, linkDir)
	require.NoError(t, err)

	// Rule path matches the symlink directory (bwrap mounts target at this path)
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, linkDir),
	})

	resolver := newResolver(cfg)

	// Access to descendant via rule-boundary symlink should not resolve the symlink
	linkPath := filepath.Join(linkDir, "file.txt")
	result := resolver.CheckAccess(linkPath, OperationRead)
	assert.True(t, result.Allowed)
	assert.Nil(t, result.Symlink)
	require.NotNil(t, result.Rule)
	assert.Equal(t, "ro:"+linkDir, *result.Rule)
}

func TestCheckAccess_SymlinkChainMultiHop(t *testing.T) {
	// Create temp directory structure with multi-hop chain
	tmpDir := t.TempDir()
	hop1 := filepath.Join(tmpDir, "hop1")
	hop2 := filepath.Join(tmpDir, "hop2")
	final := filepath.Join(tmpDir, "final.txt")

	// Create final target file
	err := os.WriteFile(final, []byte("test"), 0o600)
	require.NoError(t, err)

	// Create symlink chain: hop1 -> hop2 -> final.txt
	err = os.Symlink(final, hop2)
	require.NoError(t, err)
	err = os.Symlink(hop2, hop1)
	require.NoError(t, err)

	// Rule allows the mount directory
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, tmpDir),
	})

	resolver := newResolver(cfg)

	// Access via multi-hop chain
	result := resolver.CheckAccess(hop1, OperationRead)
	assert.True(t, result.Allowed)
	require.NotNil(t, result.Symlink)
	require.Len(t, result.Symlink.Hops, 2)

	// First hop: hop1 -> hop2
	assert.Equal(t, hop1, result.Symlink.Hops[0].Path)
	assert.True(t, result.Symlink.Hops[0].Allowed)
	require.NotNil(t, result.Symlink.Hops[0].Rule)

	// Second hop: hop2 -> final.txt
	assert.Equal(t, hop2, result.Symlink.Hops[1].Path)
	assert.True(t, result.Symlink.Hops[1].Allowed)
	require.NotNil(t, result.Symlink.Hops[1].Rule)

	// Final target
	assert.Equal(t, final, result.Symlink.ResolvedPath)
	assert.True(t, result.Allowed)
	require.NotNil(t, result.Rule)
}

func TestCheckAccess_SymlinkChainDeniedHop(t *testing.T) {
	// Create temp directory structure with chain that breaks
	tmpDir := t.TempDir()
	outsideDir := filepath.Join(tmpDir, "outside")
	mountDir := filepath.Join(tmpDir, "mount")

	err := os.Mkdir(outsideDir, 0o700)
	require.NoError(t, err)
	err = os.Mkdir(mountDir, 0o700)
	require.NoError(t, err)

	hop1 := filepath.Join(mountDir, "hop1")
	hop2 := filepath.Join(outsideDir, "hop2")
	final := filepath.Join(mountDir, "final.txt")

	// Create final target file
	err = os.WriteFile(final, []byte("test"), 0o600)
	require.NoError(t, err)

	// Create chain: hop1 -> outside/hop2 -> final.txt (chain breaks at hop2)
	err = os.Symlink(final, hop2)
	require.NoError(t, err)
	err = os.Symlink(hop2, hop1)
	require.NoError(t, err)

	// Rule only allows mount directory, not outside
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, mountDir),
	})

	resolver := newResolver(cfg)

	// Access should be denied at the intermediate hop
	result := resolver.CheckAccess(hop1, OperationRead)
	assert.False(t, result.Allowed)
	assert.Nil(t, result.Rule)
	require.NotNil(t, result.Symlink)
	require.Len(t, result.Symlink.Hops, 2)

	// First hop should be OK
	assert.Equal(t, hop1, result.Symlink.Hops[0].Path)
	assert.True(t, result.Symlink.Hops[0].Allowed)

	// Second hop should be denied
	assert.Equal(t, hop2, result.Symlink.Hops[1].Path)
	assert.False(t, result.Symlink.Hops[1].Allowed)
	assert.Nil(t, result.Symlink.Hops[1].Rule)

	// ResolvedPath should be empty when chain breaks
	assert.Empty(t, result.Symlink.ResolvedPath)
}

func TestCheckAccess_SymlinkEscapesMount(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()
	mountDir := filepath.Join(tmpDir, "mount")
	outsideDir := filepath.Join(tmpDir, "outside")

	err := os.Mkdir(mountDir, 0o700)
	require.NoError(t, err)
	err = os.Mkdir(outsideDir, 0o700)
	require.NoError(t, err)

	escapeLink := filepath.Join(mountDir, "escape.txt")
	outsideTarget := filepath.Join(outsideDir, "secret.txt")

	err = os.WriteFile(outsideTarget, []byte("secret"), 0o600)
	require.NoError(t, err)
	err = os.Symlink(outsideTarget, escapeLink)
	require.NoError(t, err)

	// Rule only allows mount directory
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, mountDir),
	})

	resolver := newResolver(cfg)

	// Symlink hop should be OK, but target should be denied
	result := resolver.CheckAccess(escapeLink, OperationRead)
	assert.False(t, result.Allowed)
	assert.Nil(t, result.Rule)
	require.NotNil(t, result.Symlink)
	require.Len(t, result.Symlink.Hops, 1)
	assert.True(t, result.Symlink.Hops[0].Allowed)
	assert.Equal(t, outsideTarget, result.Symlink.ResolvedPath)
}

func TestCheckAccess_SymlinkDepthLimit(t *testing.T) {
	// Create a symlink loop
	tmpDir := t.TempDir()
	loopA := filepath.Join(tmpDir, "loop-a")
	loopB := filepath.Join(tmpDir, "loop-b")

	err := os.Symlink(loopB, loopA)
	require.NoError(t, err)
	err = os.Symlink(loopA, loopB)
	require.NoError(t, err)

	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, tmpDir),
	})

	resolver := newResolver(cfg)

	// Should detect loop and deny at the 40th hop (MAXSYMLINKS)
	// The kernel checks if (count >= MAXSYMLINKS) where MAXSYMLINKS=40,
	// so it allows up to 39 hops
	result := resolver.CheckAccess(loopA, OperationRead)
	assert.False(t, result.Allowed)
	require.NotNil(t, result.Symlink)
	// Should have 40 hops (0-39 allowed, 40th denied)
	assert.Len(t, result.Symlink.Hops, 40)
	// Last hop should be denied
	assert.False(t, result.Symlink.Hops[39].Allowed)
	assert.Nil(t, result.Symlink.Hops[39].Rule)
}

func TestCheckAccess_SymlinkIntermediateComponent(t *testing.T) {
	// Create temp directory structure with symlink in middle of path
	tmpDir := t.TempDir()
	realDir := filepath.Join(tmpDir, "real-subdir")
	linkDir := filepath.Join(tmpDir, "link-subdir")

	err := os.Mkdir(realDir, 0o700)
	require.NoError(t, err)

	targetFile := filepath.Join(realDir, "file.txt")
	err = os.WriteFile(targetFile, []byte("test"), 0o600)
	require.NoError(t, err)

	// Create symlink to directory
	err = os.Symlink(realDir, linkDir)
	require.NoError(t, err)

	// Rule allows the parent directory (so both link and target are within mount)
	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, tmpDir),
	})

	resolver := newResolver(cfg)

	// Access file through symlink directory in path
	linkPath := filepath.Join(linkDir, "file.txt")
	result := resolver.CheckAccess(linkPath, OperationRead)
	assert.True(t, result.Allowed)
	require.NotNil(t, result.Symlink)
	// Should have hop for the symlink directory
	require.Len(t, result.Symlink.Hops, 1)
	assert.Equal(t, linkDir, result.Symlink.Hops[0].Path)
	assert.Equal(t, targetFile, result.Symlink.ResolvedPath)
}

// testSymlinkWriteThroughHelper sets up a symlink between two directories with different permissions
// and validates write-through behavior.
func testSymlinkWriteThroughHelper(
	t *testing.T,
	linkDir, targetDir string,
	linkPerm, targetPerm Permission,
	expectedAllowed bool,
) {
	t.Helper()
	tmpDir := t.TempDir()
	linkDirPath := filepath.Join(tmpDir, linkDir)
	targetDirPath := filepath.Join(tmpDir, targetDir)

	err := os.Mkdir(linkDirPath, 0o700)
	require.NoError(t, err)
	err = os.Mkdir(targetDirPath, 0o700)
	require.NoError(t, err)

	link := filepath.Join(linkDirPath, "link.txt")
	target := filepath.Join(targetDirPath, "target.txt")

	err = os.WriteFile(target, []byte("test"), 0o600)
	require.NoError(t, err)
	err = os.Symlink(target, link)
	require.NoError(t, err)

	cfg := makeTestConfig([]Rule{
		fsRule(linkPerm, linkDirPath),
		fsRule(targetPerm, targetDirPath),
	})

	resolver := newResolver(cfg)

	result := resolver.CheckAccess(link, OperationWrite)
	assert.Equal(t, expectedAllowed, result.Allowed)
	require.NotNil(t, result.Symlink)
	require.Len(t, result.Symlink.Hops, 1)
	assert.True(t, result.Symlink.Hops[0].Allowed)
	require.NotNil(t, result.Rule)
	assert.Contains(t, *result.Rule, targetDirPath)
}

func TestCheckAccess_SymlinkWriteThroughToReadOnly(t *testing.T) {
	// Write through symlink - hop is readable, target write is denied
	testSymlinkWriteThroughHelper(
		t, "writable", "readonly",
		PermissionReadWrite, PermissionReadOnly,
		false,
	)
}

func TestCheckAccess_SymlinkWriteThroughReadOnlyLinkToWritableTarget(t *testing.T) {
	// Write through ro symlink to rw target - hop is readable, target write is allowed
	testSymlinkWriteThroughHelper(
		t, "readonly", "writable",
		PermissionReadOnly, PermissionReadWrite,
		true,
	)
}

func TestCheckAccess_SymlinkThroughManagedPath(t *testing.T) {
	tmpDir := t.TempDir()
	mountDir := filepath.Join(tmpDir, "mount")
	managedDir := filepath.Join(tmpDir, "managed")

	err := os.Mkdir(mountDir, 0o700)
	require.NoError(t, err)
	err = os.Mkdir(managedDir, 0o700)
	require.NoError(t, err)

	// Create symlink: mount/link -> managed/target
	linkPath := filepath.Join(mountDir, "link")
	managedTarget := filepath.Join(managedDir, "target.txt")

	err = os.WriteFile(managedTarget, []byte("data"), 0o600)
	require.NoError(t, err)
	err = os.Symlink(managedTarget, linkPath)
	require.NoError(t, err)

	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadWrite, mountDir),
	})
	cfg.managedPaths = []string{managedDir}

	resolver := newResolver(cfg)

	result := resolver.CheckAccess(linkPath, OperationRead)

	// Can't determine true target — result is uncertain
	assert.True(t, result.Uncertain)
	assert.False(t, result.Allowed)

	// Symlink chain should record the hop and be marked unresolvable
	require.NotNil(t, result.Symlink)
	require.Len(t, result.Symlink.Hops, 1)
	assert.Equal(t, linkPath, result.Symlink.Hops[0].Path)
	assert.True(t, result.Symlink.Hops[0].Allowed)
	assert.True(t, result.Symlink.Unresolvable)
	assert.Empty(t, result.Symlink.ResolvedPath)
}

func TestCheckAccess_SymlinkChainThroughManagedPath(t *testing.T) {
	// mount/hop1 -> mount/hop2 -> managed/target -> mount/final
	// Chain should break when it enters the managed area at hop2's target
	tmpDir := t.TempDir()
	mountDir := filepath.Join(tmpDir, "mount")
	managedDir := filepath.Join(tmpDir, "managed")

	err := os.Mkdir(mountDir, 0o700)
	require.NoError(t, err)
	err = os.Mkdir(managedDir, 0o700)
	require.NoError(t, err)

	hop1 := filepath.Join(mountDir, "hop1")
	hop2 := filepath.Join(mountDir, "hop2")
	managedLink := filepath.Join(managedDir, "link")
	finalTarget := filepath.Join(mountDir, "final.txt")

	err = os.WriteFile(finalTarget, []byte("data"), 0o600)
	require.NoError(t, err)
	err = os.Symlink(finalTarget, managedLink)
	require.NoError(t, err)
	err = os.Symlink(managedLink, hop2)
	require.NoError(t, err)
	err = os.Symlink(hop2, hop1)
	require.NoError(t, err)

	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadWrite, mountDir),
	})
	cfg.managedPaths = []string{managedDir}

	resolver := newResolver(cfg)

	result := resolver.CheckAccess(hop1, OperationRead)

	// Chain enters managed area after hop2, so result is uncertain
	assert.True(t, result.Uncertain)
	assert.False(t, result.Allowed)

	require.NotNil(t, result.Symlink)
	// hop1 and hop2 were resolved before entering managed area
	require.Len(t, result.Symlink.Hops, 2)
	assert.Equal(t, hop1, result.Symlink.Hops[0].Path)
	assert.True(t, result.Symlink.Hops[0].Allowed)
	assert.Equal(t, hop2, result.Symlink.Hops[1].Path)
	assert.True(t, result.Symlink.Hops[1].Allowed)
	assert.True(t, result.Symlink.Unresolvable)
}

func TestCheckAccess_NonExistentPathNotResolved(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistent := filepath.Join(tmpDir, "does-not-exist.txt")

	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, tmpDir),
	})

	resolver := newResolver(cfg)

	// Non-existent path should not be resolved as symlink
	result := resolver.CheckAccess(nonExistent, OperationRead)
	assert.True(t, result.Allowed)
	assert.True(t, result.PathNotFound)
	assert.Nil(t, result.Symlink)
	require.NotNil(t, result.Rule)
	assert.Equal(t, "ro:"+tmpDir, *result.Rule)
}

func TestCheckAccess_ExistingPathNotMarkedNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	existingFile := filepath.Join(tmpDir, "exists.txt")
	err := os.WriteFile(existingFile, []byte("test"), 0o600)
	require.NoError(t, err)

	cfg := makeTestConfig([]Rule{
		fsRule(PermissionReadOnly, tmpDir),
	})

	resolver := newResolver(cfg)

	result := resolver.CheckAccess(existingFile, OperationRead)
	assert.True(t, result.Allowed)
	assert.False(t, result.PathNotFound)
}

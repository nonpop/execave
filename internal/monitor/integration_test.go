package monitor_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Requirement: Operation type mapping ---

func TestIntegration_OperationTypeMapping_QueryingFileMetadataLoggedAsRead(t *testing.T) {
	var testFile string
	env := newMonitorTestEnv(t, func(tmpDir string) *config.Config {
		testFile = filepath.Join(tmpDir, "test.txt")
		require.NoError(t, os.WriteFile(testFile, []byte("content"), 0o600))
		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(tmpDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	// stat queries file metadata
	exitCode, err := env.run([]string{"stat", testFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	assertLogContainsLine(t, logStr, "READ", testFile, "OK", "fs:ro:"+env.TmpDir)
}

func TestIntegration_OperationTypeMapping_CreatingDirectoryLoggedAsWrite(t *testing.T) {
	// Use a directory outside /tmp to avoid managed path filtering
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	newDir := filepath.Join(absTestDir, "newdir")

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{rwRule(absTestDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	exitCode, err := env.run([]string{"mkdir", newDir})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	assertLogContainsLine(t, logStr, "WRITE", newDir, "OK", "fs:rw:"+absTestDir)
}

// --- Requirement: Real-time access log writing ---

func TestIntegration_RealTimeAccessLogWriting_LogEntriesAppearInSyscallOrder(t *testing.T) {
	// Use a directory outside /tmp to avoid managed path filtering
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	aFile := filepath.Join(absTestDir, "a.txt")
	bFile := filepath.Join(absTestDir, "b.txt")
	require.NoError(t, os.WriteFile(aFile, []byte("a"), 0o600))
	require.NoError(t, os.WriteFile(bFile, []byte("b"), 0o600))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{rwRule(absTestDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	// Read a.txt then write b.txt
	exitCode, err := env.run([]string{"sh", "-c", "cat " + aFile + " && echo new > " + bFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	lines := strings.Split(logStr, "\n")

	readIdx := -1
	writeIdx := -1
	for i, line := range lines {
		if strings.Contains(line, "READ") && strings.Contains(line, "a.txt") {
			readIdx = i
		}
		if strings.Contains(line, "WRITE") && strings.Contains(line, "b.txt") {
			writeIdx = i
		}
	}

	require.NotEqual(t, -1, readIdx)
	require.NotEqual(t, -1, writeIdx)
	assert.Less(t, readIdx, writeIdx)
}

// --- Requirement: Symlink path resolution in access logging ---

func TestIntegration_SymlinkPathResolution_RuleBoundarySymlinkLoggedWithoutResolution(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	linkFile := filepath.Join(absTestDir, "link-file")
	targetFile := filepath.Join(absTestDir, "target-file")

	require.NoError(t, os.WriteFile(targetFile, []byte("target content"), 0o600))
	require.NoError(t, os.Symlink(targetFile, linkFile))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			// Rule targets the symlink exactly → rule boundary
			FSRules:      []fsrules.Rule{roRule(linkFile)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	exitCode, err := env.run([]string{"cat", linkFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	assertLogContainsLine(t, logStr, "READ", linkFile, "OK", "fs:ro:"+linkFile)
	// Target should NOT be in the log
	assert.NotContains(t, logStr, targetFile)
}

func TestIntegration_SymlinkPathResolution_RuleBoundarySymlinkInIntermediateComponentLoggedWithoutResolution(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	realDir := filepath.Join(absTestDir, "real-dir")
	linkDir := filepath.Join(absTestDir, "link-dir")
	targetFile := filepath.Join(realDir, "file.txt")

	require.NoError(t, os.MkdirAll(realDir, 0o750))
	require.NoError(t, os.WriteFile(targetFile, []byte("target content"), 0o600))
	require.NoError(t, os.Symlink(realDir, linkDir))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			// Rule targets the symlink dir → rule boundary
			FSRules:      []fsrules.Rule{roRule(linkDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	linkPath := filepath.Join(linkDir, "file.txt")
	exitCode, err := env.run([]string{"cat", linkPath})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	assertLogContainsLine(t, logStr, "READ", linkPath, "OK", "fs:ro:"+linkDir)
	// Real path should NOT be in log
	assert.NotContains(t, logStr, targetFile)
}

func TestIntegration_SymlinkPathResolution_SymlinkWithinMountResolvedAndLogged(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	mountDir := filepath.Join(absTestDir, "mount")
	linkPath := filepath.Join(mountDir, "link.txt")
	targetPath := filepath.Join(mountDir, "target.txt")

	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	require.NoError(t, os.WriteFile(targetPath, []byte("target content"), 0o600))
	require.NoError(t, os.Symlink(targetPath, linkPath))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	exitCode, err := env.run([]string{"cat", linkPath})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	assertLogContainsLine(t, logStr, "READ", linkPath, "OK", "fs:ro:"+mountDir)
	assertLogContainsLine(t, logStr, "READ", targetPath, "OK", "fs:ro:"+mountDir)
}

func TestIntegration_SymlinkPathResolution_RelativeSymlinkWithinMountResolvedAndLogged(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	mountDir := filepath.Join(absTestDir, "mount")
	linkPath := filepath.Join(mountDir, "link.txt")
	targetPath := filepath.Join(mountDir, "target.txt")

	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	require.NoError(t, os.WriteFile(targetPath, []byte("target content"), 0o600))
	// Create relative symlink
	require.NoError(t, os.Symlink("target.txt", linkPath))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	exitCode, err := env.run([]string{"cat", linkPath})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	assertLogContainsLine(t, logStr, "READ", linkPath, "OK", "fs:ro:"+mountDir)
	assertLogContainsLine(t, logStr, "READ", targetPath, "OK", "fs:ro:"+mountDir)
}

func TestIntegration_SymlinkPathResolution_RelativeSymlinkChainResolvedAndLogged(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	mountDir := filepath.Join(absTestDir, "mount")
	linkPath := filepath.Join(mountDir, "link")
	hop2Path := filepath.Join(mountDir, "hop2")
	finalPath := filepath.Join(mountDir, "final.txt")

	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	require.NoError(t, os.WriteFile(finalPath, []byte("final content"), 0o600))
	// link -> hop2 -> final.txt
	require.NoError(t, os.Symlink("final.txt", hop2Path))
	require.NoError(t, os.Symlink("hop2", linkPath))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	exitCode, err := env.run([]string{"cat", linkPath})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	assertLogContainsLine(t, logStr, "READ", linkPath, "OK", "fs:ro:"+mountDir)
	assertLogContainsLine(t, logStr, "READ", hop2Path, "OK", "fs:ro:"+mountDir)
	assertLogContainsLine(t, logStr, "READ", finalPath, "OK", "fs:ro:"+mountDir)
}

func TestIntegration_SymlinkPathResolution_SymlinkWithinMountPointingOutsideRulesDenied(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	mountDir := filepath.Join(absTestDir, "mount")
	outsideDir := filepath.Join(absTestDir, "outside")
	escapeLink := filepath.Join(mountDir, "escape.txt")
	secretFile := filepath.Join(outsideDir, "secret.txt")

	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	require.NoError(t, os.MkdirAll(outsideDir, 0o750))
	require.NoError(t, os.WriteFile(secretFile, []byte("secret"), 0o600))
	require.NoError(t, os.Symlink(secretFile, escapeLink))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	// Without bwrap, cat follows the symlink and succeeds, but the monitor
	// resolves and logs the denial for the target path
	_, _ = env.run([]string{"cat", escapeLink})

	logStr := env.readLog()
	assertLogContainsLine(t, logStr, "READ", escapeLink, "OK", "fs:ro:"+mountDir)
	assertLogContainsLine(t, logStr, "READ", secretFile, "DENY", "no-matching-rule")
}

func TestIntegration_SymlinkPathResolution_MultiHopSymlinkChainWithinMount(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	mountDir := filepath.Join(absTestDir, "mount")
	hop1 := filepath.Join(mountDir, "hop1")
	hop2 := filepath.Join(mountDir, "hop2")
	final := filepath.Join(mountDir, "final.txt")

	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	require.NoError(t, os.WriteFile(final, []byte("final content"), 0o600))
	require.NoError(t, os.Symlink(final, hop2))
	require.NoError(t, os.Symlink(hop2, hop1))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	exitCode, err := env.run([]string{"cat", hop1})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	assertLogContainsLine(t, logStr, "READ", hop1, "OK", "fs:ro:"+mountDir)
	assertLogContainsLine(t, logStr, "READ", hop2, "OK", "fs:ro:"+mountDir)
	assertLogContainsLine(t, logStr, "READ", final, "OK", "fs:ro:"+mountDir)
}

func TestIntegration_SymlinkPathResolution_MultiHopChainBreaksAtDeniedIntermediateHop(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	mountDir := filepath.Join(absTestDir, "mount")
	nomatchDir := filepath.Join(absTestDir, "nomatch")
	hop1 := filepath.Join(mountDir, "hop1")
	hop2 := filepath.Join(nomatchDir, "hop2")
	final := filepath.Join(mountDir, "final.txt")

	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	require.NoError(t, os.MkdirAll(nomatchDir, 0o750))
	require.NoError(t, os.WriteFile(final, []byte("final content"), 0o600))
	require.NoError(t, os.Symlink(final, hop2))
	require.NoError(t, os.Symlink(hop2, hop1))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	_, _ = env.run([]string{"cat", hop1})

	logStr := env.readLog()
	assertLogContainsLine(t, logStr, "READ", hop1, "OK", "fs:ro:"+mountDir)
	assertLogContainsLine(t, logStr, "READ", hop2, "DENY", "no-matching-rule")
	// Final target should NOT be logged
	assert.NotContains(t, logStr, final)
}

func TestIntegration_SymlinkPathResolution_SymlinkInIntermediatePathComponentResolved(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	mountDir := filepath.Join(absTestDir, "mount")
	realSubdir := filepath.Join(mountDir, "real-subdir")
	linkSubdir := filepath.Join(mountDir, "link-subdir")
	targetFile := filepath.Join(realSubdir, "file.txt")

	require.NoError(t, os.MkdirAll(realSubdir, 0o750))
	require.NoError(t, os.WriteFile(targetFile, []byte("target content"), 0o600))
	require.NoError(t, os.Symlink(realSubdir, linkSubdir))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	linkPath := filepath.Join(linkSubdir, "file.txt")
	exitCode, err := env.run([]string{"cat", linkPath})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	assertLogContainsLine(t, logStr, "READ", linkSubdir, "OK", "fs:ro:"+mountDir)
	assertLogContainsLine(t, logStr, "READ", targetFile, "OK", "fs:ro:"+mountDir)
}

func TestIntegration_SymlinkPathResolution_WriteOperationThroughSymlinkWithinMount(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	mountDir := filepath.Join(absTestDir, "mount")
	linkPath := filepath.Join(mountDir, "link.txt")
	realPath := filepath.Join(mountDir, "real.txt")

	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	require.NoError(t, os.WriteFile(realPath, []byte("original"), 0o600))
	require.NoError(t, os.Symlink(realPath, linkPath))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{rwRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	exitCode, err := env.run([]string{"sh", "-c", "echo new > " + linkPath})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	// Hop is READ, target is WRITE
	assertLogContainsLine(t, logStr, "READ", linkPath, "OK", "fs:rw:"+mountDir)
	assertLogContainsLine(t, logStr, "WRITE", realPath, "OK", "fs:rw:"+mountDir)
}

func TestIntegration_SymlinkPathResolution_WriteThroughSymlinkToReadOnlyTargetDenied(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	rwDir := filepath.Join(absTestDir, "writable")
	roDir := filepath.Join(absTestDir, "readonly")
	linkPath := filepath.Join(rwDir, "link.txt")
	targetPath := filepath.Join(roDir, "target.txt")

	require.NoError(t, os.MkdirAll(rwDir, 0o750))
	require.NoError(t, os.MkdirAll(roDir, 0o750))
	require.NoError(t, os.WriteFile(targetPath, []byte("readonly"), 0o600))
	require.NoError(t, os.Symlink(targetPath, linkPath))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{rwRule(rwDir), roRule(roDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	// Without bwrap, the write succeeds on the filesystem, but the monitor
	// logs the denial based on rule evaluation
	_, _ = env.run([]string{"sh", "-c", "echo new > " + linkPath})

	logStr := env.readLog()
	assertLogContainsLine(t, logStr, "READ", linkPath, "OK", "fs:rw:"+rwDir)
	assertLogContainsLine(t, logStr, "WRITE", targetPath, "DENY", "fs:ro:"+roDir)
}

func TestIntegration_SymlinkPathResolution_WriteThroughReadOnlySymlinkToWritableTargetAllowed(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	roDir := filepath.Join(absTestDir, "readonly")
	rwDir := filepath.Join(absTestDir, "writable")
	linkPath := filepath.Join(roDir, "link.txt")
	targetPath := filepath.Join(rwDir, "file.txt")

	require.NoError(t, os.MkdirAll(roDir, 0o750))
	require.NoError(t, os.MkdirAll(rwDir, 0o750))
	require.NoError(t, os.WriteFile(targetPath, []byte("original"), 0o600))
	require.NoError(t, os.Symlink(targetPath, linkPath))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(roDir), rwRule(rwDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	exitCode, err := env.run([]string{"sh", "-c", "echo new > " + linkPath})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	assertLogContainsLine(t, logStr, "READ", linkPath, "OK", "fs:ro:"+roDir)
	assertLogContainsLine(t, logStr, "WRITE", targetPath, "OK", "fs:rw:"+rwDir)
}

func TestIntegration_SymlinkPathResolution_SymlinkDepthLimitExceeded(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	mountDir := filepath.Join(absTestDir, "mount")
	loopA := filepath.Join(mountDir, "loop-a")
	loopB := filepath.Join(mountDir, "loop-b")

	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	require.NoError(t, os.Symlink(loopB, loopA))
	require.NoError(t, os.Symlink(loopA, loopB))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	_, _ = env.run([]string{"cat", loopA})

	logStr := env.readLog()
	// Should contain depth-limit denial
	assertLogContainsLine(t, logStr, "READ", "DENY", "symlink-depth-limit-exceeded")
}

func TestIntegration_SymlinkPathResolution_ResolvedSymlinkPathsDeduplicated(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	mountDir := filepath.Join(absTestDir, "mount")
	link1 := filepath.Join(mountDir, "link1")
	link2 := filepath.Join(mountDir, "link2")
	target := filepath.Join(mountDir, "target.txt")

	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	require.NoError(t, os.WriteFile(target, []byte("target content"), 0o600))
	require.NoError(t, os.Symlink(target, link1))
	require.NoError(t, os.Symlink(target, link2))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	exitCode, err := env.run([]string{"sh", "-c", "cat " + link1 + " && cat " + link2})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	// Both symlinks and the target should be logged
	assertLogContainsLine(t, logStr, "READ", link1, "OK")
	assertLogContainsLine(t, logStr, "READ", link2, "OK")
	assertLogContainsLine(t, logStr, "READ", target, "OK")

	// Target should appear exactly once (deduplicated)
	targetCount := strings.Count(logStr, target)
	assert.Equal(t, 1, targetCount)
}

func TestIntegration_SymlinkPathResolution_SymlinkThroughManagedPathLoggedAsUnknown(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	mountDir := filepath.Join(absTestDir, "mount")
	managedDir := filepath.Join(absTestDir, "managed")
	linkPath := filepath.Join(mountDir, "link.txt")
	managedTarget := filepath.Join(managedDir, "target.txt")

	require.NoError(t, os.MkdirAll(mountDir, 0o750))
	require.NoError(t, os.MkdirAll(managedDir, 0o750))
	require.NoError(t, os.WriteFile(managedTarget, []byte("data"), 0o600))
	require.NoError(t, os.Symlink(managedTarget, linkPath))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{rwRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: []string{managedDir},
		}
	})

	_, _ = env.run([]string{"cat", linkPath})

	logStr := env.readLog()
	assertLogContainsLine(t, logStr, "READ", linkPath, "UNKNOWN", "symlink-target-unresolvable")
}

// --- Requirement: Non-existent path filtering for reads ---

func TestIntegration_NonExistentPathFiltering_NonExistentReadFilteredFromLog(t *testing.T) {
	testNonExistentPathFiltering(t, "noexist.txt")
}

func TestIntegration_NonExistentPathFiltering_NonExistentPathNotResolved(t *testing.T) {
	testNonExistentPathFiltering(t, "does-not-exist.txt")
}

func testNonExistentPathFiltering(t *testing.T, filename string) {
	t.Helper()

	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	mountDir := filepath.Join(absTestDir, "mount")
	nonExistent := filepath.Join(mountDir, filename)

	require.NoError(t, os.MkdirAll(mountDir, 0o750))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(mountDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	_, _ = env.run([]string{"cat", nonExistent})

	logStr := env.readLog()
	assert.NotContains(t, logStr, nonExistent)
}

func TestIntegration_NonExistentPathFiltering_StatErrorStillLogged(t *testing.T) {
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	restrictedDir := filepath.Join(absTestDir, "restricted")
	restrictedFile := filepath.Join(restrictedDir, "secret.txt")

	require.NoError(t, os.MkdirAll(restrictedDir, 0o750))
	require.NoError(t, os.WriteFile(restrictedFile, []byte("secret"), 0o600))

	// Remove permissions to trigger EACCES on stat
	require.NoError(t, os.Chmod(restrictedDir, 0o000))
	t.Cleanup(func() {
		_ = os.Chmod(restrictedDir, 0o700) //nolint:gosec // G302: need execute bit for cleanup
		_ = os.RemoveAll(restrictedDir)
	})

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(absTestDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	_, _ = env.run([]string{"cat", restrictedFile})

	logStr := env.readLog()
	// Fail-safe: EACCES is not ENOENT, so the path should be logged
	assertLogContainsLine(t, logStr, "READ", restrictedFile, "DENY")
}

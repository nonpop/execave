package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_Monitor_MonitorDisabledByDefault tests that monitoring is disabled by default.
func TestE2E_Monitor_MonitorDisabledByDefault(t *testing.T) {
	failIfNoBwrap(t)

	workDir := testTempDir(t)
	writeConfigInDir(t, workDir, systemPaths())

	logPath := filepath.Join(workDir, "execave-access.log")

	result := runExecave(t, workDir, "--", "true")
	assertExitCode(t, result, 0)

	assertLogNotExists(t, logPath)
}

// TestE2E_Monitor_MonitorEnabled tests that --monitor enables monitoring and writes
// the access log to the default path (./execave-access.log).
func TestE2E_Monitor_MonitorEnabled(t *testing.T) {
	failIfNoStrace(t)

	workDir := testTempDir(t)
	writeConfigInDir(t, workDir, systemPaths())

	// Default log path: ./execave-access.log relative to working directory
	logPath := filepath.Join(workDir, "execave-access.log")

	result := runExecave(t, workDir, "--monitor", "--", "true")
	assertExitCode(t, result, 0)

	assertLogExists(t, logPath)
}

// TestE2E_Monitor_CustomLogPath tests that --monitor=<path> creates a log at the specified path.
func TestE2E_Monitor_CustomLogPath(t *testing.T) {
	failIfNoStrace(t)

	workDir := testTempDir(t)
	writeConfigInDir(t, workDir, systemPaths())

	customLogPath := filepath.Join(workDir, "custom-access.log")

	result := runExecave(t, workDir, "--monitor="+customLogPath, "--", "true")
	assertExitCode(t, result, 0)

	assertLogExists(t, customLogPath)
}

// TestE2E_Monitor_AllowedReadLogged tests that allowed reads are logged with OK.
func TestE2E_Monitor_AllowedReadLogged(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")
	createFile(t, testFile, "content")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	result := env.runMonitored(t, rules, "cat", testFile)
	assertExitCode(t, result, 0)

	assertLogLineContainsAll(t, env.LogPath, "READ", testFile, "OK", "fs:ro:"+env.TmpDir)
}

// TestE2E_Monitor_DeniedWriteLogged tests that denied writes are logged with DENY.
func TestE2E_Monitor_DeniedWriteLogged(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	// Write will fail because sandbox enforces read-only
	result := env.runMonitored(t, rules, "sh", "-c", "echo test > "+testFile)
	assert.NotEqual(t, 0, result.ExitCode)

	assertLogLineContainsAll(t, env.LogPath, "WRITE", testFile, "DENY", "fs:ro:"+env.TmpDir)
}

// TestE2E_Monitor_NoAccessRuleLogged tests that access to fs:none paths is logged with DENY.
func TestE2E_Monitor_NoAccessRuleLogged(t *testing.T) {
	env := newMonitorTest(t)

	secretFile := filepath.Join(env.TmpDir, "secret.txt")
	createFile(t, secretFile, "secret")

	rules := append(systemPaths(), "fs:none:"+secretFile)

	// Read will fail because sandbox blocks fs:none paths
	result := env.runMonitored(t, rules, "cat", secretFile)
	assert.NotEqual(t, 0, result.ExitCode)

	assertLogLineContainsAll(t, env.LogPath, "READ", secretFile, "DENY", "fs:none:"+secretFile)
}

// TestE2E_Monitor_NoMatchingRuleLogged tests that access without matching rule is logged.
func TestE2E_Monitor_NoMatchingRuleLogged(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")
	createFile(t, testFile, "content")

	// System paths allowed but not our test file's directory
	result := env.runMonitored(t, systemPaths(), "cat", testFile)
	assert.NotEqual(t, 0, result.ExitCode)

	assertLogLineContainsAll(t, env.LogPath, "READ", testFile, "DENY", "no-matching-rule")
}

// TestE2E_Monitor_UnresolvedRelativePathLogged is a placeholder for the
// "Unresolved relative path logged" spec scenario. I couldn't find a way to trigger it. Covered by unit test with synthetic data.
func TestE2E_Monitor_UnresolvedRelativePathLogged(*testing.T) {}

// TestE2E_Monitor_QueryingFileMetadataLoggedAsRead tests that querying file metadata is logged as READ.
func TestE2E_Monitor_QueryingFileMetadataLoggedAsRead(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")
	createFile(t, testFile, "content")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	// stat queries file metadata without reading contents
	result := env.runMonitored(t, rules, "stat", testFile)
	assertExitCode(t, result, 0)

	assertLogLineContainsAll(t, env.LogPath, "READ", testFile, "OK", "fs:ro:"+env.TmpDir)
}

// TestE2E_Monitor_CreatingDirectoryLoggedAsWrite tests that creating a directory is logged as WRITE.
func TestE2E_Monitor_CreatingDirectoryLoggedAsWrite(t *testing.T) {
	env := newMonitorTest(t)

	newDir := filepath.Join(env.TmpDir, "newdir")

	rules := append(systemPaths(), "fs:rw:"+env.TmpDir)

	result := env.runMonitored(t, rules, "mkdir", newDir)
	assertExitCode(t, result, 0)

	assertLogLineContainsAll(t, env.LogPath, "WRITE", newDir, "OK", "fs:rw:"+env.TmpDir)
}

// TestE2E_Monitor_RepeatedReadsDeduplicated tests that repeated reads are deduplicated.
func TestE2E_Monitor_RepeatedReadsDeduplicated(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")
	createFile(t, testFile, "content")

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	// Read the same file 3 times
	result := env.runMonitored(t, rules,
		"sh", "-c", "cat "+testFile+" && cat "+testFile+" && cat "+testFile)
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	// Specifically check that the test file appears only once with READ
	lines := 0
	for line := range strings.SplitSeq(logContent, "\n") {
		if strings.Contains(line, "READ") && strings.Contains(line, testFile) {
			lines++
		}
	}
	// Should be deduplicated to 1 entry
	assert.Equal(t, 1, lines)
}

// TestE2E_Monitor_ReadAndWriteBothLogged tests that read and write to same file are both logged.
func TestE2E_Monitor_ReadAndWriteBothLogged(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")
	createFile(t, testFile, "initial")

	rules := append(systemPaths(), "fs:rw:"+env.TmpDir)

	// Read then write to same file
	result := env.runMonitored(t, rules,
		"sh", "-c", "cat "+testFile+" && echo 'more' >> "+testFile)
	assertExitCode(t, result, 0)

	// Should have both READ and WRITE entries
	assertLogLineContainsAll(t, env.LogPath, "READ", testFile)
	assertLogLineContainsAll(t, env.LogPath, "WRITE", testFile)
}

// TestE2E_Monitor_RepeatedWritesDeduplicated tests that repeated writes are deduplicated.
func TestE2E_Monitor_RepeatedWritesDeduplicated(t *testing.T) {
	env := newMonitorTest(t)

	testFile := filepath.Join(env.TmpDir, "test.txt")

	rules := append(systemPaths(), "fs:rw:"+env.TmpDir)

	// Write to same file 3 times
	result := env.runMonitored(t, rules,
		"sh", "-c", "echo a > "+testFile+" && echo b >> "+testFile+" && echo c >> "+testFile)
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	// Should only have 1 WRITE entry for this file (deduplicated)
	lines := 0
	for line := range strings.SplitSeq(logContent, "\n") {
		if strings.Contains(line, "WRITE") && strings.Contains(line, testFile) {
			lines++
		}
	}
	// Should be deduplicated to 1 entry
	assert.Equal(t, 1, lines)
}

// TestE2E_Monitor_InfrastructurePathsNotLogged tests that infrastructure paths are not logged.
func TestE2E_Monitor_InfrastructurePathsNotLogged(t *testing.T) {
	env := newMonitorTest(t)

	// Run a command that accesses infrastructure paths
	// bash will access /proc, /dev/tty, etc.
	result := env.runMonitored(t, systemPaths(), "bash", "-c", "exit 0")
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	// Infrastructure paths should NOT be in the log
	assert.NotContains(t, logContent, "/proc")
	assert.NotContains(t, logContent, "/dev")
	assert.NotContains(t, logContent, "newroot")
	assert.NotContains(t, logContent, "uid_map")

	// System paths should still be logged
	assert.Contains(t, logContent, "/usr/")
}

// TestE2E_Monitor_InfrastructureWritesNotLogged tests that writes to infrastructure paths are not logged.
func TestE2E_Monitor_InfrastructureWritesNotLogged(t *testing.T) {
	env := newMonitorTest(t)

	// Run a command that writes to /dev/tty (or /dev/null as fallback)
	result := env.runMonitored(t, systemPaths(), "sh", "-c", "echo test > /dev/null")
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	// Writes to /dev should NOT be in the log
	assert.NotContains(t, logContent, "/dev/")
}

// TestE2E_Monitor_FilesystemPathsStillLogged tests that only user-controlled filesystem paths are logged.
func TestE2E_Monitor_FilesystemPathsStillLogged(t *testing.T) {
	env := newMonitorTest(t)

	result := env.runMonitored(t, systemPaths(), "bash", "-c", "exit 0")
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	assert.Contains(t, logContent, "/usr/")
}

// TestE2E_Monitor_SandboxSetupPathsNotLogged tests that sandbox setup paths are not logged.
func TestE2E_Monitor_SandboxSetupPathsNotLogged(t *testing.T) {
	env := newMonitorTest(t)

	// Run a simple command - sandbox setup will perform internal operations
	result := env.runMonitored(t, systemPaths(), "true")
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	// Sandbox setup paths should NOT be in the log (no leading slash to catch
	// both absolute "/newroot" and relative "newroot" forms from bwrap)
	assert.NotContains(t, logContent, "newroot")
	assert.NotContains(t, logContent, "oldroot")
	assert.NotContains(t, logContent, "uid_map")
	assert.NotContains(t, logContent, "gid_map")
	assert.NotContains(t, logContent, "setgroups")
	assert.NotContains(t, logContent, "self/fd")
	assert.NotContains(t, logContent, "self/mountinfo")
}

// TestE2E_Monitor_NamespaceOperationsNotLogged tests that namespace operations are not logged.
func TestE2E_Monitor_NamespaceOperationsNotLogged(t *testing.T) {
	env := newMonitorTest(t)

	// Run a simple command - sandbox setup will perform internal operations
	result := env.runMonitored(t, systemPaths(), "true")
	assertExitCode(t, result, 0)

	logContent := env.readLog(t)

	assert.NotContains(t, logContent, "/ns/")
}

// TestE2E_Monitor_AccessLogWrittenAfterChildTerminatedBySIGINT tests that the access log
// is written even when the child process is terminated by SIGINT (ctrl-c).
func TestE2E_Monitor_AccessLogWrittenAfterChildTerminatedBySIGINT(t *testing.T) {
	env := newMonitorTest(t)

	// Start execave with --monitor and a long-running command
	// We'll send SIGINT to the process group after a short delay
	result := env.runMonitoredWithInterrupt(t, systemPaths(), "sleep", "60")

	// Exit code should be 130 (128 + SIGINT=2)
	assertExitCode(t, result, 130)

	// Access log should exist and contain entries
	assertLogExists(t, env.LogPath)

	// The log should have at least system path accesses
	logContent := env.readLog(t)
	assert.NotEmpty(t, logContent)
}

// Symlink resolution tests

// TestE2E_Monitor_RuleBoundarySymlinkLoggedWithoutResolution tests that symlinks matching
// rule paths exactly are logged without resolution.
func TestE2E_Monitor_RuleBoundarySymlinkLoggedWithoutResolution(t *testing.T) {
	env := newMonitorTest(t)

	linkFile := filepath.Join(env.TmpDir, "link-file")
	targetFile := filepath.Join(env.TmpDir, "target-file")

	createFile(t, targetFile, "target content")
	createSymlink(t, targetFile, linkFile)

	rules := append(systemPaths(), "fs:ro:"+linkFile)

	result := env.runMonitored(t, rules, "cat", linkFile)
	assertExitCode(t, result, 0)
	assert.Equal(t, "target content", result.Stdout)

	assertLogLineContainsAll(t, env.LogPath, "READ", linkFile, "OK", "fs:ro:"+linkFile)

	logContent := env.readLog(t)
	// Target should NOT be in log - bwrap resolves at mount time
	assert.NotContains(t, logContent, targetFile)
}

// TestE2E_Monitor_RuleBoundarySymlinkInIntermediateComponentLoggedWithoutResolution
// tests that intermediate directory symlinks matching rule paths are not resolved.
func TestE2E_Monitor_RuleBoundarySymlinkInIntermediateComponentLoggedWithoutResolution(t *testing.T) {
	env := newMonitorTest(t)

	realDir := filepath.Join(env.TmpDir, "real-dir")
	linkDir := filepath.Join(env.TmpDir, "link-dir")
	targetFile := filepath.Join(realDir, "file.txt")

	createFile(t, targetFile, "target content")
	createSymlink(t, realDir, linkDir)

	rules := append(systemPaths(), "fs:ro:"+linkDir)

	linkPath := filepath.Join(linkDir, "file.txt")
	result := env.runMonitored(t, rules, "cat", linkPath)
	assertExitCode(t, result, 0)
	assert.Equal(t, "target content", result.Stdout)

	assertLogLineContainsAll(t, env.LogPath, "READ", linkPath, "OK", "fs:ro:"+linkDir)

	logContent := env.readLog(t)
	// Real path should NOT be in log
	assert.NotContains(t, logContent, targetFile)
}

// TestE2E_Monitor_SymlinkWithinMountResolvedAndLogged tests that symlinks within
// a mounted directory are resolved and both hop and target are logged.
func TestE2E_Monitor_SymlinkWithinMountResolvedAndLogged(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	linkPath := filepath.Join(mountDir, "link.txt")
	targetPath := filepath.Join(mountDir, "target.txt")

	createFile(t, targetPath, "target content")
	createSymlink(t, targetPath, linkPath)

	rules := append(systemPaths(), "fs:ro:"+mountDir)

	result := env.runMonitored(t, rules, "cat", linkPath)
	assertExitCode(t, result, 0)
	assert.Equal(t, "target content", result.Stdout)

	// Both hop and target should be logged
	assertLogLineContainsAll(t, env.LogPath, "READ", linkPath, "OK", "fs:ro:"+mountDir)
	assertLogLineContainsAll(t, env.LogPath, "READ", targetPath, "OK", "fs:ro:"+mountDir)
}

// TestE2E_Monitor_RelativeSymlinkWithinMountResolvedAndLogged tests that relative
// symlinks within a mount are resolved and both hop and target are logged.
func TestE2E_Monitor_RelativeSymlinkWithinMountResolvedAndLogged(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	linkPath := filepath.Join(mountDir, "link.txt")
	targetPath := filepath.Join(mountDir, "target.txt")

	createFile(t, targetPath, "target content")
	// Create relative symlink (not absolute path)
	require.NoError(t, os.Symlink("target.txt", linkPath))

	rules := append(systemPaths(), "fs:ro:"+mountDir)

	result := env.runMonitored(t, rules, "cat", linkPath)
	assertExitCode(t, result, 0)
	assert.Equal(t, "target content", result.Stdout)

	// Both hop and target should be logged
	assertLogLineContainsAll(t, env.LogPath, "READ", linkPath, "OK", "fs:ro:"+mountDir)
	assertLogLineContainsAll(t, env.LogPath, "READ", targetPath, "OK", "fs:ro:"+mountDir)
}

// TestE2E_Monitor_RelativeSymlinkChainResolvedAndLogged tests that a chain of
// relative symlinks is fully resolved with all hops logged in order.
func TestE2E_Monitor_RelativeSymlinkChainResolvedAndLogged(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	linkPath := filepath.Join(mountDir, "link")
	hop2Path := filepath.Join(mountDir, "hop2")
	finalPath := filepath.Join(mountDir, "final.txt")

	createFile(t, finalPath, "final content")
	// Create relative symlink chain: link -> hop2 -> final.txt
	require.NoError(t, os.Symlink("final.txt", hop2Path))
	require.NoError(t, os.Symlink("hop2", linkPath))

	rules := append(systemPaths(), "fs:ro:"+mountDir)

	result := env.runMonitored(t, rules, "cat", linkPath)
	assertExitCode(t, result, 0)
	assert.Equal(t, "final content", result.Stdout)

	// All hops and final target should be logged
	assertLogLineContainsAll(t, env.LogPath, "READ", linkPath, "OK", "fs:ro:"+mountDir)
	assertLogLineContainsAll(t, env.LogPath, "READ", hop2Path, "OK", "fs:ro:"+mountDir)
	assertLogLineContainsAll(t, env.LogPath, "READ", finalPath, "OK", "fs:ro:"+mountDir)
}

// TestE2E_Monitor_SymlinkWithinMountPointingOutsideRulesDenied tests that symlinks
// within a mount pointing to paths outside any rule are denied.
func TestE2E_Monitor_SymlinkWithinMountPointingOutsideRulesDenied(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	outsideDir := filepath.Join(env.TmpDir, "outside")
	escapeLink := filepath.Join(mountDir, "escape.txt")
	secretFile := filepath.Join(outsideDir, "secret.txt")

	createFile(t, secretFile, "secret")
	createSymlink(t, secretFile, escapeLink)

	rules := append(systemPaths(), "fs:ro:"+mountDir)

	result := env.runMonitored(t, rules, "cat", escapeLink)
	assertExitCode(t, result, 1) // Should fail
	assert.Contains(t, result.Stderr, "escape.txt: No such file")

	// Hop should be OK, target should be denied
	assertLogLineContainsAll(t, env.LogPath, "READ", escapeLink, "OK", "fs:ro:"+mountDir)
	assertLogLineContainsAll(t, env.LogPath, "READ", secretFile, "DENY", "no-matching-rule")
}

// TestE2E_Monitor_MultiHopSymlinkChainWithinMount tests that multi-hop symlink chains
// within a mount are fully logged.
func TestE2E_Monitor_MultiHopSymlinkChainWithinMount(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	hop1 := filepath.Join(mountDir, "hop1")
	hop2 := filepath.Join(mountDir, "hop2")
	final := filepath.Join(mountDir, "final.txt")

	createFile(t, final, "final content")
	createSymlink(t, final, hop2)
	createSymlink(t, hop2, hop1)

	rules := append(systemPaths(), "fs:ro:"+mountDir)

	result := env.runMonitored(t, rules, "cat", hop1)
	assertExitCode(t, result, 0)
	assert.Equal(t, "final content", result.Stdout)

	// All hops and final target should be logged
	assertLogLineContainsAll(t, env.LogPath, "READ", hop1, "OK", "fs:ro:"+mountDir)
	assertLogLineContainsAll(t, env.LogPath, "READ", hop2, "OK", "fs:ro:"+mountDir)
	assertLogLineContainsAll(t, env.LogPath, "READ", final, "OK", "fs:ro:"+mountDir)
}

// TestE2E_Monitor_MultiHopChainBreaksAtDeniedIntermediateHop tests that symlink chains
// stop at a denied intermediate hop.
func TestE2E_Monitor_MultiHopChainBreaksAtDeniedIntermediateHop(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	nomatchDir := filepath.Join(env.TmpDir, "nomatch")
	hop1 := filepath.Join(mountDir, "hop1")
	hop2 := filepath.Join(nomatchDir, "hop2")
	final := filepath.Join(mountDir, "final.txt")

	createFile(t, final, "final content")
	createSymlink(t, final, hop2)
	createSymlink(t, hop2, hop1)

	rules := append(systemPaths(), "fs:ro:"+mountDir)

	result := env.runMonitored(t, rules, "cat", hop1)
	assertExitCode(t, result, 1) // Should fail
	assert.Contains(t, result.Stderr, "hop1: No such file")

	// First hop OK, second hop denied
	assertLogLineContainsAll(t, env.LogPath, "READ", hop1, "OK", "fs:ro:"+mountDir)
	assertLogLineContainsAll(t, env.LogPath, "READ", hop2, "DENY", "no-matching-rule")

	logContent := env.readLog(t)
	// Final target should NOT be logged
	assert.NotContains(t, logContent, final)
}

// TestE2E_Monitor_SymlinkInIntermediatePathComponentResolved tests that symlinks
// in intermediate path components are resolved.
func TestE2E_Monitor_SymlinkInIntermediatePathComponentResolved(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	realSubdir := filepath.Join(mountDir, "real-subdir")
	linkSubdir := filepath.Join(mountDir, "link-subdir")
	targetFile := filepath.Join(realSubdir, "file.txt")

	createFile(t, targetFile, "target content")
	createSymlink(t, realSubdir, linkSubdir)

	rules := append(systemPaths(), "fs:ro:"+mountDir)

	linkPath := filepath.Join(linkSubdir, "file.txt")
	result := env.runMonitored(t, rules, "cat", linkPath)
	assertExitCode(t, result, 0)
	assert.Equal(t, "target content", result.Stdout)

	// Symlink hop and final path should be logged
	assertLogLineContainsAll(t, env.LogPath, "READ", linkSubdir, "OK", "fs:ro:"+mountDir)
	assertLogLineContainsAll(t, env.LogPath, "READ", targetFile, "OK", "fs:ro:"+mountDir)
}

// TestE2E_Monitor_WriteOperationThroughSymlinkWithinMount tests that write operations
// through symlinks log the hop as READ and the target as WRITE.
func TestE2E_Monitor_WriteOperationThroughSymlinkWithinMount(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	linkPath := filepath.Join(mountDir, "link.txt")
	realPath := filepath.Join(mountDir, "real.txt")

	createFile(t, realPath, "original content")
	createSymlink(t, realPath, linkPath)

	rules := append(systemPaths(), "fs:rw:"+mountDir)

	result := env.runMonitored(t, rules, "sh", "-c", "echo new > "+linkPath)
	assertExitCode(t, result, 0)

	// Verify the write succeeded
	data, err := os.ReadFile(realPath) // #nosec G304 -- test code reading controlled test files
	require.NoError(t, err)
	assert.Equal(t, "new\n", string(data))

	// Hop is READ, target is WRITE
	assertLogLineContainsAll(t, env.LogPath, "READ", linkPath, "OK", "fs:rw:"+mountDir)
	assertLogLineContainsAll(t, env.LogPath, "WRITE", realPath, "OK", "fs:rw:"+mountDir)
}

// TestE2E_Monitor_WriteThroughSymlinkToReadOnlyTargetDenied tests that writing through
// a symlink to a read-only target is denied.
func TestE2E_Monitor_WriteThroughSymlinkToReadOnlyTargetDenied(t *testing.T) {
	env := newMonitorTest(t)

	rwDir := filepath.Join(env.TmpDir, "writable")
	roDir := filepath.Join(env.TmpDir, "readonly")
	linkPath := filepath.Join(rwDir, "link.txt")
	targetPath := filepath.Join(roDir, "target.txt")

	createFile(t, targetPath, "readonly content")
	createSymlink(t, targetPath, linkPath)

	rules := append(systemPaths(), "fs:rw:"+rwDir, "fs:ro:"+roDir)

	result := env.runMonitored(t, rules, "sh", "-c", "echo new > "+linkPath)
	assertExitCode(t, result, 1) // Should fail
	assert.Contains(t, result.Stderr, "link.txt: Read-only file system")

	// Hop OK (read), target denied (write to ro)
	assertLogLineContainsAll(t, env.LogPath, "READ", linkPath, "OK", "fs:rw:"+rwDir)
	assertLogLineContainsAll(t, env.LogPath, "WRITE", targetPath, "DENY", "fs:ro:"+roDir)
}

// TestE2E_Monitor_WriteThroughReadOnlySymlinkToWritableTargetAllowed tests that writing
// through a symlink in a read-only directory to a writable target succeeds.
func TestE2E_Monitor_WriteThroughReadOnlySymlinkToWritableTargetAllowed(t *testing.T) {
	env := newMonitorTest(t)

	roDir := filepath.Join(env.TmpDir, "readonly")
	rwDir := filepath.Join(env.TmpDir, "writable")
	linkPath := filepath.Join(roDir, "link.txt")
	targetPath := filepath.Join(rwDir, "file.txt")

	createFile(t, targetPath, "original content")
	createSymlink(t, targetPath, linkPath)

	rules := append(systemPaths(), "fs:ro:"+roDir, "fs:rw:"+rwDir)

	result := env.runMonitored(t, rules, "sh", "-c", "echo new > "+linkPath)
	assertExitCode(t, result, 0)

	// Verify the write succeeded
	data, err := os.ReadFile(targetPath) // #nosec G304 -- test code reading controlled test files
	require.NoError(t, err)
	assert.Equal(t, "new\n", string(data))

	// Hop is READ (symlink in ro dir), target is WRITE (in rw dir)
	assertLogLineContainsAll(t, env.LogPath, "READ", linkPath, "OK", "fs:ro:"+roDir)
	assertLogLineContainsAll(t, env.LogPath, "WRITE", targetPath, "OK", "fs:rw:"+rwDir)
}

// TestE2E_Monitor_SymlinkDepthLimitExceeded tests that symlink loops are detected
// and denied.
func TestE2E_Monitor_SymlinkDepthLimitExceeded(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	loopA := filepath.Join(mountDir, "loop-a")
	loopB := filepath.Join(mountDir, "loop-b")

	createSymlink(t, loopB, loopA)
	createSymlink(t, loopA, loopB)

	rules := append(systemPaths(), "fs:ro:"+mountDir)

	result := env.runMonitored(t, rules, "cat", loopA)
	assertExitCode(t, result, 1) // Should fail
	assert.Contains(t, result.Stderr, "loop-a: Too many levels of symbolic links")

	// Reads the hops successfully until limit exceeded. One successful entry for each hop
	// (deduplicated), then DENY with depth-limit reason when limit exceeded.
	assertLogLineContainsAll(t, env.LogPath, "READ", loopA, "OK", "fs:ro:"+mountDir)
	assertLogLineContainsAll(t, env.LogPath, "READ", loopB, "OK", "fs:ro:"+mountDir)
	// The 40th hop (where limit is exceeded) could be either loop-a or loop-b depending on
	// which one we started with. We started with loop-a, so the 40th hop is loop-b.
	assertLogLineContainsAll(t, env.LogPath, "READ", loopB, "DENY", "symlink-depth-limit-exceeded")
}

// TestE2E_Monitor_ResolvedSymlinkPathsDeduplicated tests that multiple symlinks to the
// same target only log the target once.
func TestE2E_Monitor_ResolvedSymlinkPathsDeduplicated(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	link1 := filepath.Join(mountDir, "link1")
	link2 := filepath.Join(mountDir, "link2")
	target := filepath.Join(mountDir, "target.txt")

	createFile(t, target, "target content")
	createSymlink(t, target, link1)
	createSymlink(t, target, link2)

	rules := append(systemPaths(), "fs:ro:"+mountDir)

	result := env.runMonitored(t, rules, "sh", "-c", "cat "+link1+" && cat "+link2)
	assertExitCode(t, result, 0)
	// Should print the content twice (once for each cat)
	assert.Equal(t, "target contenttarget content", result.Stdout)

	logContent := env.readLog(t)

	// Both symlinks should be logged
	assertLogLineContainsAll(t, env.LogPath, "READ", link1, "OK", "fs:ro:"+mountDir)
	assertLogLineContainsAll(t, env.LogPath, "READ", link2, "OK", "fs:ro:"+mountDir)
	assertLogLineContainsAll(t, env.LogPath, "READ", target, "OK", "fs:ro:"+mountDir)

	// Target should appear exactly once in log (deduplicated)
	targetCount := strings.Count(logContent, target)
	assert.Equal(t, 1, targetCount)
}

// TestE2E_Monitor_SymlinkThroughManagedPathLoggedAsUnknown tests that symlinks pointing
// into managed paths (e.g., /tmp tmpfs) are logged as UNKNOWN since the host-side resolver
// cannot see the sandbox's tmpfs contents.
func TestE2E_Monitor_SymlinkThroughManagedPathLoggedAsUnknown(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	linkPath := filepath.Join(mountDir, "link.txt")

	// Symlink points into /tmp, which is a managed tmpfs inside the sandbox.
	// The target doesn't exist on the sandbox's tmpfs, so cat fails.
	createSymlink(t, "/tmp/target.txt", linkPath)

	rules := append(systemPaths(), "fs:rw:"+mountDir)

	result := env.runMonitored(t, rules, "cat", linkPath)
	assertExitCode(t, result, 1) // Fails: /tmp/target.txt doesn't exist on sandbox tmpfs

	// Resolver detects symlink target is under managed /tmp — logs UNKNOWN
	assertLogLineContainsAll(t, env.LogPath, "READ", linkPath, "UNKNOWN", "symlink-target-unresolvable")
}

// TestE2E_Monitor_NonExistentPathFilteredFromLog tests that non-existent paths are filtered
// from the access log to reduce noise.
func TestE2E_Monitor_NonExistentPathFilteredFromLog(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	nonExistent := filepath.Join(mountDir, "noexist.txt")

	// Create mount directory but not the file
	err := os.MkdirAll(mountDir, 0o750)
	require.NoError(t, err)

	rules := append(systemPaths(), "fs:ro:"+mountDir)

	result := env.runMonitored(t, rules, "cat", nonExistent)
	assertExitCode(t, result, 1) // Should fail (file doesn't exist)
	assert.Contains(t, result.Stderr, "noexist.txt: No such file")

	// Non-existent path should NOT be in the log
	logContent := env.readLog(t)
	assert.NotContains(t, logContent, nonExistent)
}

// TestE2E_Monitor_NonExistentPathNotResolved tests that non-existent paths are not
// resolved as symlinks.
func TestE2E_Monitor_NonExistentPathNotResolved(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	nonExistent := filepath.Join(mountDir, "does-not-exist.txt")

	// Create mount directory but not the file
	err := os.MkdirAll(mountDir, 0o750)
	require.NoError(t, err)

	rules := append(systemPaths(), "fs:ro:"+mountDir)

	result := env.runMonitored(t, rules, "cat", nonExistent)
	assertExitCode(t, result, 1) // Should fail (file doesn't exist)
	assert.Contains(t, result.Stderr, "does-not-exist.txt: No such file")

	// Non-existent path should NOT be in the log
	logContent := env.readLog(t)
	assert.NotContains(t, logContent, nonExistent)
}

// TestE2E_Monitor_StatErrorStillLogged tests that non-ENOENT stat errors (permission
// denied, I/O errors) result in logging (fail-safe behavior).
func TestE2E_Monitor_StatErrorStillLogged(t *testing.T) {
	env := newMonitorTest(t)

	// Create a directory with restricted permissions to trigger permission denied
	restrictedDir := filepath.Join(env.TmpDir, "restricted")
	err := os.MkdirAll(restrictedDir, 0o750)
	require.NoError(t, err)

	restrictedFile := filepath.Join(restrictedDir, "secret.txt")
	createFile(t, restrictedFile, "secret")

	// Remove all permissions on the directory to prevent stat access from monitor
	err = os.Chmod(restrictedDir, 0o000)
	require.NoError(t, err)
	defer func() {
		_ = os.Chmod(restrictedDir, 0o700) //nolint:gosec // G302: need execute bit for cleanup
		_ = os.RemoveAll(restrictedDir)
	}()

	rules := append(systemPaths(), "fs:ro:"+env.TmpDir)

	// The sandboxed process can access the file (bwrap mounted it before permission change),
	// but the monitor's os.Stat will fail with permission denied
	_ = env.runMonitored(t, rules, "cat", restrictedFile)
	// May succeed or fail depending on bwrap mount behavior - we don't care about exit code

	// Despite stat error, the path should be logged (fail-safe)
	assertLogLineContainsAll(t, env.LogPath, "READ", restrictedFile, "DENY")
}

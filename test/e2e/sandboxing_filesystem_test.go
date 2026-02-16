package e2e_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_SandboxingFilesystem_RunCommandWithReadOnlySystemAccess tests that the user
// can grant read-only access to system paths and the sandboxed command can read but not write.
func TestE2E_SandboxingFilesystem_RunCommandWithReadOnlySystemAccess(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "data.txt")
	createFile(t, testFile, "hello from sandbox")

	rules := append(systemPaths(), "fs:ro:"+tmpDir)
	configPath := writeConfig(t, rules)

	// Read should succeed
	result := runExecave(t, "", "--config", configPath, "--", "cat", testFile)
	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "hello from sandbox")

	// Write should be denied
	result = runExecave(t, "", "--config", configPath, "--", "sh", "-c", "echo test > "+filepath.Join(tmpDir, "new.txt"))
	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "Read-only file system")
}

// TestE2E_SandboxingFilesystem_RunCommandWithReadWriteProjectAccess tests that the user
// can grant read-write access so the sandboxed command can create and read files.
func TestE2E_SandboxingFilesystem_RunCommandWithReadWriteProjectAccess(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "output.txt")

	rules := append(systemPaths(), "fs:rw:"+tmpDir)
	configPath := writeConfig(t, rules)

	// Write should succeed
	result := runExecave(t, "", "--config", configPath, "--", "sh", "-c", "echo 'written' > "+testFile)
	assertExitCode(t, result, 0)

	// Verify file was written
	data, err := os.ReadFile(testFile) // #nosec G304 -- test code reading controlled test files
	require.NoError(t, err)
	assert.Contains(t, string(data), "written")

	// Read should also succeed
	result = runExecave(t, "", "--config", configPath, "--", "cat", testFile)
	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "written")
}

// TestE2E_SandboxingFilesystem_ProtectSensitiveFilesWithNoAccessRules tests that the user
// can block access to sensitive files within an otherwise accessible directory.
func TestE2E_SandboxingFilesystem_ProtectSensitiveFilesWithNoAccessRules(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	envFile := filepath.Join(tmpDir, ".env")
	normalFile := filepath.Join(tmpDir, "data.txt")
	createFile(t, envFile, "SECRET=password")
	createFile(t, normalFile, "normal data")

	rules := append(systemPaths(),
		"fs:rw:"+tmpDir,
		"fs:none:"+envFile,
	)
	configPath := writeConfig(t, rules)

	// Reading the protected file should be denied
	result := runExecave(t, "", "--config", configPath, "--", "cat", envFile)
	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, ".env: Permission denied")

	// Reading and writing other files should still work
	result = runExecave(t, "", "--config", configPath, "--", "cat", normalFile)
	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "normal data")

	result = runExecave(t, "", "--config", configPath, "--", "sh", "-c", "echo new >> "+normalFile)
	assertExitCode(t, result, 0)
}

// TestE2E_SandboxingFilesystem_OverrideParentRuleWithMoreSpecificChildRule tests that the
// most specific rule wins when rules overlap.
func TestE2E_SandboxingFilesystem_OverrideParentRuleWithMoreSpecificChildRule(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	projDir := filepath.Join(tmpDir, "proj")
	gitDir := filepath.Join(projDir, ".git")
	gitFile := filepath.Join(gitDir, "config")
	srcFile := filepath.Join(projDir, "src", "main.go")

	err := os.MkdirAll(gitDir, 0o750)
	require.NoError(t, err)
	createFile(t, gitFile, "existing")
	createFile(t, srcFile, "package main")

	rules := append(systemPaths(),
		"fs:rw:"+projDir,
		"fs:ro:"+gitDir,
	)
	configPath := writeConfig(t, rules)

	// Writing to .git should be denied (ro child rule overrides rw parent)
	result := runExecave(t, "", "--config", configPath, "--", "sh", "-c", "echo test > "+gitFile)
	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "config: Read-only file system")

	// Reading from .git should succeed
	result = runExecave(t, "", "--config", configPath, "--", "cat", gitFile)
	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "existing")

	// Writing to project/src should succeed (parent rw rule applies)
	result = runExecave(t, "", "--config", configPath, "--", "sh", "-c", "echo 'updated' > "+srcFile)
	assertExitCode(t, result, 0)
}

// TestE2E_SandboxingFilesystem_AccessFilesThroughSymlinksWithAllowedTarget tests that
// symlinks work when both the symlink path and target are permitted.
func TestE2E_SandboxingFilesystem_AccessFilesThroughSymlinksWithAllowedTarget(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	projectDir := filepath.Join(tmpDir, "project")
	targetDir := filepath.Join(tmpDir, "target")
	targetFile := filepath.Join(targetDir, "data.txt")
	linkFile := filepath.Join(projectDir, "data-link")

	err := os.MkdirAll(projectDir, 0o750)
	require.NoError(t, err)
	err = os.MkdirAll(targetDir, 0o750)
	require.NoError(t, err)

	createFile(t, targetFile, "target content")
	createSymlink(t, targetFile, linkFile)

	rules := append(systemPaths(),
		"fs:rw:"+projectDir,
		"fs:ro:"+targetDir,
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--", "cat", linkFile)

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "target content")
}

// TestE2E_SandboxingFilesystem_SymlinkToInaccessibleTargetDenied tests that symlinks
// pointing to paths outside any rule are denied.
func TestE2E_SandboxingFilesystem_SymlinkToInaccessibleTargetDenied(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	secretDir := filepath.Join(tmpDir, "secret")
	secretFile := filepath.Join(secretDir, "data.txt")
	publicDir := filepath.Join(tmpDir, "public")
	linkFile := filepath.Join(publicDir, "link.txt")

	err := os.MkdirAll(secretDir, 0o750)
	require.NoError(t, err)
	err = os.MkdirAll(publicDir, 0o750)
	require.NoError(t, err)

	createFile(t, secretFile, "secret data")
	createSymlink(t, secretFile, linkFile)

	// Allow rw to public but no rule for secret
	rules := append(systemPaths(), "fs:rw:"+publicDir)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--", "cat", linkFile)

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "link.txt: No such file or directory")
}

// TestE2E_SandboxingFilesystem_DefaultDenyForUnmatchedPaths tests that paths not
// matched by any rule are inaccessible.
func TestE2E_SandboxingFilesystem_DefaultDenyForUnmatchedPaths(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "secret.txt")
	createFile(t, testFile, "secret data")

	// System paths let cat execute, but no rule for tmpDir
	configPath := writeConfig(t, systemPaths())

	result := runExecave(t, "", "--config", configPath, "--", "cat", testFile)

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "secret.txt: No such file or directory")
}

// TestE2E_SandboxingFilesystem_NoneDirectoryWithAccessibleChildPath tests that a
// none-directory with a child rule allows access to the child but blocks the parent.
func TestE2E_SandboxingFilesystem_NoneDirectoryWithAccessibleChildPath(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	parentDir := filepath.Join(tmpDir, "parent")
	childDir := filepath.Join(parentDir, "child")
	childFile := filepath.Join(childDir, "data.txt")

	err := os.MkdirAll(childDir, 0o750)
	require.NoError(t, err)
	createFile(t, childFile, "child content")

	rules := append(systemPaths(),
		"fs:rw:"+tmpDir,
		"fs:none:"+parentDir,
		"fs:rw:"+childDir,
	)
	configPath := writeConfig(t, rules)

	// Child file should be accessible
	result := runExecave(t, "", "--config", configPath, "--", "cat", childFile)
	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "child content")

	// Parent listing should be denied
	result = runExecave(t, "", "--config", configPath, "--", "ls", parentDir)
	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "parent': Permission denied")
}

// TestE2E_SandboxingFilesystem_RelativePathsInRulesResolvedRelativeToConfigDirectory tests
// that relative paths in rules are resolved from the config file's directory.
func TestE2E_SandboxingFilesystem_RelativePathsInRulesResolvedRelativeToConfigDirectory(t *testing.T) {
	failIfNoBwrap(t)

	workDir := testTempDir(t)
	srcDir := filepath.Join(workDir, "src")
	err := os.MkdirAll(srcDir, 0o750)
	require.NoError(t, err)

	testFile := filepath.Join(srcDir, "test.txt")
	createFile(t, testFile, "hello")

	rules := append(systemPaths(), "fs:ro:./src")
	writeConfigInDir(t, workDir, rules)

	result := runExecave(t, workDir, "--", "cat", testFile)

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "hello")
}

// TestE2E_SandboxingFilesystem_TUIApplicationsReceiveTerminalResizeSignals tests that
// on modern kernels (Linux 6.2+) where TIOCSTI is blocked, sandboxed TUI applications
// receive SIGWINCH for terminal resize events.
func TestE2E_SandboxingFilesystem_TUIApplicationsReceiveTerminalResizeSignals(t *testing.T) {
	failIfNoBwrap(t)

	// Skip test on old kernels where TIOCSTI is not blocked by default
	data, err := os.ReadFile("/proc/sys/dev/tty/legacy_tiocsti")
	if err != nil {
		t.Skip("skipping: /proc/sys/dev/tty/legacy_tiocsti not available (pre-6.2 kernel)")
	}
	// Trim whitespace and check for "0"
	if strings.TrimSpace(string(data)) != "0" {
		t.Skipf("skipping: TIOCSTI not blocked by kernel (expected '0', got '%s')", strings.TrimSpace(string(data)))
	}

	tmpDir := testTempDir(t)
	signalFile := filepath.Join(tmpDir, "signal-received")
	scriptFile := filepath.Join(tmpDir, "trap-sigwinch.sh")

	// Create a script that traps SIGWINCH and writes to a file, then loops
	script := fmt.Sprintf(`#!/bin/bash
trap 'echo "received" > %[1]s && exit 0' WINCH
# Loop for a while to give time for signal delivery
for i in {1..50}; do
  sleep 0.1
  # Exit early if signal was received
  [ -f %[1]s ] && exit 0
done
exit 1`, signalFile)
	createFile(t, scriptFile, script)

	rules := append(systemPaths(), "fs:rw:"+tmpDir)
	configPath := writeConfig(t, rules)

	// Start the sandboxed process in the background
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, "--config", configPath, "--", "bash", scriptFile) //#nosec G204 -- test code intentionally launches binary with test-controlled args
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	require.NoError(t, cmd.Start())

	// Give the sandbox time to start and set up the signal handler
	time.Sleep(500 * time.Millisecond)

	// Send SIGWINCH to the sandboxed process group
	require.NoError(t, syscall.Kill(-cmd.Process.Pid, syscall.SIGWINCH))

	// Wait for the process to complete
	err = cmd.Wait()
	require.NoError(t, err)

	// Verify the signal was received
	data, err = os.ReadFile(signalFile) //#nosec G304 -- test-controlled file path in temp directory
	require.NoError(t, err)
	assert.Contains(t, string(data), "received")
}

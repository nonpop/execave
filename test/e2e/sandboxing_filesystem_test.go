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
	s := newScenario(t)
	data := s.givenDir("data")
	testFile := data.file("data.txt", "hello from sandbox")

	s.givenRules("fs:ro:" + data.String())

	// Read should succeed
	s.whenRun("cat", testFile)

	s.thenExitCode(0)
	s.thenStdoutContains("hello from sandbox")

	// Write should be denied
	s.whenRun("sh", "-c", "echo test > "+data.join("new.txt"))

	s.thenExitCodeNonZero()
	s.thenStderrContains("Read-only file system")
}

// TestE2E_SandboxingFilesystem_RunCommandWithReadWriteProjectAccess tests that the user
// can grant read-write access so the sandboxed command can create and read files.
func TestE2E_SandboxingFilesystem_RunCommandWithReadWriteProjectAccess(t *testing.T) {
	s := newScenario(t)
	data := s.givenDir("data")
	testFile := data.join("output.txt")

	s.givenRules("fs:rw:" + data.String())

	// Write should succeed
	s.whenRun("sh", "-c", "echo 'written' > "+testFile)

	s.thenExitCode(0)
	s.thenFileContains(testFile, "written")

	// Read should also succeed
	s.whenRun("cat", testFile)

	s.thenExitCode(0)
	s.thenStdoutContains("written")
}

// TestE2E_SandboxingFilesystem_ProtectSensitiveFilesWithNoAccessRules tests that the user
// can block access to sensitive files within an otherwise accessible directory.
func TestE2E_SandboxingFilesystem_ProtectSensitiveFilesWithNoAccessRules(t *testing.T) {
	s := newScenario(t)
	data := s.givenDir("data")
	envFile := data.file(".env", "SECRET=password")
	normalFile := data.file("data.txt", "normal data")

	s.givenRules("fs:rw:"+data.String(), "fs:none:"+envFile)

	// Reading the protected file should be denied
	s.whenRun("cat", envFile)

	s.thenExitCodeNonZero()
	s.thenStderrContains(".env: Permission denied")

	// Reading and writing other files should still work
	s.whenRun("cat", normalFile)

	s.thenExitCode(0)
	s.thenStdoutContains("normal data")

	s.whenRun("sh", "-c", "echo new >> "+normalFile)

	s.thenExitCode(0)
}

// TestE2E_SandboxingFilesystem_OverrideParentRuleWithMoreSpecificChildRule tests that the
// most specific rule wins when rules overlap.
func TestE2E_SandboxingFilesystem_OverrideParentRuleWithMoreSpecificChildRule(t *testing.T) {
	s := newScenario(t)
	proj := s.givenDir("proj")
	gitDir := proj.join(".git")
	err := os.MkdirAll(gitDir, 0o750)
	require.NoError(t, err)
	gitFile := proj.file(".git/config", "existing")
	srcFile := proj.file("src/main.go", "package main")

	s.givenRules("fs:rw:"+proj.String(), "fs:ro:"+gitDir)

	// Writing to .git should be denied (ro child rule overrides rw parent)
	s.whenRun("sh", "-c", "echo test > "+gitFile)

	s.thenExitCodeNonZero()
	s.thenStderrContains("config: Read-only file system")

	// Reading from .git should succeed
	s.whenRun("cat", gitFile)

	s.thenExitCode(0)
	s.thenStdoutContains("existing")

	// Writing to project/src should succeed (parent rw rule applies)
	s.whenRun("sh", "-c", "echo 'updated' > "+srcFile)

	s.thenExitCode(0)
}

// TestE2E_SandboxingFilesystem_AccessFilesThroughSymlinksWithAllowedTarget tests that
// symlinks work when both the symlink path and target are permitted.
func TestE2E_SandboxingFilesystem_AccessFilesThroughSymlinksWithAllowedTarget(t *testing.T) {
	s := newScenario(t)
	project := s.givenDir("project")
	target := s.givenDir("target")
	targetFile := target.file("data.txt", "target content")
	linkFile := project.join("data-link")
	s.givenSymlink(targetFile, linkFile)

	s.givenRules("fs:rw:"+project.String(), "fs:ro:"+target.String())

	s.whenRun("cat", linkFile)

	s.thenExitCode(0)
	s.thenStdoutContains("target content")
}

// TestE2E_SandboxingFilesystem_SymlinkToInaccessibleTargetDenied tests that symlinks
// pointing to paths outside any rule are denied.
func TestE2E_SandboxingFilesystem_SymlinkToInaccessibleTargetDenied(t *testing.T) {
	s := newScenario(t)
	secret := s.givenDir("secret")
	secret.file("data.txt", "secret data")
	public := s.givenDir("public")
	linkFile := public.join("link.txt")
	s.givenSymlink(secret.join("data.txt"), linkFile)

	s.givenRules("fs:rw:" + public.String())

	s.whenRun("cat", linkFile)

	s.thenExitCodeNonZero()
	s.thenStderrContains("link.txt: No such file or directory")
}

// TestE2E_SandboxingFilesystem_DefaultDenyForUnmatchedPaths tests that paths not
// matched by any rule are inaccessible.
func TestE2E_SandboxingFilesystem_DefaultDenyForUnmatchedPaths(t *testing.T) {
	s := newScenario(t)
	data := s.givenDir("data")
	testFile := data.file("secret.txt", "secret data")

	s.givenRules() // no extra rules beyond systemPaths

	s.whenRun("cat", testFile)

	s.thenExitCodeNonZero()
	s.thenStderrContains("secret.txt: No such file or directory")
}

// TestE2E_SandboxingFilesystem_NoneDirectoryWithAccessibleChildPath tests that a
// none-directory with a child rule allows access to the child but blocks the parent.
func TestE2E_SandboxingFilesystem_NoneDirectoryWithAccessibleChildPath(t *testing.T) {
	s := newScenario(t)
	tmp := s.givenDir("tmp")
	parent := s.givenDir("tmp/parent")
	child := s.givenDir("tmp/parent/child")
	childFile := child.file("data.txt", "child content")

	s.givenRules(
		"fs:rw:"+tmp.String(),
		"fs:none:"+parent.String(),
		"fs:rw:"+child.String(),
	)

	// Child file should be accessible
	s.whenRun("cat", childFile)

	s.thenExitCode(0)
	s.thenStdoutContains("child content")

	// Parent listing should be denied
	s.whenRun("ls", parent.String())

	s.thenExitCodeNonZero()
	s.thenStderrContains("parent': Permission denied")
}

// TestE2E_SandboxingFilesystem_RelativePathsInRulesResolvedRelativeToConfigDirectory tests
// that relative paths in rules are resolved from the config file's directory.
func TestE2E_SandboxingFilesystem_RelativePathsInRulesResolvedRelativeToConfigDirectory(t *testing.T) {
	s := newScenario(t)
	workDir := s.givenDir("work")
	src := s.givenDir("work/src")
	testFile := src.file("test.txt", "hello")

	s.givenRulesInDir(workDir.String(), "fs:ro:./src")

	s.whenRunWithDefaultConfig(workDir.String(), "cat", testFile)

	s.thenExitCode(0)
	s.thenStdoutContains("hello")
}

// TestE2E_SandboxingFilesystem_SandboxedProcessReceivesTerminalResizeSignal tests that
// on modern kernels (Linux 6.2+) where TIOCSTI is blocked, sandboxed TUI applications
// receive SIGWINCH for terminal resize events.
func TestE2E_SandboxingFilesystem_SandboxedProcessReceivesTerminalResizeSignal(t *testing.T) {
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

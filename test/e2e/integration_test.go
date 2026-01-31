package e2e_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_Integration_SandboxEnforcementWithMonitoringEnabled tests that
// sandbox enforcement and monitor logging work correctly together. This is
// the core integration test: when both --monitor and sandbox are active,
// enforcement decisions must be accurately logged.
func TestE2E_Integration_SandboxEnforcementWithMonitoringEnabled(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	tmpDir := testTempDir(t)
	allowedFile := filepath.Join(tmpDir, "allowed.txt")
	deniedFile := filepath.Join(tmpDir, "denied.txt")
	createFile(t, allowedFile, "allowed content")
	createFile(t, deniedFile, "denied content")

	// Allow reading allowed.txt but deny denied.txt
	rules := append(systemPaths(),
		"fs:ro:"+allowedFile,
		"fs:none:"+deniedFile,
	)
	configPath := writeConfig(t, rules)
	logPath := filepath.Join(tmpDir, "access.log")

	// Run both operations in a single invocation so both are logged
	// First cat should succeed, second should fail, but both get logged
	_ = runExecave(t, "", "--config", configPath, "--monitor="+logPath, "--",
		"sh", "-c", "cat "+allowedFile+" || true; cat "+deniedFile+" || true")

	// Verify log contains both enforcement decisions
	assertLogLineContainsAll(t, logPath, "READ", allowedFile, "OK", "fs:ro:"+allowedFile)
	assertLogLineContainsAll(t, logPath, "READ", deniedFile, "DENY", "fs:none:"+deniedFile)
}

// TestE2E_Integration_RulePrecedenceWithLogging tests that most-specific rule
// precedence is correctly enforced and logged. This ensures both rule
// resolution systems (sandbox and monitor) agree on which rule applies.
func TestE2E_Integration_RulePrecedenceWithLogging(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	tmpDir := testTempDir(t)
	projectDir := filepath.Join(tmpDir, "project")
	gitDir := filepath.Join(projectDir, ".git")

	err := os.MkdirAll(gitDir, 0o750)
	require.NoError(t, err)

	projectFile := filepath.Join(projectDir, "main.go")
	gitFile := filepath.Join(gitDir, "config")

	createFile(t, projectFile, "package main")
	createFile(t, gitFile, "[core]")

	// Nested rules: project rw, .git ro (more specific overrides parent)
	rules := append(systemPaths(),
		"fs:rw:"+projectDir,
		"fs:ro:"+gitDir,
	)
	configPath := writeConfig(t, rules)
	logPath := filepath.Join(tmpDir, "access.log")

	// Run all operations in one invocation to capture all in the same log
	cmd := "echo '// comment' >> " + projectFile + " && " +
		"cat " + gitFile + " && " +
		"(echo 'modified' >> " + gitFile + " || true)"

	result := runExecave(t, "", "--config", configPath, "--monitor="+logPath, "--",
		"sh", "-c", cmd)
	// First two operations succeed, last one fails
	assertExitCode(t, result, 0)

	// Verify log contains all operations with correct verdicts
	assertLogLineContainsAll(t, logPath, "WRITE", projectFile, "OK", "fs:rw:"+projectDir)
	assertLogLineContainsAll(t, logPath, "READ", gitFile, "OK", "fs:ro:"+gitDir)
	assertLogLineContainsAll(t, logPath, "WRITE", gitFile, "DENY", "fs:ro:"+gitDir)
}

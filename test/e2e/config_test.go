package e2e_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_Config_DefaultConfigLocation tests that execave reads ./execave.json by default.
func TestE2E_Config_DefaultConfigLocation(t *testing.T) {
	failIfNoBwrap(t)

	workDir := testTempDir(t)
	writeConfigInDir(t, workDir, systemPaths())

	result := runExecave(t, workDir, "--", "echo", "hi")

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "hi")
}

// TestE2E_Config_CustomConfigLocation tests that --config specifies a custom config path.
func TestE2E_Config_CustomConfigLocation(t *testing.T) {
	failIfNoBwrap(t)

	configPath := writeConfig(t, systemPaths())

	result := runExecave(t, "", "--config", configPath, "--", "echo", "hi")

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "hi")
}

// TestE2E_Config_ConfigFileNotFound tests that a missing config file produces an error.
func TestE2E_Config_ConfigFileNotFound(t *testing.T) {
	result := runExecave(t, "", "--config", "/nonexistent/config.json", "--", "echo", "hi")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "config file not found")
}

// TestE2E_Config_ValidConfig tests that a valid config runs the sandboxed command successfully.
func TestE2E_Config_ValidConfig(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	rules := append(systemPaths(),
		"fs:rw:"+tmpDir,
		"fs:none:/etc/shadow",
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 0)
}

// TestE2E_Config_EmptyRulesArray tests that empty rules array results in default-deny.
func TestE2E_Config_EmptyRulesArray(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	tmpDir := testTempDir(t)
	configPath := writeConfig(t, systemPaths())
	logPath := filepath.Join(tmpDir, "access.log")

	// With no rule for /etc/passwd, attempting to read it should fail
	result := runExecave(t, "", "--config", configPath, "--monitor="+logPath, "--", "cat", "/etc/passwd")

	// Should fail due to denied access (exit code from cat when it can't read)
	assert.NotEqual(t, 0, result.ExitCode)

	// Log should contain denial due to no matching rule
	assertLogLineContainsAll(t, logPath, "READ", "/etc/passwd", "no-matching-rule")
}

// TestE2E_Config_InvalidPermissionType tests that invalid permission types produce an error.
func TestE2E_Config_InvalidPermissionType(t *testing.T) {
	configPath := writeConfig(t, []string{"fs:readonly:/path"})

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "invalid permission type")
}

// TestE2E_Config_MalformedRule tests that malformed rules produce an error.
func TestE2E_Config_MalformedRule(t *testing.T) {
	configPath := writeConfig(t, []string{"fs:ro"}) // Missing path

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "malformed rule")
}

// TestE2E_Config_UnknownResourceType tests that unknown resource types produce an error.
func TestE2E_Config_UnknownResourceType(t *testing.T) {
	configPath := writeConfig(t, []string{"net:allow:443"})

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "unknown resource type")
}

// TestE2E_Config_PathWithRelativeComponents tests that rules with relative components grant access to the resolved path.
func TestE2E_Config_PathWithRelativeComponents(t *testing.T) {
	failIfNoBwrap(t)

	// Create a temp directory with a subdirectory
	tmpDir := testTempDir(t)
	subDir := filepath.Join(tmpDir, "sub")
	err := os.MkdirAll(subDir, 0o750)
	require.NoError(t, err)

	// Path with .. should be normalized (e.g., /tmp/xxx/sub/../sub -> /tmp/xxx/sub)
	pathWithDots := filepath.Join(tmpDir, "sub", "..", "sub")
	rules := append(systemPaths(), "fs:ro:"+pathWithDots)
	configPath := writeConfig(t, rules)

	// This should work since the path normalizes correctly
	result := runExecave(t, "", "--config", configPath, "--", "ls", subDir)

	assertExitCode(t, result, 0)
}

// TestE2E_Config_TrailingSlashRemoval tests that rules with trailing slashes grant access correctly.
func TestE2E_Config_TrailingSlashRemoval(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "test.txt")
	createFile(t, testFile, "content")

	// Path with trailing slash should be normalized
	rules := append(systemPaths(), "fs:ro:"+tmpDir+"/")
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--", "cat", testFile)

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "content")
}

// TestE2E_Config_RelativePathResolution tests that relative paths are resolved from config dir.
func TestE2E_Config_RelativePathResolution(t *testing.T) {
	failIfNoBwrap(t)

	// Create a directory structure for the test
	workDir := testTempDir(t)
	srcDir := filepath.Join(workDir, "src")
	err := os.MkdirAll(srcDir, 0o750)
	require.NoError(t, err)

	// Create a file in src
	testFile := filepath.Join(srcDir, "test.txt")
	createFile(t, testFile, "hello")

	// Config with relative path "./src"
	rules := append(systemPaths(), "fs:ro:./src")
	writeConfigInDir(t, workDir, rules)

	// Run from workDir, read the file in src
	result := runExecave(t, workDir, "--", "cat", testFile)

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "hello")
}

// TestE2E_Config_RelativePathWithParentTraversal tests that relative paths with ../ are resolved from config dir.
func TestE2E_Config_RelativePathWithParentTraversal(t *testing.T) {
	failIfNoBwrap(t)

	// Create directory structure:
	// tmpDir/
	//   shared/
	//     data.txt
	//   project/
	//     execave.json (config references ../shared)
	tmpDir := testTempDir(t)
	sharedDir := filepath.Join(tmpDir, "shared")
	projectDir := filepath.Join(tmpDir, "project")
	err := os.MkdirAll(sharedDir, 0o750)
	require.NoError(t, err)
	err = os.MkdirAll(projectDir, 0o750)
	require.NoError(t, err)

	dataFile := filepath.Join(sharedDir, "data.txt")
	createFile(t, dataFile, "shared data")

	// Config with relative path "../shared"
	rules := append(systemPaths(), "fs:ro:../shared")
	writeConfigInDir(t, projectDir, rules)

	// Run from projectDir, read the file in shared
	result := runExecave(t, projectDir, "--", "cat", dataFile)

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "shared data")
}

// TestE2E_Config_DuplicatePathsWithDifferentPermissions tests that configs with duplicate paths are rejected.
func TestE2E_Config_DuplicatePathsWithDifferentPermissions(t *testing.T) {
	assertDuplicatePathRejected(t,
		[]string{"fs:ro:/home/user", "fs:rw:/home/user"},
		"/home/user",
	)
}

// TestE2E_Config_IdenticalDuplicateRules tests that configs with identical duplicate rules are rejected.
func TestE2E_Config_IdenticalDuplicateRules(t *testing.T) {
	assertDuplicatePathRejected(t,
		[]string{"fs:ro:/usr/bin", "fs:ro:/usr/bin"},
		"/usr/bin",
	)
}

func assertDuplicatePathRejected(t *testing.T, rules []string, expectedPath string) {
	t.Helper()

	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "duplicate path")
	assert.Contains(t, result.Stderr, expectedPath)
}

// TestE2E_Config_RuleTargetsManagedPathExactly tests that rules targeting a managed path exactly are rejected.
func TestE2E_Config_RuleTargetsManagedPathExactly(t *testing.T) {
	configPath := writeConfig(t, []string{"fs:ro:/dev"})

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "managed path")
	assert.Contains(t, result.Stderr, "/dev")
}

// TestE2E_Config_RuleTargetsDescendantOfManagedPath tests that rules targeting a descendant of a managed path are rejected.
func TestE2E_Config_RuleTargetsDescendantOfManagedPath(t *testing.T) {
	configPath := writeConfig(t, []string{"fs:rw:/proc/self/status"})

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "managed path")
	assert.Contains(t, result.Stderr, "/proc")
}

// TestE2E_Config_PathWithManagedPrefixInNameIsAllowed tests that paths with a managed prefix in name are allowed.
func TestE2E_Config_PathWithManagedPrefixInNameIsAllowed(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	devDir := filepath.Join(tmpDir, "dev")
	err := os.MkdirAll(devDir, 0o750)
	require.NoError(t, err)

	rules := append(systemPaths(), "fs:ro:"+devDir)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 0)
}

// TestE2E_Config_ConfigFileExplicitlyWritable tests that configs listing the config file as writable are rejected.
func TestE2E_Config_ConfigFileExplicitlyWritable(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	configPath := filepath.Join(tmpDir, "execave.json")

	// Write a config that makes itself writable
	configContent := `{"rules": ["fs:rw:` + configPath + `"]}`
	err := os.WriteFile(configPath, []byte(configContent), 0o600)
	require.NoError(t, err)

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "config file must not be writable")
}

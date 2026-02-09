package e2e_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_FSRules_RuleValidation_InvalidPermissionType tests that invalid permission types produce an error.
func TestE2E_FSRules_RuleValidation_InvalidPermissionType(t *testing.T) {
	configPath := writeConfig(t, []string{"fs:readonly:/path"})

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "invalid permission type")
}

// TestE2E_FSRules_RuleValidation_MalformedRule tests that malformed rules produce an error.
func TestE2E_FSRules_RuleValidation_MalformedRule(t *testing.T) {
	configPath := writeConfig(t, []string{"fs:ro"}) // Missing path

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "malformed rule")
}

// TestE2E_FSRules_PathNormalization_PathWithRelativeComponents tests that rules with relative components grant access to the resolved path.
func TestE2E_FSRules_PathNormalization_PathWithRelativeComponents(t *testing.T) {
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

// TestE2E_FSRules_PathNormalization_TrailingSlashRemoval tests that rules with trailing slashes grant access correctly.
func TestE2E_FSRules_PathNormalization_TrailingSlashRemoval(t *testing.T) {
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

// TestE2E_FSRules_RelativePathResolution_RelativePathResolution tests that relative paths are resolved from config dir.
func TestE2E_FSRules_RelativePathResolution_RelativePathResolution(t *testing.T) {
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

// TestE2E_FSRules_RelativePathResolution_RelativePathWithParentTraversal tests that relative paths with ../ are resolved from config dir.
func TestE2E_FSRules_RelativePathResolution_RelativePathWithParentTraversal(t *testing.T) {
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

// TestE2E_FSRules_DuplicateRuleDetection_DuplicatePathsWithDifferentPermissions tests that configs with duplicate paths are rejected.
func TestE2E_FSRules_DuplicateRuleDetection_DuplicatePathsWithDifferentPermissions(t *testing.T) {
	assertDuplicatePathRejected(t,
		[]string{"fs:ro:/home/user", "fs:rw:/home/user"},
		"/home/user",
	)
}

// TestE2E_FSRules_DuplicateRuleDetection_IdenticalDuplicateRules tests that configs with identical duplicate rules are rejected.
func TestE2E_FSRules_DuplicateRuleDetection_IdenticalDuplicateRules(t *testing.T) {
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

// TestE2E_FSRules_ManagedPathProtection_RuleTargetsManagedPathExactly tests that rules targeting a managed path exactly are rejected.
func TestE2E_FSRules_ManagedPathProtection_RuleTargetsManagedPathExactly(t *testing.T) {
	configPath := writeConfig(t, []string{"fs:ro:/dev"})

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "managed path")
	assert.Contains(t, result.Stderr, "/dev")
}

// TestE2E_FSRules_ManagedPathProtection_RuleTargetsDescendantOfManagedPath tests that rules targeting a descendant of a managed path are rejected.
func TestE2E_FSRules_ManagedPathProtection_RuleTargetsDescendantOfManagedPath(t *testing.T) {
	configPath := writeConfig(t, []string{"fs:rw:/proc/self/status"})

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "managed path")
	assert.Contains(t, result.Stderr, "/proc")
}

// TestE2E_FSRules_ManagedPathProtection_PathWithManagedPrefixInNameIsAllowed tests that paths with a managed prefix in name are allowed.
func TestE2E_FSRules_ManagedPathProtection_PathWithManagedPrefixInNameIsAllowed(t *testing.T) {
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

// TestE2E_FSRules_ConfigFileProtection_ConfigFileCannotBeExplicitlyWritable tests that configs listing the config file as writable are rejected.
func TestE2E_FSRules_ConfigFileProtection_ConfigFileCannotBeExplicitlyWritable(t *testing.T) {
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

// TestE2E_FSRules_MostSpecificRuleWins_RoOverridesRw tests that fs:ro on a more specific path overrides fs:rw on parent.
func TestE2E_FSRules_MostSpecificRuleWins_RoOverridesRw(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	projDir := filepath.Join(tmpDir, "proj")
	gitDir := filepath.Join(projDir, ".git")
	gitFile := filepath.Join(gitDir, "config")

	err := os.MkdirAll(gitDir, 0o750)
	require.NoError(t, err)
	createFile(t, gitFile, "existing")

	// rw on project, ro on .git (with system paths so sh can execute)
	rules := append(systemPaths(),
		"fs:rw:"+projDir,
		"fs:ro:"+gitDir,
	)
	configPath := writeConfig(t, rules)

	// Try to write to .git - should fail
	result := runExecave(t, "", "--config", configPath, "--", "sh", "-c", "echo test > "+gitFile)

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "config: Read-only file system")
}

// TestE2E_FSRules_MostSpecificRuleWins_RwOverridesRo tests that fs:rw on a more specific path overrides fs:ro on parent.
func TestE2E_FSRules_MostSpecificRuleWins_RwOverridesRo(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	homeDir := filepath.Join(tmpDir, "home")
	projDir := filepath.Join(homeDir, "proj")
	projFile := filepath.Join(projDir, "file.txt")

	err := os.MkdirAll(projDir, 0o750)
	require.NoError(t, err)

	// ro on home, rw on proj
	rules := append(systemPaths(),
		"fs:ro:"+homeDir,
		"fs:rw:"+projDir,
	)
	configPath := writeConfig(t, rules)

	// Write to proj - should succeed
	result := runExecave(t, "", "--config", configPath, "--", "sh", "-c", "echo 'written' > "+projFile)
	assertExitCode(t, result, 0)

	// Verify file was written
	data, err := os.ReadFile(projFile) // #nosec G304 -- test code reading controlled test files
	require.NoError(t, err)
	assert.Contains(t, string(data), "written")
}

package e2e_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_Sandbox_AccessControl_NoMatchingRule tests that access without a matching rule is denied.
func TestE2E_Sandbox_AccessControl_NoMatchingRule(t *testing.T) {
	failIfNoBwrap(t)

	// Create a real file that the sandbox has no rule for
	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "secret.txt")
	createFile(t, testFile, "secret data")

	// System paths let cat execute, but no rule for tmpDir means it's not mounted
	configPath := writeConfig(t, systemPaths())

	result := runExecave(t, "", "--config", configPath, "--", "cat", testFile)

	// Should fail because the file is not accessible inside the sandbox
	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "secret.txt: No such file or directory")
}

// TestE2E_Sandbox_AccessControl_AllowedPathAccessible tests that allowed paths are accessible.
func TestE2E_Sandbox_AccessControl_AllowedPathAccessible(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "data.txt")
	createFile(t, testFile, "hello from sandbox")

	rules := append(systemPaths(), "fs:ro:"+tmpDir)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--", "cat", testFile)

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "hello from sandbox")
}

// TestE2E_Sandbox_AccessControl_ReadAllowed tests that read is allowed on fs:ro paths.
func TestE2E_Sandbox_AccessControl_ReadAllowed(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "data.txt")
	createFile(t, testFile, "hello from sandbox")

	rules := append(systemPaths(), "fs:ro:"+tmpDir)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--", "cat", testFile)

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "hello from sandbox")
}

// TestE2E_Sandbox_AccessControl_WriteDeniedOnReadOnlyPath tests that write is denied on fs:ro paths.
func TestE2E_Sandbox_AccessControl_WriteDeniedOnReadOnlyPath(t *testing.T) {
	failIfNoBwrap(t)

	// Create a temp directory for testing writes
	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "test.txt")

	// Allow read-only access to the temp dir (with system paths so sh can execute)
	rules := append(systemPaths(), "fs:ro:"+tmpDir)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--", "sh", "-c", "echo test > "+testFile)

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "test.txt: Read-only file system")
}

// TestE2E_Sandbox_AccessControl_ReadAllowedOnReadWritePath tests that read is allowed on fs:rw paths.
func TestE2E_Sandbox_AccessControl_ReadAllowedOnReadWritePath(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "test.txt")
	createFile(t, testFile, "hello from rw")

	rules := append(systemPaths(), "fs:rw:"+tmpDir)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--", "cat", testFile)

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "hello from rw")
}

// TestE2E_Sandbox_AccessControl_WriteAllowedOnReadWritePath tests that write is allowed on fs:rw paths.
func TestE2E_Sandbox_AccessControl_WriteAllowedOnReadWritePath(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "test.txt")

	rules := append(systemPaths(), "fs:rw:"+tmpDir)
	configPath := writeConfig(t, rules)

	// Write to file
	result := runExecave(t, "", "--config", configPath, "--", "sh", "-c", "echo 'written' > "+testFile)
	assertExitCode(t, result, 0)

	// Verify file was written
	data, err := os.ReadFile(testFile) // #nosec G304 -- test code reading controlled test files
	require.NoError(t, err)
	assert.Contains(t, string(data), "written")
}

// TestE2E_Sandbox_AccessControl_ReadDeniedByNoneRule tests that read is denied on fs:none paths.
func TestE2E_Sandbox_AccessControl_ReadDeniedByNoneRule(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	secretFile := filepath.Join(tmpDir, "secret.txt")
	createFile(t, secretFile, "secret data")

	// Allow rw to parent but none to specific file (with system paths so cat can execute)
	rules := append(systemPaths(),
		"fs:rw:"+tmpDir,
		"fs:none:"+secretFile,
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--", "cat", secretFile)

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "secret.txt: Permission denied")
}

// TestE2E_Sandbox_AccessControl_WriteDeniedByNoneRule tests that write is denied on fs:none paths.
func TestE2E_Sandbox_AccessControl_WriteDeniedByNoneRule(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	secretFile := filepath.Join(tmpDir, "secret.txt")
	createFile(t, secretFile, "existing content")

	// Allow rw to parent but none to specific file (with system paths so sh can execute)
	rules := append(systemPaths(),
		"fs:rw:"+tmpDir,
		"fs:none:"+secretFile,
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--", "sh", "-c", "echo test > "+secretFile)

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "secret.txt: Permission denied")
}

// TestE2E_Sandbox_AccessControl_NoneDirectoryInaccessible tests that fs:none on a directory blocks listing and file creation.
func TestE2E_Sandbox_AccessControl_NoneDirectoryInaccessible(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	blockedDir := filepath.Join(tmpDir, "blocked")
	err := os.Mkdir(blockedDir, 0o750)
	require.NoError(t, err)

	rules := append(systemPaths(),
		"fs:rw:"+tmpDir,
		"fs:none:"+blockedDir,
	)
	configPath := writeConfig(t, rules)

	// Listing should be denied
	result := runExecave(t, "", "--config", configPath, "--", "ls", blockedDir)
	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "blocked': Permission denied")

	// File creation should be denied
	result = runExecave(t, "", "--config", configPath, "--", "sh", "-c", "touch "+filepath.Join(blockedDir, "test"))
	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "test': Permission denied")
}

// TestE2E_Sandbox_AccessControl_NoneDirectoryWithChildRuleAllowsChildAccess tests that fs:none with a child rule
// blocks listing on the parent but allows access to the child.
func TestE2E_Sandbox_AccessControl_NoneDirectoryWithChildRuleAllowsChildAccess(t *testing.T) {
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

// TestE2E_Sandbox_SymlinkHandling_SymlinkWithAccessiblePathAndAllowedTarget tests that symlinks to allowed paths work.
func TestE2E_Sandbox_SymlinkHandling_SymlinkWithAccessiblePathAndAllowedTarget(t *testing.T) {
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

	// Allow rw to project dir and ro to target dir (both symlink path and target are accessible)
	rules := append(systemPaths(),
		"fs:rw:"+projectDir,
		"fs:ro:"+targetDir,
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--", "cat", linkFile)

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "target content")
}

// TestE2E_Sandbox_SymlinkHandling_SymlinkWithInaccessiblePath tests that symlinks in inaccessible directories fail.
func TestE2E_Sandbox_SymlinkHandling_SymlinkWithInaccessiblePath(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	unmountedDir := filepath.Join(tmpDir, "unmounted")
	targetDir := filepath.Join(tmpDir, "target")
	targetFile := filepath.Join(targetDir, "data.txt")
	linkFile := filepath.Join(unmountedDir, "link.txt")

	err := os.MkdirAll(unmountedDir, 0o750)
	require.NoError(t, err)
	err = os.MkdirAll(targetDir, 0o750)
	require.NoError(t, err)

	createFile(t, targetFile, "target data")
	createSymlink(t, targetFile, linkFile)

	// Only allow access to the target directory, not the unmounted directory where the symlink is
	rules := append(systemPaths(), "fs:ro:"+targetDir)
	configPath := writeConfig(t, rules)

	// Following the symlink should fail because the symlink path is not mounted
	result := runExecave(t, "", "--config", configPath, "--", "cat", linkFile)

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "link.txt: No such file or directory")
}

// TestE2E_Sandbox_SymlinkHandling_SymlinkWithAccessiblePathButDeniedTarget tests that symlinks to denied paths fail.
func TestE2E_Sandbox_SymlinkHandling_SymlinkWithAccessiblePathButDeniedTarget(t *testing.T) {
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

	// Allow rw to public but no rule for secret (target has no matching rule)
	rules := append(systemPaths(), "fs:rw:"+publicDir)
	configPath := writeConfig(t, rules)

	// Following the symlink should fail because target is not mounted (dangling symlink)
	result := runExecave(t, "", "--config", configPath, "--", "cat", linkFile)

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "link.txt: No such file or directory")
}

// TestE2E_Sandbox_CommandExecution_CommandExecution tests that commands can be executed in the sandbox.
func TestE2E_Sandbox_CommandExecution_CommandExecution(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	scriptFile := filepath.Join(tmpDir, "test.py")
	createFile(t, scriptFile, `print("hello from python")`)

	configPath := writeConfig(t, []string{
		"fs:ro:" + tmpDir,
		"fs:ro:/usr",
		"fs:ro:/lib",
		"fs:ro:/lib64",
	})

	result := runExecave(t, "", "--config", configPath, "--", "python3", scriptFile)

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "hello from python")
}

// TestE2E_Sandbox_CommandExecution_ExitCodePropagation tests that exit codes are propagated from the command.
func TestE2E_Sandbox_CommandExecution_ExitCodePropagation(t *testing.T) {
	failIfNoBwrap(t)

	configPath := writeConfig(t, systemPaths())

	result := runExecave(t, "", "--config", configPath, "--", "sh", "-c", "exit 42")

	assertExitCode(t, result, 42)
}

// TestE2E_Sandbox_ConfigFileProtection_ConfigFileInRwDirectoryForcedToRo tests that a config file in a rw directory is forced read-only.
func TestE2E_Sandbox_ConfigFileProtection_ConfigFileInRwDirectoryForcedToRo(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	configPath := filepath.Join(tmpDir, "execave.json")

	// Config allows rw access to tmpDir (which contains the config)
	rules := append(systemPaths(), "fs:rw:"+tmpDir)
	writeConfigInDir(t, tmpDir, rules)

	// Try to write to the config file - should fail because config is mounted read-only
	result := runExecave(t, "", "--config", configPath, "--", "sh", "-c", "echo test >> "+configPath)

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "execave: config file forced read-only")
	assert.Contains(t, result.Stderr, "execave.json: Read-only file system")
}

// TestE2E_Sandbox_ConfigFileProtection_ConfigFileProtectionDoesNotBlockSiblingAccess tests that sibling files remain accessible when config is protected.
func TestE2E_Sandbox_ConfigFileProtection_ConfigFileProtectionDoesNotBlockSiblingAccess(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	configPath := filepath.Join(tmpDir, "execave.json")
	dataFile := filepath.Join(tmpDir, "data.txt")

	createFile(t, dataFile, "test data")

	// Config allows rw access to tmpDir (which contains both config and data)
	rules := append(systemPaths(), "fs:rw:"+tmpDir)
	writeConfigInDir(t, tmpDir, rules)

	// Test 1: Read sibling file
	result := runExecave(t, "", "--config", configPath, "--", "cat", dataFile)
	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stderr, "execave: config file forced read-only")
	assert.Contains(t, result.Stdout, "test data")

	// Test 2: Write to sibling file
	result = runExecave(t, "", "--config", configPath, "--", "sh", "-c", "echo 'new data' >> "+dataFile)
	assert.Contains(t, result.Stderr, "execave: config file forced read-only")
	assertExitCode(t, result, 0)

	// Verify the write
	data, err := os.ReadFile(dataFile) // #nosec G304 -- test code
	require.NoError(t, err)
	assert.Contains(t, string(data), "new data")
}

// TestE2E_Sandbox_ConfigFileProtection_ConfigFileNotMountedStaysUnmounted tests that a config file not covered by any rule stays unmounted.
func TestE2E_Sandbox_ConfigFileProtection_ConfigFileNotMountedStaysUnmounted(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	configDir := filepath.Join(tmpDir, "config")
	workDir := filepath.Join(tmpDir, "work")

	err := os.Mkdir(configDir, 0o750)
	require.NoError(t, err)
	err = os.Mkdir(workDir, 0o750)
	require.NoError(t, err)

	configPath := filepath.Join(configDir, "execave.json")

	// Config only allows access to workDir (not configDir)
	rules := append(systemPaths(), "fs:rw:"+workDir)
	writeConfigInDir(t, configDir, rules)

	// Try to read the config file - should fail because it's not mounted
	result := runExecave(t, "", "--config", configPath, "--", "cat", configPath)

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "execave.json: No such file or directory")
	// Should NOT see the info message (access was not reduced, just not mounted)
	assert.NotContains(t, result.Stderr, "force")
}

// TestE2E_Sandbox_ConfigFileProtection_ConfigFileAlreadyRoStaysRo tests that a config file already ro stays ro without a message.
func TestE2E_Sandbox_ConfigFileProtection_ConfigFileAlreadyRoStaysRo(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	configPath := filepath.Join(tmpDir, "execave.json")

	// Config allows ro access to tmpDir (which contains the config)
	rules := append(systemPaths(), "fs:ro:"+tmpDir)
	writeConfigInDir(t, tmpDir, rules)

	// Try to write to the config file - should fail
	result := runExecave(t, "", "--config", configPath, "--", "sh", "-c", "echo test >> "+configPath)

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "execave.json: Read-only file system")
	// Should NOT see the info message (access was not reduced, it was already ro)
	assert.NotContains(t, result.Stderr, "force")
}

// TestE2E_Sandbox_ConfigFileProtection_ConfigFileDeletionPossibleButAcceptable tests that config file deletion is possible but acceptable.
func TestE2E_Sandbox_ConfigFileProtection_ConfigFileDeletionPossibleButAcceptable(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	configPath := filepath.Join(tmpDir, "execave.json")

	// Config allows rw access to tmpDir (which contains the config)
	rules := append(systemPaths(), "fs:rw:"+tmpDir)
	writeConfigInDir(t, tmpDir, rules)

	// Attempt to delete the config file from within sandbox.
	// Unlink may succeed because the parent directory is writable.
	_ = runExecave(t, "", "--config", configPath, "--", "rm", configPath)
}

package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runTextLog runs execave with --monitor=<monitorArg> against the given rules and command,
// captures stderr and stdout, and returns the execaveResult.
func runTextLog(t *testing.T, rules []string, monitorArg string, args ...string) execaveResult {
	t.Helper()
	configPath := writeConfig(t, rules)
	execArgs := make([]string, 0, 5+len(args))
	execArgs = append(execArgs, "--config", configPath, "--monitor="+monitorArg, "--")
	execArgs = append(execArgs, args...)
	return runExecave(t, "", execArgs...)
}

// runTextLogWithFlags runs execave with --monitor=<monitorArg> and extra flags.
func runTextLogWithFlags(t *testing.T, rules []string, monitorArg string, extraFlags []string, args ...string) execaveResult {
	t.Helper()
	configPath := writeConfig(t, rules)
	execArgs := make([]string, 0, 5+len(extraFlags)+len(args))
	execArgs = append(execArgs, "--config", configPath, "--monitor="+monitorArg)
	execArgs = append(execArgs, extraFlags...)
	execArgs = append(execArgs, "--")
	execArgs = append(execArgs, args...)
	return runExecave(t, "", execArgs...)
}

// TestE2E_TextLog_FileContainsDenyEntries tests that --monitor=<file> writes denied
// filesystem access entries to the specified file.
func TestE2E_TextLog_FileContainsDenyEntries(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	tmpDir := testTempDir(t)
	logFile := filepath.Join(tmpDir, "access.log")
	deniedFile := filepath.Join(tmpDir, "secret.txt")
	createFile(t, deniedFile, "secret")

	// No rule allows deniedFile, so it will be denied
	rules := append(systemPaths(), "fs:none:"+deniedFile)

	result := runTextLog(t, rules, logFile, "cat", deniedFile)
	// cat fails because the file is denied
	assert.NotEqual(t, 0, result.ExitCode)

	logContent, err := os.ReadFile(logFile)
	require.NoError(t, err)

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	deniedFileRel, err := filepath.Rel(homeDir, deniedFile)
	require.NoError(t, err)

	log := string(logContent)
	assert.Contains(t, log, "DENY")
	assert.Contains(t, log, "~/"+deniedFileRel)
}

// TestE2E_TextLog_FileWrittenRealTime tests that --monitor=<file> writes entries to
// the file as they are generated (not buffered until exit).
func TestE2E_TextLog_FileWrittenRealTime(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	tmpDir := testTempDir(t)
	logFile := filepath.Join(tmpDir, "access.log")
	deniedDir := filepath.Join(tmpDir, "denied")
	deniedFile := filepath.Join(deniedDir, "file.txt")
	createFile(t, deniedFile, "data")

	rules := append(systemPaths(), "fs:none:"+deniedDir)

	result := runTextLog(t, rules, logFile, "cat", deniedFile)
	assert.NotEqual(t, 0, result.ExitCode)

	logContent, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.NotEmpty(t, string(logContent))
}

// TestE2E_TextLog_StderrContainsEntriesAfterExit tests that --monitor=- buffers
// entries and writes them to stderr after the process exits.
func TestE2E_TextLog_StderrContainsEntriesAfterExit(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	tmpDir := testTempDir(t)
	deniedFile := filepath.Join(tmpDir, "secret.txt")
	createFile(t, deniedFile, "secret")

	rules := append(systemPaths(), "fs:none:"+deniedFile)

	result := runTextLog(t, rules, "-", "cat", deniedFile)
	assert.NotEqual(t, 0, result.ExitCode)

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	deniedFileRel, err := filepath.Rel(homeDir, deniedFile)
	require.NoError(t, err)

	assert.Contains(t, result.Stderr, "DENY")
	assert.Contains(t, result.Stderr, "~/"+deniedFileRel)
}

// TestE2E_TextLog_ShowAllowedIncludesOKEntries tests that --show-allowed causes OK entries
// to appear in the text log (denied-only is the default).
func TestE2E_TextLog_ShowAllowedIncludesOKEntries(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	tmpDir := testTempDir(t)
	allowedFile := filepath.Join(tmpDir, "data.txt")
	createFile(t, allowedFile, "data")

	rules := append(systemPaths(), "fs:ro:"+tmpDir)

	// Without --show-allowed, OK entries are hidden
	resultDefault := runTextLog(t, rules, "-", "cat", allowedFile)
	assertExitCode(t, resultDefault, 0)

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	allowedFileRel, err := filepath.Rel(homeDir, allowedFile)
	require.NoError(t, err)

	assert.NotContains(t, resultDefault.Stderr, "~/"+allowedFileRel)

	// With --show-allowed, OK entries appear
	resultAllowed := runTextLogWithFlags(t, rules, "-", []string{"--show-allowed"}, "cat", allowedFile)
	assertExitCode(t, resultAllowed, 0)

	assert.Contains(t, resultAllowed.Stderr, "OK")
	assert.Contains(t, resultAllowed.Stderr, "~/"+allowedFileRel)
}

// TestE2E_TextLog_ShowNologIncludesNologEntries tests that --show-nolog causes entries
// matching nolog rules to appear in the text log (nolog entries are hidden by default).
func TestE2E_TextLog_ShowNologIncludesNologEntries(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	tmpDir := testTempDir(t)
	cacheDir := filepath.Join(tmpDir, "project", "cache")
	cacheFile := filepath.Join(cacheDir, "data.bin")
	createFile(t, cacheFile, "cache data")
	projectDir := filepath.Join(tmpDir, "project")

	rules := append(systemPaths(),
		"fs:ro:"+projectDir,
		"fs:nolog:"+cacheDir,
	)

	// Without --show-nolog, nolog entries are hidden (even denied ones)
	resultDefault := runTextLog(t, rules, "-", "cat", cacheFile)
	assertExitCode(t, resultDefault, 0)

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	cacheFileRel, err := filepath.Rel(homeDir, cacheFile)
	require.NoError(t, err)

	assert.NotContains(t, resultDefault.Stderr, "~/"+cacheFileRel)

	// With --show-nolog, nolog entries appear
	resultNolog := runTextLogWithFlags(t, rules, "-", []string{"--show-nolog", "--show-allowed"}, "cat", cacheFile)
	assertExitCode(t, resultNolog, 0)

	assert.Contains(t, resultNolog.Stderr, "~/"+cacheFileRel)
}

// TestE2E_TextLog_BareMonitorStartsWebUI tests that bare --monitor (without a value)
// still starts the web UI — backward compatibility.
func TestE2E_TextLog_BareMonitorStartsWebUI(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	env := newMonitorTest(t)

	rules := systemPaths()
	result := env.runMonitored(t, rules, "true")
	assertExitCode(t, result.execaveResult, 0)

	// Web UI was started (monitor URL printed to stderr)
	assert.Contains(t, result.Stderr, "monitor running at http://")
	// Web UI responded with HTML content
	assert.Contains(t, result.WebUI, "<html")
}

// TestE2E_TextLog_ShowAllowedSetsWebUICheckboxState tests that --show-allowed sets the
// "Denied only" checkbox to unchecked in the web UI initial state.
func TestE2E_TextLog_ShowAllowedSetsWebUICheckboxState(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	rules := systemPaths()
	configPath := writeConfig(t, rules)
	execArgs := []string{"--config", configPath, "--monitor", "--no-open", "--show-allowed", "--", "true"}
	result := runExecaveMonitored(t, execArgs...)

	// When showAllowed=true, DeniedOnlyChecked=false, so the checkbox should NOT have checked
	assert.NotContains(t, result.WebUI, `id="denied-only-checkbox" checked`)
	// Apply-nolog checkbox should still be checked (default)
	assert.Contains(t, result.WebUI, `id="apply-nolog-checkbox" checked`)
}

// TestE2E_TextLog_ShowNologSetsWebUICheckboxState tests that --show-nolog sets the
// "Apply nolog rules" checkbox to unchecked in the web UI initial state.
func TestE2E_TextLog_ShowNologSetsWebUICheckboxState(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	rules := systemPaths()
	configPath := writeConfig(t, rules)
	execArgs := []string{"--config", configPath, "--monitor", "--no-open", "--show-nolog", "--", "true"}
	result := runExecaveMonitored(t, execArgs...)

	// When showNolog=true, ApplyNologChecked=false, so the checkbox should NOT have checked
	assert.NotContains(t, result.WebUI, `id="apply-nolog-checkbox" checked`)
	// Denied-only checkbox should still be checked (default)
	assert.Contains(t, result.WebUI, `id="denied-only-checkbox" checked`)
}

// TestE2E_TextLog_OutputFormatContainsAllColumns tests that text log lines contain
// all four columns: result, operation, target, rule.
func TestE2E_TextLog_OutputFormatContainsAllColumns(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	tmpDir := testTempDir(t)
	deniedFile := filepath.Join(tmpDir, "secret.txt")
	createFile(t, deniedFile, "secret")

	rules := append(systemPaths(), "fs:none:"+deniedFile)

	result := runTextLog(t, rules, "-", "cat", deniedFile)
	assert.NotEqual(t, 0, result.ExitCode)

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	deniedFileRel, err := filepath.Rel(homeDir, deniedFile)
	require.NoError(t, err)

	// Find the text log line containing the denied file (shortened path form)
	var matchLine string
	for _, line := range strings.Split(result.Stderr, "\n") {
		if strings.Contains(line, "~/"+deniedFileRel) {
			matchLine = line
			break
		}
	}
	require.NotEmpty(t, matchLine)

	assert.Contains(t, matchLine, "DENY")
	assert.Contains(t, matchLine, "READ")
	assert.Contains(t, matchLine, "fs:none:"+deniedFile)
}

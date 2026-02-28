package e2e_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_TextLog_FileContainsDenyEntries tests that --monitor=<file> writes denied
// filesystem access entries to the specified file.
func TestE2E_TextLog_FileContainsDenyEntries(t *testing.T) {
	s := newScenario(t)
	data := s.givenDir("data")
	logFile := data.join("access.log")
	deniedFile := data.file("secret.txt", "secret")

	s.givenRules("fs:none:" + deniedFile)

	s.whenRunTextLog(logFile, "cat", deniedFile)

	s.thenExitCodeNonZero()
	s.thenFileContains(logFile, "DENY")
	s.thenFileContains(logFile, data.rel("secret.txt"))
}

// TestE2E_TextLog_FileWrittenRealTime tests that --monitor=<file> writes entries to
// the file as they are generated (not buffered until exit).
func TestE2E_TextLog_FileWrittenRealTime(t *testing.T) {
	s := newScenario(t)
	data := s.givenDir("data")
	logFile := data.join("access.log")
	denied := s.givenDir("data/denied")
	deniedFile := denied.file("file.txt", "data")

	s.givenRules("fs:none:" + denied.String())

	s.whenRunTextLog(logFile, "cat", deniedFile)

	s.thenExitCodeNonZero()
	logContent, err := os.ReadFile(logFile) // #nosec G304 -- test code reading controlled test file path
	require.NoError(t, err)
	assert.NotEmpty(t, string(logContent))
}

// TestE2E_TextLog_StderrContainsEntriesAfterExit tests that --monitor=- buffers
// entries and writes them to stderr after the process exits.
func TestE2E_TextLog_StderrContainsEntriesAfterExit(t *testing.T) {
	s := newScenario(t)
	data := s.givenDir("data")
	deniedFile := data.file("secret.txt", "secret")

	s.givenRules("fs:none:" + deniedFile)

	s.whenRunTextLog("-", "cat", deniedFile)

	s.thenExitCodeNonZero()
	s.thenStderrContains("DENY")
	s.thenStderrContains(data.rel("secret.txt"))
}

// TestE2E_TextLog_ShowAllowedIncludesOKEntries tests that --show-allowed causes OK entries
// to appear in the text log (denied-only is the default).
func TestE2E_TextLog_ShowAllowedIncludesOKEntries(t *testing.T) {
	s := newScenario(t)
	data := s.givenDir("data")
	allowedFile := data.file("data.txt", "data")

	s.givenRules("fs:ro:" + data.String())

	s.whenRunTextLog("-", "cat", allowedFile)

	s.thenExitCode(0)
	s.thenStderrNotContains(data.rel("data.txt"))

	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", allowedFile)

	s.thenExitCode(0)
	s.thenStderrContains("OK")
	s.thenStderrContains(data.rel("data.txt"))
}

// TestE2E_TextLog_ShowNologIncludesNologEntries tests that --show-nolog causes entries
// matching nolog rules to appear in the text log (nolog entries are hidden by default).
func TestE2E_TextLog_ShowNologIncludesNologEntries(t *testing.T) {
	s := newScenario(t)
	project := s.givenDir("project")
	cacheDir := project.join("cache")
	cacheFile := project.file("cache/data.bin", "cache data")

	s.givenRules("fs:ro:"+project.String(), "fs:nolog:"+cacheDir)

	s.whenRunTextLog("-", "cat", cacheFile)

	s.thenExitCode(0)
	s.thenStderrNotContains(project.rel("cache/data.bin"))

	s.whenRunTextLogWithFlags([]string{"--show-nolog", "--show-allowed"}, "cat", cacheFile)

	s.thenExitCode(0)
	s.thenStderrContains(project.rel("cache/data.bin"))
}

// TestE2E_TextLog_BareMonitorWritesToStderr tests that bare --monitor (without a value)
// writes denied entries to stderr after process exits.
func TestE2E_TextLog_BareMonitorWritesToStderr(t *testing.T) {
	s := newScenario(t)
	data := s.givenDir("data")
	deniedFile := data.file("secret.txt", "secret")

	s.givenRules("fs:none:" + deniedFile)

	s.whenRunTextLog("-", "cat", deniedFile)

	s.thenExitCodeNonZero()
	s.thenStderrContains("DENY")
	s.thenStderrContains(data.rel("secret.txt"))
}

// TestE2E_TextLog_OutputFormatContainsAllColumns tests that text log lines contain
// all four columns: result, operation, target, rule.
func TestE2E_TextLog_OutputFormatContainsAllColumns(t *testing.T) {
	s := newScenario(t)
	data := s.givenDir("data")
	deniedFile := data.file("secret.txt", "secret")

	s.givenRules("fs:none:" + deniedFile)

	s.whenRunTextLog("-", "cat", deniedFile)

	s.thenExitCodeNonZero()
	var matchLine string
	for line := range strings.SplitSeq(s.lastResult.Stderr, "\n") {
		if strings.Contains(line, data.rel("secret.txt")) {
			matchLine = line
			break
		}
	}
	require.NotEmpty(t, matchLine)
	assert.Contains(t, matchLine, "DENY")
	assert.Contains(t, matchLine, "READ")
	assert.Contains(t, matchLine, "fs:none:"+deniedFile)
}

package e2e_test

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TextLog_WritesLogToFile(t *testing.T) {
	// --output-path writes access log entries to the specified file instead of stderr.
	// Default view shows only DENY/UNKNOWN; OK entries are excluded.

	t.Run("DENY entry with all columns", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		logFile := data.join("access.log")
		deniedFile := data.file("secret.txt", "secret")
		s.givenRules("fs:none:" + deniedFile)

		s.whenRunTextLog(logFile, "cat", deniedFile)

		s.thenExitCodeNonZero()
		s.thenFileHasEntry(logFile, "READ", data.rel("secret.txt"), "DENY", "none:"+deniedFile)
		s.thenStderrNotContains(data.rel("secret.txt"))
	})

	t.Run("OK entry absent by default", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		logFile := data.join("access.log")
		allowedFile := data.file("data.txt", "content")
		s.givenRules("fs:ro:" + data.String())

		s.whenRunTextLog(logFile, "cat", allowedFile)

		s.thenExitCode(0)
		fileContent, err := os.ReadFile(logFile) // #nosec G304 -- test code reading controlled test file path
		require.NoError(t, err)
		assert.NotContains(t, string(fileContent), data.rel("data.txt"))
		s.thenStderrNotContains(data.rel("data.txt"))
	})
}

func Test_TextLog_FileWrittenRealTime(t *testing.T) {
	// In monitor mode with --output-path, entries are written to the file in real
	// time — before the process exits — enabling tail -f monitoring while running.
	failIfNoStrace(t)

	s := newScenario(t)
	data := s.givenDir("data")
	logFile := data.join("access.log")
	deniedFile := data.file("secret.txt", "secret")

	s.givenRules("fs:none:" + deniedFile)

	//nolint:gosec // G204: test uses controlled input from test fixtures
	cmd := exec.CommandContext(context.Background(), binaryPath,
		"--config", s.configPath, "monitor",
		"--output-path="+logFile,
		"--", "sh", "-c", "cat "+deniedFile+"; sleep 30",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	time.Sleep(500 * time.Millisecond)

	// DENY entry must appear in the file while the process is still sleeping.
	s.thenFileHasEntry(logFile, "READ", data.rel("secret.txt"), "DENY", "none:"+deniedFile)

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

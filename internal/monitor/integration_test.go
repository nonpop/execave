package monitor_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Requirement: Real-time access log writing ---

func TestIntegration_RealTimeAccessLogWriting_LogEntriesAvailableDuringExecution(t *testing.T) {
	// Use a directory outside /tmp to avoid managed path filtering
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	dataDir := filepath.Join(absTestDir, "data")
	testFile := filepath.Join(dataDir, "file.txt")
	require.NoError(t, os.MkdirAll(dataDir, 0o750))
	require.NoError(t, os.WriteFile(testFile, []byte("test data"), 0o600))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{roRule(dataDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	// Run a command that reads the file, then sleeps briefly before exiting.
	// We verify entries appear during the sleep (while the sandbox is still running).
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = env.mon.Run(context.Background(), []string{"sh", "-c", "cat " + testFile + " && sleep 3"})
	}()

	// Entry must be available via the Logger while the sandbox is still running
	require.Eventually(t, func() bool {
		for _, e := range env.logger.Entries() {
			if e.Target == testFile && e.Operation == accesslog.OperationRead {
				return true
			}
		}
		return false
	}, 5*time.Second, 50*time.Millisecond)

	// Confirm the command is still running (still in the sleep phase)
	select {
	case <-done:
		t.Fatal("command exited before entry could be verified during execution")
	default:
	}

	// Verify entry fields
	for _, e := range env.logger.Entries() {
		if e.Target == testFile && e.Operation == accesslog.OperationRead {
			assert.Equal(t, accesslog.ResultOK, e.Result)
			assert.Equal(t, "fs:ro:"+dataDir, e.Rule)
		}
	}

	// Wait for command to finish normally
	<-done
}

func TestIntegration_RealTimeAccessLogWriting_LogEntriesAppearInSyscallOrder(t *testing.T) {
	// Use a directory outside /tmp to avoid managed path filtering
	//nolint:usetesting // Need a path outside /tmp
	testDir, err := os.MkdirTemp(".", "monitor-integ-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(testDir) })

	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)
	aFile := filepath.Join(absTestDir, "a.txt")
	bFile := filepath.Join(absTestDir, "b.txt")
	require.NoError(t, os.WriteFile(aFile, []byte("a"), 0o600))
	require.NoError(t, os.WriteFile(bFile, []byte("b"), 0o600))

	env := newMonitorTestEnv(t, func(_ string) *config.Config {
		return &config.Config{
			FSRules:      []fsrules.Rule{rwRule(absTestDir)},
			NetRules:     nil,
			ManagedPaths: nil,
		}
	})

	// Read a.txt then write b.txt
	exitCode, err := env.run([]string{"sh", "-c", "cat " + aFile + " && echo new > " + bFile})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	logStr := env.readLog()
	lines := strings.Split(logStr, "\n")

	readIdx := -1
	writeIdx := -1
	for i, line := range lines {
		if strings.Contains(line, "READ") && strings.Contains(line, "a.txt") {
			readIdx = i
		}
		if strings.Contains(line, "WRITE") && strings.Contains(line, "b.txt") {
			writeIdx = i
		}
	}

	require.NotEqual(t, -1, readIdx)
	require.NotEqual(t, -1, writeIdx)
	assert.Less(t, readIdx, writeIdx)
}

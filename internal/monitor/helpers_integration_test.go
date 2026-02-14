package monitor_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/monitor"
	"github.com/stretchr/testify/require"
)

type monitorTestEnv struct {
	t       *testing.T
	TmpDir  string
	LogPath string
	LogFile *os.File
	mon     *monitor.Monitor
}

func newMonitorTestEnv(t *testing.T, setupConfig func(tmpDir string) *config.Config) *monitorTestEnv {
	t.Helper()
	_, err := exec.LookPath("strace")
	require.NoError(t, err)

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "access.log")
	logFile, err := os.Create(logPath) // #nosec G304 -- test file path from t.TempDir()
	require.NoError(t, err)
	t.Cleanup(func() { _ = logFile.Close() })

	cfg := setupConfig(tmpDir)

	logger := accesslog.New(logFile, cfg.ManagedPaths)
	resolver := fsrules.NewResolver(cfg.FSRules, cfg.ManagedPaths)
	mon := monitor.New(logger, resolver, nil, false)

	return &monitorTestEnv{
		t:       t,
		TmpDir:  tmpDir,
		LogPath: logPath,
		LogFile: logFile,
		mon:     mon,
	}
}

func (e *monitorTestEnv) run(cmd []string) (int, error) {
	return e.mon.Run(context.Background(), cmd) //nolint:wrapcheck
}

func (e *monitorTestEnv) readLog() string {
	e.t.Helper()
	require.NoError(e.t, e.LogFile.Sync())
	content, err := os.ReadFile(e.LogPath) // #nosec G304 -- test file path from t.TempDir()
	require.NoError(e.t, err)
	logStr := string(content)
	e.t.Logf("Log content:\n%s", logStr)
	return logStr
}

func roRule(path string) fsrules.Rule {
	return fsrules.Rule{
		Resource:   fsrules.ResourceFS,
		Permission: fsrules.PermissionReadOnly,
		Path:       path,
		RawRule:    "fs:ro:" + path,
	}
}

func rwRule(path string) fsrules.Rule {
	return fsrules.Rule{
		Resource:   fsrules.ResourceFS,
		Permission: fsrules.PermissionReadWrite,
		Path:       path,
		RawRule:    "fs:rw:" + path,
	}
}

// assertLogContainsLine checks that the log contains at least one line
// that includes all of the given components (in any order).
func assertLogContainsLine(t *testing.T, logStr string, components ...string) {
	t.Helper()
	for line := range strings.SplitSeq(strings.TrimSpace(logStr), "\n") {
		allFound := true
		for _, component := range components {
			if !strings.Contains(line, component) {
				allFound = false
				break
			}
		}
		if allFound {
			return
		}
	}
	t.Errorf("no line found containing all components: %v", components)
}

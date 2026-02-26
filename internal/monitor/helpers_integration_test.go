package monitor_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/monitor"
	"github.com/nonpop/execave/internal/sandbox"
	"github.com/stretchr/testify/require"
)

type monitorTestEnv struct {
	t      *testing.T
	TmpDir string
	logger *accesslog.Logger
	mon    *monitor.Monitor
}

func newMonitorTestEnv(t *testing.T, setupConfig func(tmpDir string) *config.Config) *monitorTestEnv {
	t.Helper()

	stracePath, err := sandbox.ResolveStrace()
	require.NoError(t, err)

	tmpDir := t.TempDir()

	cfg := setupConfig(tmpDir)

	logger := accesslog.New(cfg.ManagedPaths)
	resolver := fsrules.NewAccessResolver(cfg.FSRules, cfg.ManagedPaths)
	mon := monitor.New("", stracePath, logger, resolver, nil, false, nil, nil, nil)

	return &monitorTestEnv{
		t:      t,
		TmpDir: tmpDir,
		logger: logger,
		mon:    mon,
	}
}

func (e *monitorTestEnv) run(cmd []string) (int, error) {
	return e.mon.Run(context.Background(), cmd) //nolint:wrapcheck
}

// readLog reconstructs a text log from in-memory entries for assertion helpers.
// Each line has the format: OPERATION\tTARGET\tRESULT\tRULE.
func (e *monitorTestEnv) readLog() string {
	e.t.Helper()
	entries := e.logger.Entries()
	var sb strings.Builder
	for _, entry := range entries {
		fmt.Fprintf(&sb, "%s\t%s\t%s\t%s\n", entry.Operation, entry.Target, entry.Result, entry.Rule)
	}
	logStr := sb.String()
	e.t.Logf("Log content:\n%s", logStr)
	return logStr
}

func roRule(path string) fsrules.AccessRule {
	return fsrules.AccessRule{
		Permission: fsrules.PermissionReadOnly,
		Path:       path,
		RawRule:    "fs:ro:" + path,
	}
}

func rwRule(path string) fsrules.AccessRule {
	return fsrules.AccessRule{
		Permission: fsrules.PermissionReadWrite,
		Path:       path,
		RawRule:    "fs:rw:" + path,
	}
}

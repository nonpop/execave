package monitor_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/binutil"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/exitcode"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/monitor"
	"github.com/nonpop/execave/internal/syscallrules"
	"github.com/stretchr/testify/require"
)

// syncBuffer is a mutex-protected bytes.Buffer safe for concurrent use.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type monitorTestEnv struct {
	t          *testing.T
	TmpDir     string
	logBuf     syncBuffer
	logger     *accesslog.Logger
	stracePath string
	resolver   *fsrules.Resolver
}

func newMonitorTestEnv(t *testing.T, setupConfig func(tmpDir string) *config.Config) *monitorTestEnv {
	t.Helper()

	stracePath, err := binutil.ResolveStrace()
	require.NoError(t, err)

	tmpDir := t.TempDir()

	cfg := setupConfig(tmpDir)

	env := &monitorTestEnv{
		t:      t,
		TmpDir: tmpDir,
	}

	logCfg := &accesslog.Config{ManagedPaths: cfg.ManagedPaths, ShowAllowed: true}
	env.logger = accesslog.New(&env.logBuf, logCfg)
	env.resolver = fsrules.NewResolver(cfg.FSRules, cfg.ManagedPaths)
	env.stracePath = stracePath

	return env
}

func (e *monitorTestEnv) run(cmd []string) (int, error) {
	return runMonitorDirect(e.t, e.stracePath, e.logger, e.resolver, cmd, 0, nil, nil, false)
}

// runMonitorDirect runs a command via strace with the given processor configuration.
// This is a test helper for tests that need to directly configure monitor parameters.
func runMonitorDirect(
	t testing.TB,
	stracePath string,
	logger *accesslog.Logger,
	fsResolver *fsrules.Resolver,
	cmd []string,
	setupExecves int,
	extraFile *os.File,
	syscallResolver *syscallrules.Resolver,
	unenforced bool,
) (int, error) {
	t.Helper()

	processor := monitor.New(logger, fsResolver, syscallResolver, setupExecves, unenforced)
	prepared, err := monitor.Prepare(stracePath, cmd, extraFile, syscallResolver, 3)
	if err != nil {
		return 1, err
	}

	execCmd := exec.CommandContext(context.Background(), prepared.StracePath, prepared.Args...) // #nosec G204
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.ExtraFiles = prepared.ExtraFiles

	if startErr := execCmd.Start(); startErr != nil {
		prepared.Abort()
		return 1, fmt.Errorf("start strace: %w", startErr)
	}
	prepared.Started()

	processingErrCh := make(chan error, 1)
	go func() {
		processingErrCh <- processor.Run(prepared.StraceReader)
		_ = prepared.StraceReader.Close()
	}()

	waitErr := execCmd.Wait()
	_ = prepared.StraceReader.Close()

	code, exitErr := exitcode.Extract(waitErr)
	if exitErr != nil {
		return code, fmt.Errorf("execute strace: %w", exitErr)
	}

	processingErr := <-processingErrCh
	if processingErr != nil {
		if !errors.Is(processingErr, os.ErrClosed) {
			return code, fmt.Errorf("process strace output: %w", processingErr)
		}
	}

	return code, nil
}

// readLog returns the accumulated text log output for assertion helpers.
func (e *monitorTestEnv) readLog() string {
	e.t.Helper()
	logStr := e.logBuf.String()
	e.t.Logf("Log content:\n%s", logStr)
	return logStr
}

func roRule(path string) fsrules.Rule {
	return fsrules.Rule{
		Permission: fsrules.PermissionReadOnly,
		Path:       path,
		RawRule:    "ro:" + path,
		SourcePath: "",
	}
}

func rwRule(path string) fsrules.Rule {
	return fsrules.Rule{
		Permission: fsrules.PermissionReadWrite,
		Path:       path,
		RawRule:    "rw:" + path,
		SourcePath: "",
	}
}

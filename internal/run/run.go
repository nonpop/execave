// Package run orchestrates the full sandbox execution pipeline.
//
// [Run] is the single entry point: config loading, signal setup, terminal
// management, proxy, sandbox, optional monitor, execution, and cleanup.
// [LoadRuntimeConfig] is also exposed for "execave config show".
package run

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/binutil"
	"github.com/nonpop/execave/internal/exitcode"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/monitor"
	"github.com/nonpop/execave/internal/netrules"
	"github.com/nonpop/execave/internal/proxy"
	"github.com/nonpop/execave/internal/sandbox"
	"github.com/nonpop/execave/internal/seccomp"
	"github.com/nonpop/execave/internal/syscallrules"
	"github.com/nonpop/execave/internal/tunnel"
)

// SandboxConfig holds parameters for [Run].
type SandboxConfig struct {
	ConfigPath    string         // Path to execave config file.
	TargetArgv    []string       // Command and arguments to execute.
	TunnelBinary  string         // Override tunnel binary; empty uses os.Executable().
	MonitorConfig *MonitorConfig // Nil disables monitoring.
}

// MonitorConfig holds parameters for access monitoring within [Run].
type MonitorConfig struct {
	File        string // Log output path; empty buffers to stderr after exit.
	LogAllowed  bool   // Include OK entries in output.
	Unsandboxed bool   // Skip bwrap/seccomp; run unsandboxed with observation only.
}

// Run executes the target command inside the sandbox. Returns the process exit code.
func Run(sandboxCfg SandboxConfig) (_ int, err error) {
	runtimeCfg, cleanup, err := LoadRuntimeConfig(sandboxCfg.ConfigPath)
	if err != nil {
		return 0, fmt.Errorf("load config: %w", err)
	}
	if sandboxCfg.TunnelBinary != "" {
		runtimeCfg.TunnelBinary = sandboxCfg.TunnelBinary
	}
	defer cleanup()

	cfg := runtimeCfg.Config

	// Prevent SIGINT from terminating the Go process: allows deferred cleanup
	// (terminal restore, proxy shutdown) to run.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT)

	// Ignore SIGTTOU so terminal ioctls (tcsetattr, tcflush, tcsetpgrp)
	// succeed when execave is in a background process group. This happens
	// when --new-session is skipped (Linux 6.2+): the sandboxed process can
	// call tcsetpgrp() to become the foreground group, and when it dies,
	// execave is left as a background group.
	//
	// Must use signal.Ignore (not signal.Notify): the kernel's
	// tty_check_change checks for SIG_IGN disposition specifically. A Go
	// runtime handler (signal.Notify) does not satisfy is_ignored(), causing
	// an infinite SIGTTOU/restart loop on terminal ioctls from a background
	// group.
	//
	// SIG_IGN is inherited by children across exec, but this is harmless:
	// interactive shells (bash, zsh) reset their own signal handlers on
	// startup, and non-interactive children don't use job control.
	signal.Ignore(syscall.SIGTTOU)

	// Restore terminal state on exit, even if command fails.
	// This prevents sandboxed processes from leaving the terminal in a bad state
	// (e.g., echo disabled, raw mode enabled).
	restoreTerminal := saveTerminalState()
	defer restoreTerminal()

	ctx := context.Background()
	monitored := sandboxCfg.MonitorConfig != nil

	// Set up log writer and accesslog.Logger.
	var logger *accesslog.Logger
	if monitored {
		monCfg := sandboxCfg.MonitorConfig
		homeDir, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return 0, fmt.Errorf("resolve user home directory: %w", homeErr)
		}

		var logWriter io.Writer
		if monCfg.File != "" {
			f, openErr := os.Create(monCfg.File) // #nosec G304 -- path is user-provided output path for text log
			if openErr != nil {
				return 0, fmt.Errorf("create log file %s: %w", monCfg.File, openErr)
			}
			defer f.Close() //nolint:errcheck
			logWriter = f
		} else {
			buf := new(bytes.Buffer)
			// No log file configured: buffer output and print to stderr after the run
			// (logger.Close, deferred below, flushes all entries to buf first).
			defer func() { _, _ = io.Copy(os.Stderr, buf) }()
			logWriter = buf
		}

		logCfg := &accesslog.Config{
			ManagedPaths: cfg.ManagedPaths,
			HomeDir:      homeDir,
			ConfigDir:    filepath.Dir(cfg.ConfigPaths[0]),
			ShowAllowed:  monCfg.LogAllowed,
		}
		logger = accesslog.New(logWriter, logCfg)
	}

	fsResolver := fsrules.NewResolver(cfg.FSRules, cfg.ManagedPaths)
	netResolver := netrules.NewResolver(cfg.NetRules)
	syscallResolver := syscallrules.NewResolver(cfg.SyscallRules, seccomp.RuleableSyscallNames())

	noSandbox := monitored && sandboxCfg.MonitorConfig.Unsandboxed
	httpProxy := proxy.New(logger, netResolver, runtimeCfg.UDSPath, noSandbox)
	if err := httpProxy.Start(); err != nil {
		return 0, fmt.Errorf("start proxy: %w", err)
	}
	defer func() {
		if stopErr := httpProxy.Stop(); stopErr != nil {
			err = errors.Join(err, fmt.Errorf("stop proxy: %w", stopErr))
		}
	}()

	if logger != nil {
		// logger.Close must run before the buffer-copy defer (so all log entries
		// are flushed to the buffer before it is copied to stderr) and before
		// f.Close (so all entries are written before the file is closed).
		// Since defers run LIFO, registering this defer last ensures it runs first.
		defer func() {
			if closeErr := logger.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close logger: %w", closeErr))
			}
		}()
	}

	drainStdin()

	// Build inner command: sandboxed via bwrap, or plain with optional tunnel prefix.
	// Resolve strace binary and check version.
	var stracePath string
	if monitored {
		stracePath, err = binutil.ResolveStrace()
		if err != nil {
			return 0, fmt.Errorf("resolve strace: %w", err)
		}
		if warn, verr := binutil.CheckStraceVersion(stracePath); verr != nil {
			return 0, fmt.Errorf("check strace version: %w", verr)
		} else if warn != "" {
			fmt.Fprintln(os.Stderr, "execave: warning:", warn)
		}
	}

	// Resolve bwrap binary and check version.
	sandboxed := !noSandbox
	var bwrapPath string
	if sandboxed {
		bwrapPath, err = binutil.ResolveBwrap()
		if err != nil {
			return 0, fmt.Errorf("resolve bwrap: %w", err)
		}
		if warn, verr := binutil.CheckBwrapVersion(bwrapPath); verr != nil {
			return 0, fmt.Errorf("check bwrap version: %w", verr)
		} else if warn != "" {
			fmt.Fprintln(os.Stderr, "execave: warning:", warn)
		}
	}
	argv := sandboxCfg.TargetArgv

	tunnelCmd := tunnel.WrapCommand(runtimeCfg.TunnelBinary, runtimeCfg.UDSPath, argv)

	var innerCmd []string
	var extraFile *os.File
	var cmdExtraFiles []*os.File
	var setupExecves int
	var unenforced bool

	// Go convention: cmd.ExtraFiles[i] = fd 3+i.
	const extraFilesBaseFD = 3

	if sandboxed {
		// Sandbox's seccomp pipe is always first in ExtraFiles.
		sc, cleanup, prepErr := sandbox.Prepare(bwrapPath, cfg, tunnelCmd, extraFilesBaseFD)
		if prepErr != nil {
			return 0, fmt.Errorf("prepare sandbox: %w", prepErr)
		}
		defer cleanup()
		innerCmd = append([]string{sc.BwrapPath}, sc.Args...)
		if monitored {
			extraFile = sc.ExtraFiles[0]
			setupExecves = sc.SetupExecves
		} else {
			cmdExtraFiles = sc.ExtraFiles
		}
	} else {
		innerCmd = tunnelCmd
		unenforced = true
	}

	// Wrap inner command with strace.
	var mc *monitor.MonitoredCommand
	var mon *monitor.Monitor
	var cmdPath string
	var cmdArgs []string
	if monitored {
		mon = monitor.New(logger, fsResolver, syscallResolver, setupExecves, unenforced)
		mc, err = monitor.Prepare(stracePath, innerCmd, extraFile, syscallResolver, extraFilesBaseFD)
		if err != nil {
			return 0, fmt.Errorf("prepare monitor: %w", err)
		}
		cmdExtraFiles = mc.ExtraFiles
		cmdPath = mc.StracePath
		cmdArgs = mc.Args
	} else {
		cmdPath = innerCmd[0]
		cmdArgs = innerCmd[1:]
	}

	cmd := exec.CommandContext(ctx, cmdPath, cmdArgs...) // #nosec G204 -- args built from validated config
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = cmdExtraFiles

	if startErr := cmd.Start(); startErr != nil {
		if monitored {
			mc.Abort()
		}
		return 1, fmt.Errorf("start %s: %w", cmdPath, startErr)
	}

	// Close parent-side pipe ends after child inherits them, and launch processing goroutine.
	var processingErrCh chan error
	if monitored {
		// Close parent-side pipe ends after child inherits them via ExtraFiles.
		mc.Started()
		processingErrCh = make(chan error, 1)
		go func() {
			processingErrCh <- mon.Run(mc.StraceReader)
			_ = mc.StraceReader.Close()
		}()
	}

	waitErr := cmd.Wait()

	// Close strace reader to unblock the processing goroutine.
	if monitored {
		// Close the read end to unblock the processing goroutine. When strace is
		// killed (context cancellation), descendant processes (bwrap, sandboxed
		// command) may briefly hold the pipe write end open — they inherit fd 3
		// from strace but never use it. Without this close, the processing
		// goroutine blocks on read waiting for EOF that won't come until all
		// descendants die, which delays all post-exit cleanup (terminal
		// restoration, screen clearing, etc.).
		// In the normal exit case this is harmless: strace has already closed its
		// write end and the goroutine has already reached EOF or is about to.
		_ = mc.StraceReader.Close()
	}

	// Reclaim foreground and clean terminal artifacts unconditionally.
	// Without --new-session (Linux 6.2+), the sandboxed process can take over
	// the foreground group and leave alt-screen artifacts regardless of monitoring.
	reclaimForeground()
	conditionalClearScreen()

	exitCode, exitErr := exitcode.Extract(waitErr)
	if exitErr != nil {
		return exitCode, fmt.Errorf("execute %s: %w", cmdPath, exitErr)
	}

	// Wait for processing goroutine.
	if monitored {
		processingErr := <-processingErrCh
		if processingErr != nil && ctx.Err() == nil {
			// Ignore pipe read errors caused by the forced close above.
			// When strace exits normally, we close straceR to unblock descendants
			// that inherited fd 3. This can race with the goroutine's read, causing
			// os.ErrClosed. This is benign and expected in normal exit scenarios.
			if !errors.Is(processingErr, os.ErrClosed) {
				return exitCode, fmt.Errorf("process strace output: %w", processingErr)
			}
		}
	}

	return exitCode, nil
}

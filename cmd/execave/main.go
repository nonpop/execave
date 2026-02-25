// Package main is the CLI entrypoint for execave.
package main

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
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/netrules"
	"github.com/nonpop/execave/internal/proxy"
	"github.com/nonpop/execave/internal/runner"
	"github.com/nonpop/execave/internal/sandbox"
	"github.com/nonpop/execave/internal/textlog"
	"github.com/nonpop/execave/internal/tunnel"
	"github.com/nonpop/execave/internal/webui"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	defaultConfigPath = "./execave.toml"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var configPath string
	var monitor string
	var noOpen bool
	var showAllowed bool
	var showNolog bool

	cmd := &cobra.Command{
		Use:   "execave [flags] [--] <command>",
		Short: "Filesystem sandbox for command execution",
		Long: `execave - Filesystem sandbox for command execution

Wraps command execution with bubblewrap to enforce filesystem access rules.`,
		Example: `  execave python
  execave --monitor -- bash -c 'ls /etc'
  execave --monitor=access.log -- bash -c 'ls /etc'`,
		Args: func(cmd *cobra.Command, args []string) error {
			// Check if -- was used
			argsLenAtDash := cmd.ArgsLenAtDash()
			if argsLenAtDash == -1 {
				// No -- found, treat all args as command
				if len(args) == 0 {
					return errors.New("no command specified")
				}
				return nil
			}
			// -- was used, check args after it
			if argsLenAtDash >= len(args) {
				return errors.New("no command specified after --")
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(c *cobra.Command, args []string) error {
			return runCommand(c, args, configPath, monitor, noOpen, showAllowed, showNolog)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath, "Configuration file path")
	cmd.Flags().StringVar(&monitor, "monitor", "", "Enable access monitoring. Without a value starts the web UI (opens browser). With a path writes text log to that file. With - writes text log to stderr after process exits.")
	cmd.Flags().Lookup("monitor").NoOptDefVal = "web"
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "Do not open the browser when --monitor is enabled")
	cmd.Flags().BoolVar(&showAllowed, "show-allowed", false, "Include OK entries in text log output (default: denied only). Also sets the initial 'Denied only' checkbox state in web UI mode.")
	cmd.Flags().BoolVar(&showNolog, "show-nolog", false, "Include entries matching nolog rules (default: hidden). Also sets the initial 'Apply nolog rules' checkbox state in web UI mode.")

	cmd.AddCommand(newNetworkTunnelCommand())

	return cmd
}

// newNetworkTunnelCommand creates the network-tunnel subcommand.
// This command runs inside the sandbox to bridge TCP to the proxy UDS.
func newNetworkTunnelCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "network-tunnel <uds-path> [--] <command>",
		Short:  "TCP-to-UDS bridge for network proxy (internal)",
		Hidden: false,
		Args:   cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			udsPath := args[0]

			// Find the command after optional "--"
			var command []string
			argsLenAtDash := cmd.ArgsLenAtDash()
			if argsLenAtDash == -1 {
				command = args[1:]
			} else {
				command = args[argsLenAtDash:]
			}

			if len(command) == 0 {
				return errors.New("no command specified")
			}

			exitCode, err := tunnel.Run(udsPath, command)
			if err != nil {
				return fmt.Errorf("run tunnel: %w", err)
			}
			os.Exit(exitCode)
			return nil
		},
	}
}

func runCommand(cmd *cobra.Command, args []string, configPath, monitor string, noOpen, showAllowed, showNolog bool) error {
	exitCode, err := runSandboxed(cmd, args, configPath, monitor, noOpen, showAllowed, showNolog)
	if err != nil {
		return err
	}
	os.Exit(exitCode)
	return nil
}

func runSandboxed(cmd *cobra.Command, args []string, configPath, monitor string, noOpen, showAllowed, showNolog bool) (int, error) {
	command := extractCommand(cmd, args)

	cfg, err := config.Load(configPath, sandbox.ManagedDirs)
	if err != nil {
		return 0, fmt.Errorf("load config from %s: %w", configPath, err)
	}

	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return 0, fmt.Errorf("resolve absolute path for config %s: %w", configPath, err)
	}

	// Prevent SIGINT from terminating the Go process so the processing goroutine
	// can drain remaining pipe data and write final access log entries after the
	// child exits.
	// See fix-sigint-access-log/design.md for why we use signal.Notify instead of signal.Ignore.
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

	// When monitoring is enabled, the runner manages the logger lifecycle
	// and updates the proxy via OnLoggerChange. Pass nil logger to the proxy.
	monitorEnabled := monitor != ""
	logger := setupAccessLog(monitorEnabled)
	proxyLogger := logger
	if monitorEnabled {
		proxyLogger = nil
	}

	netPath, httpProxy, proxyCleanup, err := setupNetworking(cfg, proxyLogger, monitorEnabled)
	if err != nil {
		return 0, err
	}
	if proxyCleanup != nil {
		defer proxyCleanup()
	}

	sb := sandbox.New(cfg, absConfigPath, netPath)

	if monitorEnabled {
		return runMonitored(ctx, cfg, absConfigPath, netPath, httpProxy, command, monitor, noOpen, showAllowed, showNolog, sigCh)
	}

	exitCode, err := sb.Run(ctx, command)
	if err != nil {
		return 0, fmt.Errorf("run sandbox: %w", err)
	}
	return exitCode, nil
}

// saveTerminalState saves the current terminal state and returns a function
// that restores it. Call the returned function via defer to ensure the terminal
// is restored even if the sandboxed process leaves it in a bad state.
func saveTerminalState() func() {
	stdinFd := int(os.Stdin.Fd())
	if !term.IsTerminal(stdinFd) {
		return func() {}
	}
	oldState, err := term.GetState(stdinFd)
	if err != nil {
		// IsTerminal just confirmed stdin is a terminal; GetState uses the
		// same ioctl so failure here means the fd was closed concurrently.
		panic(fmt.Sprintf("get terminal state after IsTerminal succeeded: %v", err))
	}
	// Ignore restore errors - terminal is already in unknown state.
	return func() { _ = term.Restore(stdinFd, oldState) }
}

// extractCommand extracts the command to run from cobra arguments.
func extractCommand(cmd *cobra.Command, args []string) []string {
	argsLenAtDash := cmd.ArgsLenAtDash()
	if argsLenAtDash == -1 {
		return args
	}
	return args[argsLenAtDash:]
}

// setupAccessLog initializes the access logger if monitoring is enabled.
func setupAccessLog(monitorEnabled bool) *accesslog.Logger {
	if !monitorEnabled {
		return nil
	}
	logger := accesslog.New(sandbox.ManagedDirs)
	return logger
}

// setupNetworking initializes the proxy and network path if net rules are present
// or if monitoring is enabled. When monitoring is enabled without net rules, the
// proxy starts with an empty rule set (deny-all) so that HTTP-proxy-aware
// programs' network access attempts are logged.
func setupNetworking(cfg *config.Config, logger *accesslog.Logger, monitorEnabled bool) (*sandbox.NetworkPath, *proxy.Proxy, func(), error) {
	if !cfg.HasNetRules() && !monitorEnabled {
		return nil, nil, nil, nil
	}
	netPath, proxyInstance, err := startProxy(cfg, logger)
	if err != nil {
		return nil, nil, nil, err
	}
	cleanup := func() {
		if err := proxyInstance.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "execave: stop proxy: %v\n", err)
		}
	}
	return netPath, proxyInstance, cleanup, nil
}

func startProxy(cfg *config.Config, logger *accesslog.Logger) (*sandbox.NetworkPath, *proxy.Proxy, error) {
	tmpDir, err := os.MkdirTemp("", "execave-proxy-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create proxy temp dir: %w", err)
	}

	udsPath := filepath.Join(tmpDir, "proxy.sock")

	netResolver := netrules.NewAccessResolver(cfg.NetRules)
	httpProxy := proxy.New(netResolver, logger)

	if err := httpProxy.Start(udsPath); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, nil, fmt.Errorf("start proxy: %w", err)
	}

	execaveBinary, err := os.Executable()
	if err != nil {
		_ = httpProxy.Stop()
		_ = os.RemoveAll(tmpDir)
		return nil, nil, fmt.Errorf("resolve execave binary path: %w", err)
	}

	netPath := &sandbox.NetworkPath{
		UDSPath:       udsPath,
		ExecaveBinary: execaveBinary,
	}

	return netPath, httpProxy, nil
}

// runMonitored runs the command inside a sandbox with strace-based filesystem
// access monitoring, dispatching to web UI or text log mode.
func runMonitored(ctx context.Context, cfg *config.Config, absConfigPath string, netPath *sandbox.NetworkPath, httpProxy *proxy.Proxy, command []string, monitorMode string, noOpen, showAllowed, showNolog bool, sigCh chan os.Signal) (int, error) {
	// Shared setup
	rnr := runner.New(cfg, absConfigPath, netPath)

	// Wire logger lifecycle: when the runner creates a fresh logger on each Start,
	// update the proxy so network access entries go to the same logger.
	if httpProxy != nil {
		rnr.OnLoggerChange = httpProxy.SetLogger
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return 0, fmt.Errorf("resolve user home directory: %w", err)
	}
	configDir := filepath.Dir(absConfigPath)

	fsRes := fsrules.NewLogResolver(cfg.FSLogRules)
	netRes := netrules.NewLogResolver(cfg.NetLogRules)

	if monitorMode == "web" {
		return runMonitoredWeb(ctx, cfg, absConfigPath, rnr, httpProxy, homeDir, configDir, command, noOpen, showAllowed, showNolog, fsRes, netRes, sigCh)
	}
	return runMonitoredText(ctx, cfg, rnr, homeDir, configDir, command, monitorMode, showAllowed, showNolog, fsRes, netRes)
}

// runMonitoredWeb runs the command under strace monitoring with a web UI.
func runMonitoredWeb(ctx context.Context, cfg *config.Config, absConfigPath string, rnr *runner.Runner, httpProxy *proxy.Proxy, homeDir, configDir string, command []string, noOpen, showAllowed, showNolog bool, fsRes *fsrules.LogResolver, netRes *netrules.LogResolver, sigCh chan os.Signal) (int, error) {
	// Read raw config file content for the web UI editor
	configContent, err := os.ReadFile(absConfigPath) // #nosec G304 -- absConfigPath is validated as absolute path
	if err != nil {
		return 0, fmt.Errorf("read config %s: %w", absConfigPath, err)
	}

	server := webui.New(rnr, command, homeDir, configDir, absConfigPath, string(configContent), sandbox.ManagedDirs, webui.FilterDefaults{ShowAllowed: showAllowed, ShowNolog: showNolog})
	server.SetLogResolvers(fsRes, netRes)

	// Wire config changes to update the proxy's net rules resolver
	server.OnConfigChange = func(newCfg *config.Config) {
		if httpProxy != nil {
			httpProxy.SetResolver(netrules.NewAccessResolver(newCfg.NetRules))
		}
	}

	if err := server.Start(ctx); err != nil {
		return 0, fmt.Errorf("start web UI server: %w", err)
	}
	url := server.URL()
	fmt.Fprintf(os.Stderr, "execave: monitor running at %s\n", url)
	if !noOpen {
		// Ignore errors: xdg-open may not be available on all systems
		_ = exec.CommandContext(ctx, "xdg-open", url).Start() // #nosec G204 -- url is constructed from server address and token
	}

	if err := rnr.Start(ctx, cfg, command); err != nil {
		return 0, fmt.Errorf("start initial run: %w", err)
	}

	// Wait for SIGINT
	<-sigCh

	// Wait for the active run to finish. The child already received SIGINT
	// via the process group and is dying — don't call Stop() which would
	// escalate to SIGKILL via context cancellation.
	statusCh := rnr.Subscribe()
	for rnr.Status().Running {
		<-statusCh
	}
	rnr.Unsubscribe(statusCh)

	status := rnr.Status()
	if status.Error != "" {
		return status.ExitCode, fmt.Errorf("run monitor+sandbox: %s", status.Error)
	}
	return status.ExitCode, nil
}

// runMonitoredText runs the command under strace monitoring with text log output.
// monitorPath is the output file path or "-" to buffer to stderr after process exit.
func runMonitoredText(ctx context.Context, cfg *config.Config, rnr *runner.Runner, homeDir, configDir string, command []string, monitorPath string, showAllowed, showNolog bool, fsRes *fsrules.LogResolver, netRes *netrules.LogResolver) (_ int, err error) {
	var out io.Writer
	var buf *bytes.Buffer

	if monitorPath == "-" {
		buf = new(bytes.Buffer)
		out = buf
	} else {
		logFile, createErr := os.Create(monitorPath) // #nosec G304 -- monitorPath is user-provided output path for text log
		if createErr != nil {
			return 0, fmt.Errorf("create text log file %s: %w", monitorPath, createErr)
		}
		defer func() {
			if closeErr := logFile.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close text log file %s: %w", monitorPath, closeErr))
			}
		}()
		out = logFile
	}

	logWriter := textlog.New(out, homeDir, configDir, showAllowed, showNolog, fsRes, netRes)

	if err := rnr.Start(ctx, cfg, command); err != nil {
		return 0, fmt.Errorf("start initial run: %w", err)
	}

	logger := rnr.Logger()

	writerCtx, writerCancel := context.WithCancel(ctx)
	writerErr := make(chan error, 1)
	go func() {
		writerErr <- logWriter.Run(writerCtx, logger)
	}()

	// Wait for the process to exit
	statusCh := rnr.Subscribe()
	for rnr.Status().Running {
		<-statusCh
	}
	rnr.Unsubscribe(statusCh)

	// Trigger final drain in the writer
	writerCancel()
	if writeErr := <-writerErr; writeErr != nil {
		err = errors.Join(err, fmt.Errorf("write text log: %w", writeErr))
	}

	// Flush buffered output for stderr mode after process exits
	if buf != nil {
		if _, copyErr := io.Copy(os.Stderr, buf); copyErr != nil {
			err = errors.Join(err, fmt.Errorf("flush text log to stderr: %w", copyErr))
		}
	}

	status := rnr.Status()
	if status.Error != "" {
		return status.ExitCode, fmt.Errorf("run text log+sandbox: %s", status.Error)
	}
	return status.ExitCode, err
}

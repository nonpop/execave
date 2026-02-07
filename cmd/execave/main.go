// Package main is the CLI entrypoint for execave.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/monitor"
	"github.com/nonpop/execave/internal/netrules"
	"github.com/nonpop/execave/internal/proxy"
	"github.com/nonpop/execave/internal/sandbox"
	"github.com/nonpop/execave/internal/tunnel"
	"github.com/spf13/cobra"
)

const (
	defaultConfigPath = "./execave.json"
	defaultLogPath    = "./execave-access.log"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var configPath string
	var monitorPath string

	cmd := &cobra.Command{
		Use:   "execave [flags] [--] <command>",
		Short: "Filesystem sandbox for command execution",
		Long: `execave - Filesystem sandbox for command execution

Wraps command execution with bubblewrap to enforce filesystem access rules.`,
		Example: `  execave python
  execave --monitor -- bash -c 'ls /etc'`,
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
			return runCommand(c, args, configPath, monitorPath)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath, "Configuration file path")
	cmd.Flags().StringVar(&monitorPath, "monitor", "", "Enable access monitoring (optionally specify log path)")
	cmd.Flags().Lookup("monitor").NoOptDefVal = defaultLogPath

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

func runCommand(cmd *cobra.Command, args []string, configPath, monitorPath string) error {
	exitCode, err := runSandboxed(cmd, args, configPath, monitorPath)
	if err != nil {
		return err
	}
	os.Exit(exitCode)
	return nil
}

func runSandboxed(cmd *cobra.Command, args []string, configPath, monitorPath string) (int, error) {
	command := extractCommand(cmd, args)

	cfg, err := config.Load(configPath, sandbox.ManagedDirs)
	if err != nil {
		return 0, fmt.Errorf("load config from %s: %w", configPath, err)
	}

	resolver := fsrules.NewResolver(cfg.FSRules, cfg.ManagedPaths)

	monitorEnabled := cmd.Flags().Changed("monitor")

	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return 0, fmt.Errorf("resolve absolute path for config %s: %w", configPath, err)
	}

	// Prevent SIGINT from terminating the Go process so it can process strace
	// output and write the access log after the child exits.
	// See fix-sigint-access-log/design.md for why we use signal.Notify instead of signal.Ignore.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT)

	ctx := context.Background()

	logger, logCleanup, err := setupAccessLog(monitorEnabled, monitorPath)
	if err != nil {
		return 0, err
	}
	if logCleanup != nil {
		defer logCleanup()
	}

	netPath, proxyCleanup, err := setupNetworking(cfg, logger, monitorEnabled)
	if err != nil {
		return 0, err
	}
	if proxyCleanup != nil {
		defer proxyCleanup()
	}

	sb := sandbox.New(cfg, absConfigPath, netPath)

	if monitorEnabled {
		return runMonitored(ctx, sb, logger, resolver, command)
	}

	exitCode, err := sb.Run(ctx, command)
	if err != nil {
		return 0, fmt.Errorf("run sandbox: %w", err)
	}
	return exitCode, nil
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
func setupAccessLog(monitorEnabled bool, monitorPath string) (*accesslog.Logger, func(), error) {
	if !monitorEnabled {
		return nil, nil, nil
	}
	logWriter, logCleanup, err := createAccessLogWriter(monitorPath)
	if err != nil {
		return nil, nil, err
	}
	logger := accesslog.New(logWriter, sandbox.ManagedDirs)
	return logger, logCleanup, nil
}

// setupNetworking initializes the proxy and network path if net rules are present
// or if monitoring is enabled. When monitoring is enabled without net rules, the
// proxy starts with an empty rule set (deny-all) so that HTTP-proxy-aware
// programs' network access attempts are logged.
func setupNetworking(cfg *config.Config, logger *accesslog.Logger, monitorEnabled bool) (*sandbox.NetworkPath, func(), error) {
	if !cfg.HasNetRules() && !monitorEnabled {
		return nil, nil, nil
	}
	netPath, proxyInstance, err := startProxy(cfg, logger)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		if err := proxyInstance.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "execave: stop proxy: %v\n", err)
		}
	}
	return netPath, cleanup, nil
}

func startProxy(cfg *config.Config, logger *accesslog.Logger) (*sandbox.NetworkPath, *proxy.Proxy, error) {
	tmpDir, err := os.MkdirTemp("", "execave-proxy-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create proxy temp dir: %w", err)
	}

	udsPath := filepath.Join(tmpDir, "proxy.sock")

	netResolver := netrules.NewResolver(cfg.NetRules)
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
// access monitoring.
func runMonitored(ctx context.Context, sb *sandbox.Sandbox, logger *accesslog.Logger, resolver *fsrules.Resolver, command []string) (int, error) {
	bwrapArgs := sb.BuildBwrapArgs(command)
	mon := monitor.New(logger, resolver, bwrapArgs, sb.HasNetworkPath())

	exitCode, err := mon.Run(ctx, command)
	if err != nil {
		return 0, fmt.Errorf("run monitor+sandbox: %w", err)
	}
	return exitCode, nil
}

func createAccessLogWriter(monitorPath string) (*bufio.Writer, func(), error) {
	logFile, err := os.Create(monitorPath) //nolint:gosec // monitorPath is user-provided CLI flag
	if err != nil {
		return nil, nil, fmt.Errorf("create access log %s: %w", monitorPath, err)
	}

	writer := bufio.NewWriter(logFile)

	cleanup := func() {
		if err := writer.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "execave: flush access log: %v\n", err)
		}
		_ = logFile.Close()
	}

	return writer, cleanup, nil
}

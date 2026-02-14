// Package main is the CLI entrypoint for execave.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/monitor"
	"github.com/nonpop/execave/internal/netrules"
	"github.com/nonpop/execave/internal/proxy"
	"github.com/nonpop/execave/internal/sandbox"
	"github.com/nonpop/execave/internal/tunnel"
	"github.com/nonpop/execave/internal/webui"
	"github.com/spf13/cobra"
)

const (
	defaultConfigPath = "./execave.json"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var configPath string
	var monitorPort string

	cmd := &cobra.Command{
		Use:   "execave [flags] [--] <command>",
		Short: "Filesystem sandbox for command execution",
		Long: `execave - Filesystem sandbox for command execution

Wraps command execution with bubblewrap to enforce filesystem access rules.`,
		Example: `  execave python
  execave --monitor=9876 -- bash -c 'ls /etc'`,
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
			return runCommand(c, args, configPath, monitorPort)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", defaultConfigPath, "Configuration file path")
	cmd.Flags().StringVar(&monitorPort, "monitor", "", "Enable access monitoring with web UI on specified port (e.g., --monitor=9876)")

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

func runCommand(cmd *cobra.Command, args []string, configPath, monitorPort string) error {
	exitCode, err := runSandboxed(cmd, args, configPath, monitorPort)
	if err != nil {
		return err
	}
	os.Exit(exitCode)
	return nil
}

func runSandboxed(cmd *cobra.Command, args []string, configPath, monitorPort string) (int, error) {
	command := extractCommand(cmd, args)

	cfg, err := config.Load(configPath, sandbox.ManagedDirs)
	if err != nil {
		return 0, fmt.Errorf("load config from %s: %w", configPath, err)
	}

	resolver := fsrules.NewResolver(cfg.FSRules, cfg.ManagedPaths)

	monitorEnabled := cmd.Flags().Changed("monitor")

	// Validate monitor port if monitoring is enabled
	if monitorEnabled {
		if monitorPort == "" {
			return 0, errors.New("--monitor requires a port number (e.g., --monitor=9876)")
		}
		if err := validatePort(monitorPort); err != nil {
			return 0, fmt.Errorf("invalid port for --monitor: %w", err)
		}
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

	ctx := context.Background()

	logger := setupAccessLog(monitorEnabled)

	netPath, proxyCleanup, err := setupNetworking(cfg, logger, monitorEnabled)
	if err != nil {
		return 0, err
	}
	if proxyCleanup != nil {
		defer proxyCleanup()
	}

	sb := sandbox.New(cfg, absConfigPath, netPath)

	if monitorEnabled {
		return runMonitored(ctx, sb, logger, resolver, command, monitorPort, sigCh)
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
func setupAccessLog(monitorEnabled bool) *accesslog.Logger {
	if !monitorEnabled {
		return nil
	}
	logger := accesslog.New(sandbox.ManagedDirs)
	return logger
}

// validatePort validates that the given string is a valid port number (1-65535).
func validatePort(port string) error {
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port must be a number: %w", err)
	}
	if portNum < 0 || portNum > 65535 {
		return fmt.Errorf("port must be between 0 and 65535, got %d", portNum)
	}
	return nil
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
// access monitoring and web UI.
func runMonitored(ctx context.Context, sb *sandbox.Sandbox, logger *accesslog.Logger, resolver *fsrules.Resolver, command []string, port string, sigCh chan os.Signal) (int, error) {
	// Create run status tracker
	status := newStatusTracker(command)

	// Start web UI server
	server := webui.New(logger, status, port)
	if err := server.Start(ctx); err != nil {
		return 0, fmt.Errorf("start web UI server: %w", err)
	}
	fmt.Fprintf(os.Stderr, "execave: monitor running at %s\n", server.URL())

	status.SetRunning()

	// Run sandbox with monitoring
	bwrapArgs := sb.BuildBwrapArgs(command)
	mon := monitor.New(logger, resolver, bwrapArgs, sb.HasNetworkPath())
	exitCode, runErr := mon.Run(ctx, command)

	status.SetExited(exitCode, runErr)

	fmt.Fprintf(os.Stderr, "execave: process exited with code %d. Monitor still running at %s\n", exitCode, server.URL())
	fmt.Fprintf(os.Stderr, "execave: Press Ctrl-C to stop monitor and exit\n")

	// Wait for SIGINT then exit immediately
	<-sigCh

	if runErr != nil {
		return 0, fmt.Errorf("run monitor+sandbox: %w", runErr)
	}
	return exitCode, nil
}

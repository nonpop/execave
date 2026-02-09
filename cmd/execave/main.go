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
	"github.com/nonpop/execave/internal/sandbox"
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

	return cmd
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
	var command []string
	argsLenAtDash := cmd.ArgsLenAtDash()
	if argsLenAtDash == -1 {
		command = args
	} else {
		command = args[argsLenAtDash:]
	}

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
	if monitorEnabled {
		return runMonitored(ctx, cfg, absConfigPath, monitorPath, resolver, command)
	}

	sb := sandbox.New(cfg, absConfigPath)
	exitCode, err := sb.Run(ctx, command)
	if err != nil {
		return 0, fmt.Errorf("run sandbox: %w", err)
	}
	return exitCode, nil
}

// runMonitored runs the command inside a sandbox with strace-based filesystem
// access monitoring. It writes the access log to monitorPath.
func runMonitored(ctx context.Context, cfg *config.Config, absConfigPath, monitorPath string, resolver *fsrules.Resolver, command []string) (int, error) {
	logFile, err := os.Create(monitorPath) //nolint:gosec // monitorPath is user-provided CLI flag
	if err != nil {
		return 0, fmt.Errorf("create access log %s: %w", monitorPath, err)
	}
	defer func() {
		_ = logFile.Close() // Best effort close
	}()

	writer := bufio.NewWriter(logFile)
	defer func() {
		if err := writer.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "execave: flush access log: %v\n", err)
		}
	}()
	logger := accesslog.New(writer, sandbox.ManagedDirs)

	sb := sandbox.New(cfg, absConfigPath)
	bwrapArgs := sb.BuildBwrapArgs(command)
	mon := monitor.New(logger, resolver, bwrapArgs)

	exitCode, err := mon.Run(ctx, command)
	if err != nil {
		return 0, fmt.Errorf("run monitor+sandbox: %w", err)
	}
	return exitCode, nil
}

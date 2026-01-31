// Package main is the CLI entrypoint for execave.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/monitor"
	"github.com/nonpop/execave/internal/rules"
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
	var command []string
	argsLenAtDash := cmd.ArgsLenAtDash()
	if argsLenAtDash == -1 {
		command = args
	} else {
		command = args[argsLenAtDash:]
	}

	cfg, err := config.Load(configPath, sandbox.ManagedDirs)
	if err != nil {
		return fmt.Errorf("load config from %s: %w", configPath, err)
	}

	resolver := rules.New(cfg)

	monitorEnabled := cmd.Flags().Changed("monitor")

	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("resolve absolute path for config %s: %w", configPath, err)
	}

	ctx := context.Background()
	var exitCode int
	if monitorEnabled {
		// strace wraps bwrap
		sb := sandbox.New(cfg, absConfigPath)
		bwrapArgs := sb.BuildBwrapArgs(command)
		mon := monitor.New(monitorPath, resolver, bwrapArgs)

		exitCode, err = mon.Run(ctx, command)
		if err != nil {
			return fmt.Errorf("run monitor+sandbox: %w", err)
		}
	} else {
		sb := sandbox.New(cfg, absConfigPath)
		exitCode, err = sb.Run(ctx, command)
		if err != nil {
			return fmt.Errorf("run sandbox: %w", err)
		}
	}

	os.Exit(exitCode)
	return nil
}

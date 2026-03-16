package commands

import (
	"fmt"
	"os"

	"github.com/nonpop/execave/internal/run"
	"github.com/spf13/cobra"
)

func init() {
	monitorCmd.Flags().StringVar(&monitorOutputPath, "output-path", "", "Write text log to this file. If not set, log is written to stderr after the command exits.")
	monitorCmd.Flags().BoolVar(&monitorShowAllowed, "show-allowed", false, "Include OK entries in text log output (default: denied only).")
	monitorCmd.Flags().BoolVar(&monitorNoSandbox, "no-sandbox", false, "Run WITHOUT sandboxing (default: sandboxed).")
	rootCmd.AddCommand(monitorCmd)
}

var (
	monitorOutputPath  string
	monitorShowAllowed bool
	monitorNoSandbox   bool
)

var monitorCmd = &cobra.Command{
	Use:          "monitor [flags] [--] TARGET_COMMAND [ARG...]",
	Short:        "Run a command with sandbox policy and access monitoring",
	Args:         validateTargetArgv,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		targetArgv := args
		argsLenAtDash := cmd.ArgsLenAtDash()
		if argsLenAtDash >= 0 {
			targetArgv = args[argsLenAtDash:]
		}

		cliRules, err := buildCLIRules(cmd)
		if err != nil {
			return err
		}
		sandboxCfg := run.SandboxConfig{
			ConfigPath:   configPath,
			CLIRules:     cliRules,
			TargetArgv:   targetArgv,
			TunnelBinary: "",
			MonitorConfig: &run.MonitorConfig{
				File:        monitorOutputPath,
				LogAllowed:  monitorShowAllowed,
				Unsandboxed: monitorNoSandbox,
			},
		}

		exitCode, err := run.Run(sandboxCfg)
		if err != nil {
			return fmt.Errorf("run: %w", err)
		}
		os.Exit(exitCode)
		return nil
	},
}

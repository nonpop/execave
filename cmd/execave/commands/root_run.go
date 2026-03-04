// Package commands defines the cobra command tree for execave.
package commands

import (
	"errors"
	"os"
	"strings"

	"github.com/nonpop/execave/internal/run"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", defaultConfigPath, "Configuration file path")
	rootCmd.AddCommand(runCmd)
	rootCmd.SetUsageFunc(rootUsageFunc)
}

const defaultConfigPath = "./execave.toml"

// configPath is the --config flag value shared by all subcommands.
var configPath string

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func rootUsageFunc(cmd *cobra.Command) error {
	if cmd != rootCmd {
		cmd.Printf("Usage:\n  %s\n", cmd.UseLine())
		if cmd.HasAvailableSubCommands() {
			cmd.Print("\nSubcommands:\n")
			for _, sub := range cmd.Commands() {
				if sub.IsAvailableCommand() || sub.Name() == "help" {
					cmd.Printf("  %s%s%s\n", sub.Name(), strings.Repeat(" ", 16-len(sub.Name())), sub.Short)
				}
			}
		}
		if cmd.HasAvailableFlags() {
			cmd.Printf("\nFlags:\n%s", cmd.Flags().FlagUsages())
		}
		return nil
	}
	usage := `Usage:
  execave [--config PATH] [--] TARGET_COMMAND [ARG...]
  execave [--config PATH] SUBCOMMAND [flags]

Subcommands:
`
	for _, subcmd := range cmd.Commands() {
		if subcmd.IsAvailableCommand() || subcmd.Name() == "help" {
			usage += "  " + subcmd.Name() + strings.Repeat(" ", 16-len(subcmd.Name())) + subcmd.Short + "\n"
		}
	}
	usage += "\nFlags:\n"
	usage += cmd.LocalFlags().FlagUsages()
	cmd.Print(usage)
	return nil
}

// rootCmd is the root cobra command for execave.
var rootCmd = &cobra.Command{
	Use:   "execave",
	Short: "Policy sandbox and monitor for command execution",
	Long: `execave - Policy sandbox and monitor for command execution

Runs a target command with bubblewrap-enforced sandbox policy and optional access monitoring.`,
	Example: `  execave run -- python
  execave -- python
  execave monitor --output - -- bash -c 'ls /etc'
  execave config show`,
	Args:          validateTargetArgv,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCommand(cmd, args, configPath, "", false, false, false)
	},
}

// runCmd is an alias for the root command.
var runCmd = &cobra.Command{
	Use:          "run [flags] [--] TARGET_COMMAND [ARG...]",
	Short:        "Run a command with sandbox policy",
	Args:         validateTargetArgv,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCommand(cmd, args, configPath, "", false, false, false)
	},
}

// TODO: use extractCommand?
func validateTargetArgv(cmd *cobra.Command, args []string) error {
	argsLenAtDash := cmd.ArgsLenAtDash()
	if argsLenAtDash == -1 {
		if len(args) == 0 {
			return errors.New("no command specified")
		}
		return nil
	}
	if argsLenAtDash >= len(args) {
		return errors.New("no command specified")
	}
	return nil
}

func runCommand(cmd *cobra.Command, args []string, cfgPath, monitor string, showAllowed, showNolog bool, noSandbox bool) error {
	exitCode, err := run.Run(extractCommand(cmd, args), cfgPath, monitor, showAllowed, showNolog, noSandbox)
	if err != nil {
		return err
	}
	os.Exit(exitCode)
	return nil
}

// extractCommand extracts the command to run from cobra arguments.
func extractCommand(cmd *cobra.Command, args []string) []string {
	argsLenAtDash := cmd.ArgsLenAtDash()
	if argsLenAtDash == -1 {
		return args
	}
	return args[argsLenAtDash:]
}

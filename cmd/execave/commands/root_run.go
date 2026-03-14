package commands

import (
	"errors"
	"fmt"
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

// subcmdNameWidth is the column width for subcommand name alignment in usage output.
const subcmdNameWidth = 16

// configPath is the --config flag value shared by all subcommands.
var configPath string

// Execute runs the root Cobra command.
func Execute() error {
	return rootCmd.Execute() //nolint:wrapcheck
}

func rootUsageFunc(cmd *cobra.Command) error {
	if cmd != rootCmd {
		cmd.Printf("Usage:\n  %s\n", cmd.UseLine())
		if cmd.HasAvailableSubCommands() {
			cmd.Print("\nSubcommands:\n")
			for _, sub := range cmd.Commands() {
				if sub.IsAvailableCommand() || sub.Name() == "help" {
					cmd.Printf("  %s%s%s\n", sub.Name(), strings.Repeat(" ", subcmdNameWidth-len(sub.Name())), sub.Short)
				}
			}
		}
		if cmd.HasAvailableFlags() {
			cmd.Printf("\nFlags:\n%s", cmd.Flags().FlagUsages())
		}
		return nil
	}
	var usage strings.Builder
	usage.WriteString(`Usage:
  execave [--config PATH] [--] TARGET_COMMAND [ARG...]
  execave [--config PATH] SUBCOMMAND [flags]

Subcommands:
`)
	for _, subcmd := range cmd.Commands() {
		if subcmd.IsAvailableCommand() || subcmd.Name() == "help" {
			usage.WriteString("  " + subcmd.Name() + strings.Repeat(" ", subcmdNameWidth-len(subcmd.Name())) + subcmd.Short + "\n")
		}
	}
	usage.WriteString("\nFlags:\n")
	usage.WriteString(cmd.LocalFlags().FlagUsages())
	cmd.Print(usage.String())
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
  execave monitor --output-path /tmp/access.log -- bash -c 'ls /etc'
  execave config show`,
	Args:          validateTargetArgv,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runCommand,
}

// runCmd is an alias for the root command.
var runCmd = &cobra.Command{
	Use:          "run [flags] [--] TARGET_COMMAND [ARG...]",
	Short:        "Run a command with sandbox policy",
	Args:         validateTargetArgv,
	SilenceUsage: true,
	RunE:         runCommand,
}

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

func runCommand(cmd *cobra.Command, args []string) error {
	targetArgv := args
	argsLenAtDash := cmd.ArgsLenAtDash()
	if argsLenAtDash >= 0 {
		targetArgv = args[argsLenAtDash:]
	}

	sandboxCfg := run.SandboxConfig{
		ConfigPath:    configPath,
		TargetArgv:    targetArgv,
		TunnelBinary:  "",
		MonitorConfig: nil,
	}

	exitCode, err := run.Run(sandboxCfg)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	os.Exit(exitCode)
	return nil
}

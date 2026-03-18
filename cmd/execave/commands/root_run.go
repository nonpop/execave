package commands

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/run"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", defaultConfigPath, "Configuration file path")
	rootCmd.PersistentFlags().StringArrayVar(&cliFSRules, "fs", nil, "Filesystem rule (repeatable, e.g. ro:/usr)")
	rootCmd.PersistentFlags().StringArrayVar(&cliNetRules, "net", nil, "Network rule (repeatable, e.g. http:example.com:443)")
	rootCmd.PersistentFlags().StringArrayVar(&cliSyscallRules, "syscall", nil, "Syscall rule (repeatable, e.g. allow:ptrace)")
	rootCmd.PersistentFlags().StringArrayVar(&cliEnvRules, "env", nil, "Env rule (repeatable, e.g. pass:HOME)")
	rootCmd.PersistentFlags().StringArrayVar(&cliExtends, "extends", nil, "Extend a base config file (repeatable, resolved relative to cwd)")
	rootCmd.PersistentFlags().BoolVar(&noConfig, "no-config", false, "Run without a config file (mutually exclusive with --config)")
	rootCmd.AddCommand(runCmd)
	rootCmd.SetUsageFunc(rootUsageFunc)
}

const defaultConfigPath = "./execave.toml"

// subcmdNameWidth is the column width for subcommand name alignment in usage output.
const subcmdNameWidth = 16

var (
	// configPath is the --config flag value shared by all subcommands.
	configPath string
	// CLI rule flags shared by all subcommands.
	cliFSRules      []string
	cliNetRules     []string
	cliSyscallRules []string
	cliEnvRules     []string
	cliExtends      []string
	noConfig        bool
)

// buildCLIRules builds a config.CLIRules from the current persistent flag values.
// cmd is used to determine whether --config was explicitly set.
// Returns an error if --config and --no-config are both set.
func buildCLIRules(cmd *cobra.Command) (config.CLIRules, error) {
	configChanged := cmd.Root().PersistentFlags().Lookup("config").Changed
	if noConfig && configChanged {
		return config.CLIRules{}, errors.New("--config and --no-config are mutually exclusive")
	}
	return config.CLIRules{
		FS:                  cliFSRules,
		Net:                 cliNetRules,
		Syscall:             cliSyscallRules,
		Env:                 cliEnvRules,
		Extends:             cliExtends,
		NoConfig:            noConfig,
		ConfigExplicitlySet: configChanged,
	}, nil
}

// Execute runs the root Cobra command.
func Execute() error {
	return rootCmd.Execute() //nolint:wrapcheck
}

// configFlagNames are the persistent flags in the Configuration group.
var configFlagNames = []string{"config", "no-config", "extends"}

// ruleFlagNames are the persistent flags in the Rules group.
var ruleFlagNames = []string{"fs", "net", "syscall", "env"}

// groupedFlagUsages renders flags from flags into labelled groups: Configuration, Rules, and
// Other (catch-all for any future flags). Each group is only included when non-empty.
func groupedFlagUsages(flags *pflag.FlagSet) string {
	groups := []struct {
		header string
		names  []string
	}{
		{"Configuration", configFlagNames},
		{"Rules", ruleFlagNames},
	}

	knownNames := make(map[string]bool)
	for _, g := range groups {
		for _, n := range g.names {
			knownNames[n] = true
		}
	}

	var other pflag.FlagSet
	flags.VisitAll(func(f *pflag.Flag) {
		if !knownNames[f.Name] {
			other.AddFlag(f)
		}
	})

	var sb strings.Builder
	for _, group := range groups {
		var fs pflag.FlagSet
		for _, name := range group.names {
			if f := flags.Lookup(name); f != nil {
				fs.AddFlag(f)
			}
		}
		if usages := fs.FlagUsages(); usages != "" {
			sb.WriteString("\n" + group.header + ":\n")
			sb.WriteString(usages)
		}
	}
	if usages := other.FlagUsages(); usages != "" {
		sb.WriteString("\nOther:\n")
		sb.WriteString(usages)
	}
	return sb.String()
}

//nolint:cyclop,nestif
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
		if cmd.HasAvailableLocalFlags() {
			cmd.Printf("\nFlags:\n%s", cmd.LocalFlags().FlagUsages())
		}
		if cmd.HasAvailableInheritedFlags() {
			cmd.Print(groupedFlagUsages(cmd.InheritedFlags()))
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
	usage.WriteString(groupedFlagUsages(cmd.LocalFlags()))
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

	cliRules, err := buildCLIRules(cmd)
	if err != nil {
		return err
	}
	sandboxCfg := run.SandboxConfig{
		ConfigPath:    configPath,
		CLIRules:      cliRules,
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

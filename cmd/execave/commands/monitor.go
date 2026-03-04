package commands

import "github.com/spf13/cobra"

func init() {
	// TODO: change to "output-path"? And write to stdout instead?
	monitorCmd.Flags().StringVar(&monitorOutputPath, "output", "", "Text log output path (default: write to stderr after exit).")
	monitorCmd.Flags().BoolVar(&monitorShowAllowed, "show-allowed", false, "Include OK entries in text log output (default: denied only).")
	monitorCmd.Flags().BoolVar(&monitorShowNolog, "show-nolog", false, "Include entries matching nolog rules (default: hidden).")
	monitorCmd.Flags().BoolVar(&monitorNoSandbox, "no-sandbox", false, "Run WITHOUT sandboxing (default: sandboxed).")
	rootCmd.AddCommand(monitorCmd)
}

var (
	monitorOutputPath  string
	monitorShowAllowed bool
	monitorShowNolog   bool
	monitorNoSandbox   bool
)

var monitorCmd = &cobra.Command{
	Use:          "monitor [flags] [--] TARGET_COMMAND [ARG...]",
	Short:        "Run a command with sandbox policy and access monitoring",
	Args:         validateTargetArgv,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCommand(cmd, args, configPath, monitorOutputPath, monitorShowAllowed, monitorShowNolog, monitorNoSandbox)
	},
}

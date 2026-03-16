package commands

import (
	"fmt"
	"io"
	"os"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/run"
	"github.com/spf13/cobra"
)

func init() {
	configCmd.AddCommand(configShowCmd)
	rootCmd.AddCommand(configCmd)
}

var configCmd = &cobra.Command{
	Use:          "config",
	Short:        "Configuration inspection commands",
	SilenceUsage: true,
}

var configShowCmd = &cobra.Command{
	Use:          "show",
	Short:        "Show the effective merged configuration as TOML",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return showConfig(cmd)
	},
}

func showConfig(cmd *cobra.Command) error {
	cliRules, err := buildCLIRules(cmd)
	if err != nil {
		return err
	}
	runtimeCfg, cleanup, err := run.LoadRuntimeConfig(configPath, cliRules)
	if err != nil {
		return fmt.Errorf("load effective config: %w", err)
	}
	defer cleanup()

	rendered := config.RenderEffectiveTOML(runtimeCfg.Config)

	if _, err := io.WriteString(os.Stdout, rendered); err != nil {
		return fmt.Errorf("write effective config output: %w", err)
	}
	return nil
}

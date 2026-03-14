package commands

import (
	"errors"
	"fmt"
	"os"

	"github.com/nonpop/execave/internal/tunnel"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(networkTunnelCmd)
}

// networkTunnelCmd runs inside the sandbox to bridge TCP to the proxy UDS.
var networkTunnelCmd = &cobra.Command{
	Use:   "network-tunnel UDS_PATH [flags] [--] TARGET_COMMAND [ARG...]",
	Short: "TCP-to-UDS bridge for network proxy (internal)",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runTunnel,
}

func runTunnel(cmd *cobra.Command, args []string) error {
	udsPath := args[0]

	// Find the argv after optional "--"
	var targetArgv []string
	argsLenAtDash := cmd.ArgsLenAtDash()
	if argsLenAtDash == -1 {
		targetArgv = args[1:]
	} else {
		targetArgv = args[argsLenAtDash:]
	}

	if len(targetArgv) == 0 {
		return errors.New("no command specified")
	}

	exitCode, err := tunnel.Run(udsPath, targetArgv)
	if err != nil {
		return fmt.Errorf("run tunnel: %w", err)
	}
	os.Exit(exitCode)
	return nil
}

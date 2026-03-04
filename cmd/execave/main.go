// Package main is the CLI entrypoint for execave.
package main

import (
	"fmt"
	"os"

	"github.com/nonpop/execave/cmd/execave/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

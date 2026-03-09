// Package main is the execave binary entrypoint.
// All logic lives in [commands] and the internal packages.
package main

import (
	"fmt"
	"os"

	"github.com/nonpop/execave/cmd/execave/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "execave: error: %v\n", err)
		os.Exit(1)
	}
}

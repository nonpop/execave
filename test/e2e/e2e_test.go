// Package e2e_test contains end-to-end tests for the execave CLI.
// These tests invoke the binary directly and verify behavior for all openspec scenarios.
package e2e_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var binaryPath string //nolint:gochecknoglobals

// TestMain builds the execave binary once for all tests.
func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}

func testMain(m *testing.M) int {
	// Build binary to temp location
	tmpDir, err := os.MkdirTemp("", "execave-e2e-*")
	if err != nil {
		panic("failed to create temp dir: " + err.Error())
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	binaryPath = filepath.Join(tmpDir, "execave")

	// Find the project root (two levels up from test/e2e)
	wd, err := os.Getwd()
	if err != nil {
		panic("failed to get working directory: " + err.Error())
	}
	projectRoot := filepath.Join(wd, "..", "..")

	// Build the binary
	cmd := exec.CommandContext(context.Background(), "go", "build", "-o", binaryPath, "./cmd/execave") // #nosec G204 -- test code with controlled args
	cmd.Dir = projectRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic("failed to build execave binary: " + err.Error())
	}

	// Run tests (cleanup handled by defer)
	return m.Run()
}

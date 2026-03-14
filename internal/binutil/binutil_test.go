package binutil_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/binutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeVersionBinary creates a shell script that prints output exactly when invoked with --version.
// Callers control newlines; pass "\n"-terminated strings for normal output, "" for empty output.
// The script is not root-owned, so it can only be used with Check*Version directly,
// not ResolveBwrap/ResolveStrace which validate root ownership.
func fakeVersionBinary(t *testing.T, name, output string) string {
	t.Helper()
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, name)
	content := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\n", output)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o755)) // #nosec G306 -- test script needs execute permission
	return p
}

func TestInterpreterPath_StaticBinary(t *testing.T) {
	// Build a static Go binary (CGO_ENABLED=0 produces static binaries).
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "static")
	src := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o600))

	cmd := exec.Command("go", "build", "-o", binPath, src) // #nosec G204 -- binPath and src are constructed from t.TempDir()
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	t.Log(string(out))
	require.NoError(t, err)

	interp := binutil.InterpreterPath(binPath)

	assert.Empty(t, interp)
}

func TestInterpreterPath_NonexistentPath(t *testing.T) {
	interp := binutil.InterpreterPath("/nonexistent/binary")

	assert.Empty(t, interp)
}

func TestCheckBwrapVersion(t *testing.T) {
	cases := []struct {
		name        string
		versionLine string
		wantWarn    bool
		wantErr     string
	}{
		{name: "older_minor_incompatible", versionLine: "bwrap 0.10.0\n", wantWarn: false, wantErr: "incompatible"},
		{name: "pinned_compatible", versionLine: "bwrap 0.11.0\n", wantWarn: false, wantErr: ""},
		{name: "same_minor_higher_patch_compatible", versionLine: "bwrap 0.11.5\n", wantWarn: false, wantErr: ""},
		{name: "newer_minor_warns", versionLine: "bwrap 0.12.0\n", wantWarn: true, wantErr: ""},
		{name: "major_bump_incompatible", versionLine: "bwrap 1.0.0\n", wantWarn: false, wantErr: "incompatible"},
		{name: "trailing_text", versionLine: "bwrap 0.11.5\nsome other line\n", wantWarn: false, wantErr: ""},
		{name: "empty_output", versionLine: "", wantWarn: false, wantErr: "unexpected output"},
		{name: "no_version_token", versionLine: "bwrap\n", wantWarn: false, wantErr: "unexpected output"},
		{name: "non_numeric", versionLine: "bwrap notaversion\n", wantWarn: false, wantErr: "unexpected output"},
		{name: "missing_patch", versionLine: "bwrap 0.11\n", wantWarn: false, wantErr: "unexpected output"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			fakeBwrap := fakeVersionBinary(t, "bwrap", tt.versionLine)
			warn, err := binutil.CheckBwrapVersion(context.Background(), fakeBwrap)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				if tt.wantWarn {
					assert.NotEmpty(t, warn)
				} else {
					assert.Empty(t, warn)
				}
			}
		})
	}
}

func TestCheckStraceVersion(t *testing.T) {
	cases := []struct {
		name        string
		versionLine string
		wantWarn    bool
		wantErr     string
	}{
		{name: "older_minor_incompatible", versionLine: "strace -- version 6.18\n", wantWarn: false, wantErr: "incompatible"},
		{name: "pinned_compatible", versionLine: "strace -- version 6.19\n", wantWarn: false, wantErr: ""},
		{name: "newer_minor_warns", versionLine: "strace -- version 6.20\n", wantWarn: true, wantErr: ""},
		{name: "major_bump_incompatible", versionLine: "strace -- version 7.0\n", wantWarn: false, wantErr: "incompatible"},
		{name: "second_line", versionLine: "strace\nversion 6.19 something\n", wantWarn: false, wantErr: ""},
		{name: "extracts_first_match", versionLine: "strace 6.19 (other 7.0)\n", wantWarn: false, wantErr: ""},
		{name: "empty_output", versionLine: "", wantWarn: false, wantErr: "no version found"},
		{name: "no_version_match", versionLine: "strace\nno version here\n", wantWarn: false, wantErr: "no version found"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			fakeStrace := fakeVersionBinary(t, "strace", tt.versionLine)
			warn, err := binutil.CheckStraceVersion(context.Background(), fakeStrace)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				if tt.wantWarn {
					assert.NotEmpty(t, warn)
				} else {
					assert.Empty(t, warn)
				}
			}
		})
	}
}

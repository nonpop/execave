package tunnel_test

import (
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TunnelFailureIsFailClosed_TunnelUDSInaccessible(t *testing.T) {
	udsPath := filepath.Join(t.TempDir(), "nonexistent.sock")

	exitCode, err := tunnel.Run(udsPath, []string{"sh", "-c", `
		! curl -s --proxy "$HTTP_PROXY" --max-time 2 http://test.local/ 2>/dev/null
	`})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

func TestWrapCommand(t *testing.T) {
	got := tunnel.WrapCommand("/usr/bin/execave", "/tmp/proxy.sock", []string{"echo", "hello"})
	assert.Equal(t, []string{"/usr/bin/execave", "network-tunnel", "/tmp/proxy.sock", "--", "echo", "hello"}, got)
}

func TestWrapCommand_EmptyCommandPanics(t *testing.T) {
	assert.Panics(t, func() {
		tunnel.WrapCommand("/usr/bin/execave", "/tmp/proxy.sock", []string{})
	})
}

func TestRun_NoCommand(t *testing.T) {
	exitCode, err := tunnel.Run("/nonexistent.sock", nil)
	require.ErrorContains(t, err, "no command specified")
	assert.Equal(t, 1, exitCode)
}

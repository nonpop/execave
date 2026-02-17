package tunnel_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRun_ExitCodePropagation(t *testing.T) {
	udsPath := startEchoUDS(t)

	exitCode, err := tunnel.Run(udsPath, []string{"sh", "-c", "exit 42"})
	require.NoError(t, err)
	assert.Equal(t, 42, exitCode)
}

func TestRun_ExitCodeZero(t *testing.T) {
	udsPath := startEchoUDS(t)

	exitCode, err := tunnel.Run(udsPath, []string{"true"})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

func TestRun_ProxyEnvVarsSet(t *testing.T) {
	udsPath := startEchoUDS(t)

	exitCode, err := tunnel.Run(udsPath, []string{"sh", "-c", `
		test -n "$HTTP_PROXY" &&
		test -n "$HTTPS_PROXY" &&
		test -n "$http_proxy" &&
		test -n "$https_proxy"
	`})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

func TestRun_NoProxyUnset(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	t.Setenv("no_proxy", "*")

	udsPath := startEchoUDS(t)

	exitCode, err := tunnel.Run(udsPath, []string{"sh", "-c", `
		test -z "$NO_PROXY" && test -z "$no_proxy"
	`})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

func TestRun_NoCommand(t *testing.T) {
	udsPath := startEchoUDS(t)

	exitCode, err := tunnel.Run(udsPath, nil)
	require.ErrorContains(t, err, "no command specified")
	assert.Equal(t, 1, exitCode)
}

func TestRun_TCPBridgesToUDS(t *testing.T) {
	// Start a simple HTTP server on the UDS
	udsPath := filepath.Join(t.TempDir(), "proxy.sock")
	listener, err := net.Listen("unix", udsPath)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "proxied")
	})
	server := &http.Server{Handler: mux} // #nosec G112 -- test code
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	// Run a command that uses the proxy to make an HTTP request
	exitCode, err := tunnel.Run(udsPath, []string{"sh", "-c", `
		# Use curl with the proxy
		response=$(curl -s --proxy "$HTTP_PROXY" http://test.local/ 2>/dev/null)
		if [ "$response" = "proxied" ]; then
			exit 0
		fi
		exit 1
	`})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

// startEchoUDS starts a minimal server on a UDS that accepts and immediately
// closes connections. Returns the UDS path.
func startEchoUDS(t *testing.T) string {
	t.Helper()
	udsPath := filepath.Join(t.TempDir(), "proxy.sock")
	listener, err := net.Listen("unix", udsPath)
	require.NoError(t, err)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Read and discard
			go func() {
				_, _ = io.Copy(io.Discard, conn)
				_ = conn.Close()
			}()
		}
	}()

	t.Cleanup(func() { _ = listener.Close() })

	return udsPath
}

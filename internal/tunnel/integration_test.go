package tunnel_test

import (
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Requirement: Host-side TCP bridge ---

func TestIntegration_StartBridge_ForwardsTCPToUDS(t *testing.T) {
	udsPath := filepath.Join(t.TempDir(), "proxy.sock")
	listener, err := net.Listen("unix", udsPath)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "bridge-ok")
	})
	server := &http.Server{Handler: mux} //nolint:gosec // test code
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	port, stop, err := tunnel.StartBridge(t.Context(), udsPath)
	require.NoError(t, err)
	t.Cleanup(stop)

	// Verify bridge forwards a TCP connection to the UDS
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIntegration_StartBridge_StopClosesCleanly(t *testing.T) {
	udsPath := filepath.Join(t.TempDir(), "proxy.sock")
	listener, err := net.Listen("unix", udsPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	port, stop, err := tunnel.StartBridge(t.Context(), udsPath)
	require.NoError(t, err)
	assert.Positive(t, port)

	// Stop should return without hanging
	stop()

	// After stop, new connections should be refused
	_, dialErr := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	assert.Error(t, dialErr)
}

// --- Requirement: TCP-to-UDS bridge ---

func TestIntegration_TCPToUDSBridge_TCPConnectionBridgedToUDS(t *testing.T) {
	udsPath := filepath.Join(t.TempDir(), "proxy.sock")
	listener, err := net.Listen("unix", udsPath)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "bridged")
	})
	server := &http.Server{Handler: mux} //nolint:gosec // test code
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	exitCode, err := tunnel.Run(udsPath, []string{"sh", "-c", `
		response=$(curl -s --proxy "$HTTP_PROXY" http://test.local/ 2>/dev/null)
		test "$response" = "bridged"
	`})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

func TestIntegration_TCPToUDSBridge_UDSUnavailable(t *testing.T) {
	udsPath := filepath.Join(t.TempDir(), "nonexistent.sock")

	exitCode, err := tunnel.Run(udsPath, []string{"sh", "-c", `
		! curl -s --proxy "$HTTP_PROXY" --max-time 2 http://test.local/ 2>/dev/null
	`})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

// --- Requirement: Proxy environment variables ---

func TestIntegration_ProxyEnvironmentVariables_ProxyEnvVarsSet(t *testing.T) {
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

func TestIntegration_ProxyEnvironmentVariables_NoProxyVarsUnset(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	t.Setenv("no_proxy", "*")

	udsPath := startEchoUDS(t)

	exitCode, err := tunnel.Run(udsPath, []string{"sh", "-c", `
		test -z "$NO_PROXY" && test -z "$no_proxy"
	`})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

// --- Requirement: User command execution ---

func TestIntegration_UserCommandExecution_UserCommandExitCodePropagated(t *testing.T) {
	udsPath := startEchoUDS(t)

	exitCode, err := tunnel.Run(udsPath, []string{"sh", "-c", "exit 42"})
	require.NoError(t, err)
	assert.Equal(t, 42, exitCode)
}

func TestIntegration_UserCommandExecution_UserCommandRunsWithProxyEnv(t *testing.T) {
	udsPath := startEchoUDS(t)

	exitCode, err := tunnel.Run(udsPath, []string{"sh", "-c", `
		echo "$HTTP_PROXY" | grep -q "http://127.0.0.1:"
	`})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

// --- Requirement: Tunnel failure is fail-closed ---

// Note: TunnelBindFailure is not testable at the integration level because
// binding to 127.0.0.1:0 only fails under extreme system conditions that
// cannot be reliably reproduced in a test.

func TestIntegration_TunnelFailureIsFailClosed_TunnelUDSInaccessible(t *testing.T) {
	udsPath := filepath.Join(t.TempDir(), "nonexistent.sock")

	exitCode, err := tunnel.Run(udsPath, []string{"sh", "-c", `
		! curl -s --proxy "$HTTP_PROXY" --max-time 2 http://test.local/ 2>/dev/null
	`})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

// --- Requirement: Connection draining on exit ---

// Note: InFlightDataDrained is not suitable for integration testing because
// it requires precise timing control over active relay goroutines during
// command exit, which is inherently racy.

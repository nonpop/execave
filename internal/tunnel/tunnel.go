// Package tunnel implements the TCP-to-UDS bridge that runs inside the sandbox
// as the sandboxed process's sole network exit.
//
// [WrapCommand] prepends the tunnel invocation to a command slice. [Run] is
// dispatched from the "network-tunnel" CLI subcommand. Fail-closed: if the
// tunnel cannot bind or connect, the command exits immediately.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Subcommand is the CLI subcommand name for the tunnel.
const Subcommand = "network-tunnel"

// ExecCount is the number of exec transitions the tunnel adds to the
// execution chain. Used by sandbox and monitor to compute setup skip counts.
const ExecCount = 1

// WrapCommand prepends the tunnel invocation to command.
// command must not be empty (panics otherwise).
func WrapCommand(tunnelBinary, udsPath string, command []string) []string {
	if len(command) == 0 {
		panic("execave bug: tunnel started with no command")
	}
	result := make([]string, 0, 3+1+len(command))
	result = append(result, tunnelBinary, Subcommand, udsPath, "--")
	result = append(result, command...)
	return result
}

// Run starts the TCP-to-UDS bridge, injects proxy env vars, and execs
// targetArgv. Returns the user command's exit code.
func Run(udsPath string, targetArgv []string) (int, error) {
	if len(targetArgv) == 0 {
		return 1, errors.New("no command specified")
	}

	port, stop, err := startBridge(context.Background(), udsPath)
	if err != nil {
		return 1, fmt.Errorf("start bridge: %w", err)
	}
	defer stop()

	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	return runCommand(targetArgv, proxyURL)
}

// startBridge starts a TCP-to-UDS bridge goroutine.
// udsPath is the path to the proxy's Unix domain socket.
// Returns the TCP port on 127.0.0.1, a stop function, and any error.
// The stop function closes the TCP listener and waits for in-flight relays to drain.
func startBridge(ctx context.Context, udsPath string) (int, func(), error) {
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, fmt.Errorf("bind to loopback: %w", err)
	}

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		panic("execave bug: TCP listener returned non-TCP address")
	}
	port := tcpAddr.Port

	var relayWg sync.WaitGroup
	go acceptLoop(ctx, listener, udsPath, &relayWg)

	stop := func() {
		_ = listener.Close()
		relayWg.Wait()
	}

	return port, stop, nil
}

func acceptLoop(ctx context.Context, listener net.Listener, udsPath string, wg *sync.WaitGroup) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				fmt.Fprintf(os.Stderr, "execave: tunnel: accept: %v\n", err)
			}
			return
		}
		wg.Go(func() {
			relayToUDS(ctx, conn, udsPath)
		})
	}
}

func relayToUDS(ctx context.Context, tcpConn net.Conn, udsPath string) {
	defer func() { _ = tcpConn.Close() }()

	var dialer net.Dialer
	udsConn, err := dialer.DialContext(ctx, "unix", udsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "execave: tunnel: connect to proxy: %v\n", err)
		return
	}
	defer func() { _ = udsConn.Close() }()

	var wg sync.WaitGroup
	wg.Add(2) //nolint:mnd

	go func() {
		defer wg.Done()
		_, _ = io.Copy(udsConn, tcpConn)
		// Signal the read side by closing the UDS write direction.
		if uc, ok := udsConn.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		} else {
			_ = udsConn.Close()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(tcpConn, udsConn)
		if tc, ok := tcpConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = tcpConn.Close()
		}
	}()

	wg.Wait()
}

func runCommand(args []string, proxyURL string) (int, error) {
	cmd := exec.CommandContext(context.Background(), args[0], args[1:]...) //nolint:gosec // args are the user's command
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Set proxy env vars and unset no_proxy
	cmd.Env = buildEnv(proxyURL)

	err := cmd.Run()
	if err != nil {
		exitErr := new(exec.ExitError)
		if errors.As(err, &exitErr) {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return status.ExitStatus(), nil
			}
		}
		return 1, fmt.Errorf("run command %q: %w", args[0], err)
	}

	return 0, nil
}

// buildEnv creates an environment with proxy vars set and no_proxy unset.
func buildEnv(proxyURL string) []string {
	env := os.Environ()

	// Remove existing proxy-related env vars
	filtered := make([]string, 0)
	for _, envVar := range env {
		key := envKey(envVar)
		switch key {
		case "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
			"NO_PROXY", "no_proxy":
			continue
		}
		filtered = append(filtered, envVar)
	}

	// Set proxy env vars
	filtered = append(filtered,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
	)

	return filtered
}

// envKey extracts the key part from a KEY=VALUE environment variable string.
func envKey(s string) string {
	key, _, _ := strings.Cut(s, "=")
	return key
}

// FormatListenAddr formats the tunnel listen address for display.
func FormatListenAddr(port int) string {
	return "127.0.0.1:" + strconv.Itoa(port)
}

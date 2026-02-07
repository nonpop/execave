package proxy_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/netrules"
	"github.com/nonpop/execave/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Proxy lifecycle ---

func TestProxy_StartAndStop(t *testing.T) {
	p, _, cleanup := startTestProxy(t, "https:example.com:443")
	defer cleanup()

	// Verify the UDS is accessible
	dialer := new(net.Dialer)
	conn, err := dialer.DialContext(context.Background(), "unix", p.Addr().String())
	require.NoError(t, err)
	_ = conn.Close()
}

func TestProxy_StopRemovesUDS(t *testing.T) {
	udsPath := filepath.Join(t.TempDir(), "proxy.sock")

	resolver := newTestResolver(t, "https:example.com:443")
	p := proxy.New(resolver, nil)
	err := p.Start(udsPath)
	require.NoError(t, err)

	err = p.Stop()
	require.NoError(t, err)

	// UDS should be removed
	dialer := new(net.Dialer)
	_, err = dialer.DialContext(context.Background(), "unix", udsPath)
	assert.Error(t, err)
}

// --- CONNECT handler ---

func TestProxy_CONNECTAllowed(t *testing.T) {
	testAllowedRequest(t, true, "hello from TLS")
}

func TestProxy_CONNECTDenied(t *testing.T) {
	p, udsPath, cleanup := startTestProxy(t, "https:allowed.example.com:443")
	defer cleanup()
	_ = p

	// Try to CONNECT to a non-allowlisted host
	conn, err := net.Dial("unix", udsPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	response := string(buf[:n])
	assert.Contains(t, response, "403")
}

// --- Plain HTTP handler ---

func TestProxy_HTTPAllowed(t *testing.T) {
	testAllowedRequest(t, false, "hello from HTTP")
}

func TestProxy_HTTPDenied(t *testing.T) {
	p, udsPath, cleanup := startTestProxy(t, "http:allowed.example.com:80")
	defer cleanup()
	_ = p

	client := httpClientViaUDS(udsPath, false)
	resp, err := client.Get("http://evil.example.com:80/status")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// --- Malformed request handling ---

func TestProxy_RawBytesRejected(t *testing.T) {
	_, udsPath, cleanup := startTestProxy(t, "https:example.com:443")
	defer cleanup()

	conn, err := net.Dial("unix", udsPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Send non-HTTP data
	_, _ = conn.Write([]byte("this is not HTTP\r\n"))

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	response := string(buf[:n])
	assert.Contains(t, response, "400")
}

func TestProxy_CONNECTMissingHost(t *testing.T) {
	_, udsPath, cleanup := startTestProxy(t, "https:example.com:443")
	defer cleanup()

	conn, err := net.Dial("unix", udsPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT HTTP/1.1\r\nHost: \r\n\r\n")

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	response := string(buf[:n])
	assert.Contains(t, response, "400")
}

// --- Allowlist with specificity ---

func TestProxy_AllowlistExactBeatsWildcard(t *testing.T) {
	_, udsPath, cleanup := startTestProxy(t,
		"https:*.example.com:443",
		"none:evil.example.com:443",
	)
	defer cleanup()

	// evil.example.com should be denied (exact beats wildcard)
	conn, err := net.Dial("unix", udsPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	response := string(buf[:n])
	assert.Contains(t, response, "403")
}

// --- Access log integration ---

func TestProxy_AccessLogAllowed(t *testing.T) {
	// Start a TLS server
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsServer.Close()

	host, port := hostPort(t, tlsServer.Listener.Addr().String())
	ruleBody := fmt.Sprintf("https:%s:%s", host, port)

	var logBuf bytes.Buffer
	logger := accesslog.New(&logBuf, nil)
	resolver := newTestResolver(t, ruleBody)

	udsPath := filepath.Join(t.TempDir(), "proxy.sock")
	p := proxy.New(resolver, logger)
	err := p.Start(udsPath)
	require.NoError(t, err)
	defer func() { _ = p.Stop() }()

	client := httpClientViaUDS(udsPath, true)
	resp, err := client.Get(fmt.Sprintf("https://%s/", net.JoinHostPort(host, port)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	logStr := logBuf.String()
	assert.Contains(t, logStr, "HTTPS")
	assert.Contains(t, logStr, "OK")
}

func TestProxy_AccessLogDenied(t *testing.T) {
	var logBuf bytes.Buffer
	logger := accesslog.New(&logBuf, nil)
	resolver := newTestResolver(t, "https:allowed.example.com:443")

	udsPath := filepath.Join(t.TempDir(), "proxy.sock")
	p := proxy.New(resolver, logger)
	err := p.Start(udsPath)
	require.NoError(t, err)
	defer func() { _ = p.Stop() }()

	conn, err := net.Dial("unix", udsPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")

	buf := make([]byte, 1024)
	_, _ = conn.Read(buf)

	logStr := logBuf.String()
	assert.Contains(t, logStr, "HTTPS")
	assert.Contains(t, logStr, "DENY")
	assert.Contains(t, logStr, "no-matching-rule")
}

// --- helpers ---

// testAllowedRequest starts a test server (HTTP or TLS), sets up a proxy with the given rule,
// makes a request through the proxy, and asserts the expected response.
func testAllowedRequest(t *testing.T, useTLS bool, expectedBody string) {
	t.Helper()

	var server *httptest.Server
	var scheme string

	if useTLS {
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, expectedBody)
		}))
		scheme = "https"
	} else {
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, expectedBody)
		}))
		scheme = "http"
	}
	defer server.Close()

	host, port := hostPort(t, server.Listener.Addr().String())
	ruleBody := fmt.Sprintf("%s:%s:%s", scheme, host, port)

	p, udsPath, cleanup := startTestProxy(t, ruleBody)
	defer cleanup()
	_ = p

	client := httpClientViaUDS(udsPath, useTLS)
	requestPath := "/"
	if !useTLS {
		requestPath = "/status"
	}
	resp, err := client.Get(fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(host, port), requestPath))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, expectedBody, string(body))
}

func startTestProxy(t *testing.T, ruleBodies ...string) (*proxy.Proxy, string, func()) {
	t.Helper()

	resolver := newTestResolver(t, ruleBodies...)
	udsPath := filepath.Join(t.TempDir(), "proxy.sock")

	p := proxy.New(resolver, nil)
	err := p.Start(udsPath)
	require.NoError(t, err)

	return p, udsPath, func() { _ = p.Stop() }
}

func newTestResolver(t *testing.T, ruleBodies ...string) *netrules.Resolver {
	t.Helper()
	rules := make([]netrules.Rule, 0, len(ruleBodies))
	for _, body := range ruleBodies {
		rule, err := netrules.Parse(body)
		require.NoError(t, err)
		rule.RawRule = "net:" + body
		rules = append(rules, rule)
	}
	return netrules.NewResolver(rules)
}

func hostPort(t *testing.T, addr string) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	return host, port
}

// httpClientViaUDS creates an HTTP client that connects through the proxy UDS.
func httpClientViaUDS(udsPath string, useTLS bool) *http.Client {
	proxyURL, _ := url.Parse("http://proxy.local")

	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", udsPath)
		},
		Proxy: http.ProxyURL(proxyURL),
	}

	if useTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test only
	}

	return &http.Client{Transport: transport}
}

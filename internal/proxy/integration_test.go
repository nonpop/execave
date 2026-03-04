package proxy_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/netrules"
	"github.com/nonpop/execave/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Requirement: Proxy listens on UDS ---

func TestIntegration_ProxyListensOnUDS_ProxyAcceptsConnectionOnUDS(t *testing.T) {
	_, udsPath, cleanup := startTestProxy(t, "http:example.com:443")
	defer cleanup()

	conn, err := net.Dial("unix", udsPath)
	require.NoError(t, err)
	_ = conn.Close()
}

func TestIntegration_ProxyListensOnUDS_ProxyDoesNotListenOnTCP(t *testing.T) {
	p, _, cleanup := startTestProxy(t, "http:example.com:443")
	defer cleanup()

	assert.Equal(t, "unix", p.Addr().Network())
}

// --- Requirement: CONNECT handling for HTTPS ---

func TestIntegration_CONNECTHandlingForHTTPS_AllowedCONNECTRequestTunneled(t *testing.T) {
	testProxyRequest(t, "tunnel-ok", true, "https")
}

func TestIntegration_CONNECTHandlingForHTTPS_DeniedCONNECTRequestRejected(t *testing.T) {
	_, udsPath, cleanup := startTestProxy(t, "http:allowed.example.com:443")
	defer cleanup()

	conn, err := net.Dial("unix", udsPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	assert.Contains(t, string(buf[:n]), "403")
}

func TestIntegration_CONNECTHandlingForHTTPS_CONNECTTunnelClosesWhenTargetDisconnects(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "then-close")
	}))
	defer server.Close()

	host, port := hostPort(t, server.Listener.Addr().String())
	_, udsPath, cleanup := startTestProxy(t, fmt.Sprintf("http:%s:%s", host, port))
	defer cleanup()

	client := httpClientViaUDS(udsPath, true)
	resp, err := client.Get(fmt.Sprintf("https://%s/", net.JoinHostPort(host, port)))
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, "then-close", string(body))
}

// --- Requirement: Plain HTTP forwarding ---

func TestIntegration_PlainHTTPForwarding_AllowedHTTPRequestForwarded(t *testing.T) {
	testProxyRequest(t, "http-forward-ok", false, "http")
}

func TestIntegration_PlainHTTPForwarding_DeniedHTTPRequestRejected(t *testing.T) {
	_, udsPath, cleanup := startTestProxy(t, "http:allowed.example.com:80")
	defer cleanup()

	client := httpClientViaUDS(udsPath, false)
	resp, err := client.Get("http://evil.example.com:80/status")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestIntegration_PlainHTTPForwarding_HTTPRequestWithoutPortDefaultsTo80Allowed(t *testing.T) {
	var logBuf bytes.Buffer
	cfg := &accesslog.Config{ShowAllowed: true}
	logger := accesslog.New(&logBuf, cfg)
	resolver := newTestResolver(t, "http:localhost:80")

	udsPath := filepath.Join(t.TempDir(), "proxy.sock")
	p := proxy.New(logger, resolver, udsPath, false)
	require.NoError(t, p.Start())
	defer func() { _ = p.Stop() }()

	client := httpClientViaUDS(udsPath, false)
	resp, err := client.Get("http://localhost/status")
	require.NoError(t, err)
	_ = resp.Body.Close()

	// The forward may fail (nothing on port 80), but the access log
	// shows the rule check passed with the defaulted port.
	logStr := logBuf.String()
	require.NotEmpty(t, logStr)
	assert.Contains(t, logStr, "localhost:80")
	assert.Contains(t, logStr, "OK")
}

func TestIntegration_PlainHTTPForwarding_HTTPRequestWithoutPortDefaultsTo80Denied(t *testing.T) {
	var logBuf bytes.Buffer
	cfg := &accesslog.Config{ShowAllowed: true}
	logger := accesslog.New(&logBuf, cfg)
	resolver := newTestResolver(t, "http:other.example.com:80")

	udsPath := filepath.Join(t.TempDir(), "proxy.sock")
	p := proxy.New(logger, resolver, udsPath, false)
	require.NoError(t, p.Start())
	defer func() { _ = p.Stop() }()

	client := httpClientViaUDS(udsPath, false)
	resp, err := client.Get("http://evil.example.com/status")
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	logStr := logBuf.String()
	require.NotEmpty(t, logStr)
	assert.Contains(t, logStr, "evil.example.com:80")
	assert.Contains(t, logStr, "DENY")
}

// --- Requirement: Malformed request handling ---

func TestIntegration_MalformedRequestHandling_RawBytesSentToUDS(t *testing.T) {
	_, udsPath, cleanup := startTestProxy(t, "http:example.com:443")
	defer cleanup()

	conn, err := net.Dial("unix", udsPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, _ = conn.Write([]byte("this is not HTTP\r\n"))

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	assert.Contains(t, string(buf[:n]), "400")
}

func TestIntegration_MalformedRequestHandling_CONNECTWithMissingHost(t *testing.T) {
	_, udsPath, cleanup := startTestProxy(t, "http:example.com:443")
	defer cleanup()

	conn, err := net.Dial("unix", udsPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT HTTP/1.1\r\nHost: \r\n\r\n")

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	assert.Contains(t, string(buf[:n]), "400")
}

// --- Requirement: Allowlist enforcement ---

func TestIntegration_AllowlistEnforcement_RequestAllowedByMostSpecificRule(t *testing.T) {
	var logBuf bytes.Buffer
	cfg := &accesslog.Config{ShowAllowed: true}
	logger := accesslog.New(&logBuf, cfg)
	resolver := newTestResolver(t,
		"http:*.example.com:443",
		"none:evil.example.com:443",
	)

	udsPath := filepath.Join(t.TempDir(), "proxy.sock")
	p := proxy.New(logger, resolver, udsPath, false)
	require.NoError(t, p.Start())
	defer func() { _ = p.Stop() }()

	conn, err := net.Dial("unix", udsPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// api.example.com matches wildcard, no exact deny applies
	_, _ = fmt.Fprintf(conn, "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n")

	buf := make([]byte, 1024)
	_, _ = conn.Read(buf)

	logStr := logBuf.String()
	require.NotEmpty(t, logStr)
	assert.Contains(t, logStr, "api.example.com:443")
	assert.Contains(t, logStr, "OK")
}

func TestIntegration_AllowlistEnforcement_RequestDeniedByMostSpecificRule(t *testing.T) {
	_, udsPath, cleanup := startTestProxy(t,
		"http:*.example.com:443",
		"none:evil.example.com:443",
	)
	defer cleanup()

	conn, err := net.Dial("unix", udsPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	assert.Contains(t, string(buf[:n]), "403")
}

// --- Requirement: Access log integration ---

func TestIntegration_AccessLogIntegration_AllowedRequestLogged(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	host, port := hostPort(t, server.Listener.Addr().String())
	ruleBody := fmt.Sprintf("http:%s:%s", host, port)

	var logBuf bytes.Buffer
	cfg := &accesslog.Config{ShowAllowed: true}
	logger := accesslog.New(&logBuf, cfg)
	resolver := newTestResolver(t, ruleBody)

	udsPath := filepath.Join(t.TempDir(), "proxy.sock")
	p := proxy.New(logger, resolver, udsPath, false)
	require.NoError(t, p.Start())
	defer func() { _ = p.Stop() }()

	client := httpClientViaUDS(udsPath, true)
	resp, err := client.Get(fmt.Sprintf("https://%s/", net.JoinHostPort(host, port)))
	require.NoError(t, err)
	_ = resp.Body.Close()

	logStr := logBuf.String()
	require.NotEmpty(t, logStr)
	assert.Contains(t, logStr, "HTTP")
	assert.Contains(t, logStr, net.JoinHostPort(host, port))
	assert.Contains(t, logStr, "OK")
}

func TestIntegration_AccessLogIntegration_DeniedRequestLogged(t *testing.T) {
	var logBuf bytes.Buffer
	cfg := &accesslog.Config{ShowAllowed: true}
	logger := accesslog.New(&logBuf, cfg)
	resolver := newTestResolver(t, "http:allowed.example.com:443")

	udsPath := filepath.Join(t.TempDir(), "proxy.sock")
	p := proxy.New(logger, resolver, udsPath, false)
	require.NoError(t, p.Start())
	defer func() { _ = p.Stop() }()

	conn, err := net.Dial("unix", udsPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")

	buf := make([]byte, 1024)
	_, _ = conn.Read(buf)

	logStr := logBuf.String()
	require.NotEmpty(t, logStr)
	assert.Contains(t, logStr, "HTTP")
	assert.Contains(t, logStr, "evil.example.com:443")
	assert.Contains(t, logStr, "DENY")
	assert.Contains(t, logStr, "("+accesslog.RuleNoMatch+")")
}

// --- Requirement: Proxy lifecycle ---

func TestIntegration_ProxyLifecycle_ProxyStart(t *testing.T) {
	p, _, cleanup := startTestProxy(t, "http:example.com:443")
	defer cleanup()

	assert.NotNil(t, p.Addr())
}

func TestIntegration_ProxyLifecycle_ProxyStop(t *testing.T) {
	udsPath := filepath.Join(t.TempDir(), "proxy.sock")
	resolver := newTestResolver(t, "http:example.com:443")
	p := proxy.New(nil, resolver, udsPath, false)
	require.NoError(t, p.Start())

	require.NoError(t, p.Stop())

	_, err := net.Dial("unix", udsPath)
	assert.Error(t, err)
}

// --- Requirement: noEnforce (log-only mode) ---

func TestIntegration_SetNoEnforce_HTTPRequestForwardedDespiteNoMatchingRule(t *testing.T) {
	testNoEnforceForwardsDespiteNoMatchingRule(t, false)
}

func TestIntegration_SetNoEnforce_CONNECTRequestTunneledDespiteNoMatchingRule(t *testing.T) {
	testNoEnforceForwardsDespiteNoMatchingRule(t, true)
}

func testNoEnforceForwardsDespiteNoMatchingRule(t *testing.T, useTLS bool) {
	t.Helper()

	var server *httptest.Server
	if useTLS {
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	} else {
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	}
	defer server.Close()

	host, port := hostPort(t, server.Listener.Addr().String())
	udsPath := filepath.Join(t.TempDir(), "proxy.sock")

	// Empty rules (deny-all) but noEnforce=true
	p := proxy.New(nil, netrules.NewResolver(nil), udsPath, true)
	require.NoError(t, p.Start())
	defer func() { _ = p.Stop() }()

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	client := httpClientViaUDS(udsPath, useTLS)
	resp, err := client.Get(fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(host, port)))
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIntegration_SetNoEnforce_DenyRuleDoesNotBlockRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	host, port := hostPort(t, server.Listener.Addr().String())
	udsPath := filepath.Join(t.TempDir(), "proxy.sock")

	// Explicit deny rule but noEnforce=true
	p := proxy.New(nil, newTestResolver(t, fmt.Sprintf("none:%s:%s", host, port)), udsPath, true)
	require.NoError(t, p.Start())
	defer func() { _ = p.Stop() }()

	client := httpClientViaUDS(udsPath, false)
	resp, err := client.Get(fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// --- helpers ---

// testProxyRequest tests that a proxied request through the given scheme returns the expected response.
func testProxyRequest(t *testing.T, expectedBody string, useTLS bool, scheme string) {
	t.Helper()

	var server *httptest.Server
	if useTLS {
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprint(w, expectedBody)
		}))
	} else {
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprint(w, expectedBody)
		}))
	}
	defer server.Close()

	host, port := hostPort(t, server.Listener.Addr().String())
	_, udsPath, cleanup := startTestProxy(t, fmt.Sprintf("http:%s:%s", host, port))
	defer cleanup()

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

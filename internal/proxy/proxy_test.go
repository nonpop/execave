package proxy_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/netrules"
	"github.com/nonpop/execave/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startTestProxy(t *testing.T, ruleBodies ...string) (string, func()) {
	t.Helper()

	resolver := newTestResolver(t, ruleBodies...)
	udsPath := filepath.Join(t.TempDir(), "proxy.sock")

	p := proxy.New(nil, resolver, udsPath, false)
	err := p.Start()
	require.NoError(t, err)

	return udsPath, func() { _ = p.Stop() }
}

func newTestResolver(t *testing.T, ruleBodies ...string) *netrules.Resolver {
	t.Helper()
	rules := make([]netrules.Rule, 0, len(ruleBodies))
	for _, body := range ruleBodies {
		rule, err := netrules.ParseAccessRule(body, "")
		require.NoError(t, err)
		rules = append(rules, rule)
	}
	return netrules.NewResolver(rules)
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

func Test_PlainHTTPForwarding_HTTPRequestWithoutPortDefaultsTo80Allowed(t *testing.T) {
	var logBuf bytes.Buffer
	cfg := &accesslog.Config{ManagedPaths: nil, HomeDir: "", ConfigDir: "", ShowAllowed: true}
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

func Test_PlainHTTPForwarding_HTTPRequestWithoutPortDefaultsTo80Denied(t *testing.T) {
	var logBuf bytes.Buffer
	cfg := &accesslog.Config{ManagedPaths: nil, HomeDir: "", ConfigDir: "", ShowAllowed: true}
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

func Test_MalformedRequestHandling_RawBytesSentToUDS(t *testing.T) {
	udsPath, cleanup := startTestProxy(t, "http:example.com:443")
	defer cleanup()

	conn, err := net.Dial("unix", udsPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, _ = conn.Write([]byte("this is not HTTP\r\n"))

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	assert.Contains(t, string(buf[:n]), "400")
}

func Test_MalformedRequestHandling_CONNECTWithMissingHost(t *testing.T) {
	udsPath, cleanup := startTestProxy(t, "http:example.com:443")
	defer cleanup()

	conn, err := net.Dial("unix", udsPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT HTTP/1.1\r\nHost: \r\n\r\n")

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	assert.Contains(t, string(buf[:n]), "400")
}

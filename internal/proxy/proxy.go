// Package proxy implements a forward HTTP proxy that listens on a Unix domain socket
// and enforces a network allowlist based on net rules.
//
// The proxy handles CONNECT requests (for tunneling) and plain HTTP requests.
// It evaluates each request against the configured allowlist and either forwards
// the request or responds with 403 Forbidden.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/netrules"
)

const (
	// drainTimeout is the maximum time to wait for in-flight connections on shutdown.
	drainTimeout = 5 * time.Second
	// dialTimeout is the maximum time to wait for a connection to be established.
	dialTimeout = 10 * time.Second
	// readHeaderTimeout is the maximum time allowed to read request headers.
	readHeaderTimeout = 30 * time.Second
)

// Proxy is a forward HTTP proxy that listens on a UDS and enforces net rules.
type Proxy struct {
	resolver  atomic.Pointer[netrules.AccessResolver]
	logger    atomic.Pointer[accesslog.Logger]
	listener  net.Listener
	udsPath   string
	wg        sync.WaitGroup
	server    *http.Server
	transport *http.Transport
}

// New creates a new Proxy with the given net rules resolver and access logger.
// resolver must not be nil.
// logger may be nil if access logging is not needed.
func New(resolver *netrules.AccessResolver, logger *accesslog.Logger) *Proxy {
	if resolver == nil {
		panic("New: resolver must not be nil")
	}
	proxy := &Proxy{
		resolver:  atomic.Pointer[netrules.AccessResolver]{},
		logger:    atomic.Pointer[accesslog.Logger]{},
		listener:  nil,
		udsPath:   "",
		wg:        sync.WaitGroup{},
		server:    nil,
		transport: &http.Transport{},
	}
	proxy.resolver.Store(resolver)
	if logger != nil {
		proxy.logger.Store(logger)
	}
	return proxy
}

// SetResolver replaces the net rules resolver. Safe for concurrent use with request handlers.
// resolver must not be nil.
func (p *Proxy) SetResolver(resolver *netrules.AccessResolver) {
	if resolver == nil {
		panic("SetResolver: resolver must not be nil")
	}
	p.resolver.Store(resolver)
}

// SetLogger replaces the access logger. Safe for concurrent use with request handlers.
// logger may be nil to disable access logging.
func (p *Proxy) SetLogger(logger *accesslog.Logger) {
	p.logger.Store(logger)
}

// Start creates the UDS at the given path and begins accepting connections.
func (p *Proxy) Start(udsPath string) error {
	p.udsPath = udsPath

	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "unix", udsPath)
	if err != nil {
		return fmt.Errorf("listen on UDS %s: %w", udsPath, err)
	}
	p.listener = listener

	p.server = &http.Server{
		Handler:           http.HandlerFunc(p.handleRequest),
		ReadHeaderTimeout: readHeaderTimeout,
	}

	p.wg.Go(func() {
		if err := p.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "execave: serve proxy: %v\n", err)
		}
	})

	return nil
}

// Stop closes the listener, drains in-flight connections with a timeout,
// and removes the UDS.
func (p *Proxy) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()

	err := p.server.Shutdown(ctx)

	p.wg.Wait()

	if rmErr := os.Remove(p.udsPath); rmErr != nil && !os.IsNotExist(rmErr) {
		if err == nil {
			err = fmt.Errorf("remove UDS %s: %w", p.udsPath, rmErr)
		}
	}

	return err
}

// Addr returns the listener address. Only valid after Start.
func (p *Proxy) Addr() net.Addr {
	return p.listener.Addr()
}

func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleCONNECT(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *Proxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	host, port, err := parseHostPort(r.Host, 443) //nolint:mnd
	if err != nil {
		fmt.Fprintf(os.Stderr, "execave: CONNECT parse host %q: %v\n", r.Host, err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	result := p.resolver.Load().Resolve(netrules.ProtocolHTTP, host, port)
	p.logAccess(accesslog.OperationHTTP, r.Host, result)

	if !result.Allowed {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	targetAddr := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	dialer := net.Dialer{Timeout: dialTimeout}
	targetConn, err := dialer.DialContext(r.Context(), "tcp", targetAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "execave: CONNECT dial %s: %v\n", targetAddr, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer func() { _ = targetConn.Close() }()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		fmt.Fprintf(os.Stderr, "execave: CONNECT hijack not available\n")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		fmt.Fprintf(os.Stderr, "execave: CONNECT hijack: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		fmt.Fprintf(os.Stderr, "execave: CONNECT write 200: %v\n", err)
		return
	}

	relay(clientConn, targetConn)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host, port, err := extractHTTPHostPort(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "execave: HTTP parse host: %v\n", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	hostPort := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	result := p.resolver.Load().Resolve(netrules.ProtocolHTTP, host, port)
	p.logAccess(accesslog.OperationHTTP, hostPort, result)

	if !result.Allowed {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Forward the request
	r.RequestURI = ""
	r.URL.Scheme = "http"
	if r.URL.Host == "" {
		r.URL.Host = hostPort
	}

	removeHopByHopHeaders(r.Header)

	resp, err := p.transport.RoundTrip(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "execave: HTTP round-trip %s: %v\n", r.URL.Host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	removeHopByHopHeaders(resp.Header)

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		fmt.Fprintf(os.Stderr, "execave: HTTP copy response body: %v\n", err)
	}
}

func (p *Proxy) logAccess(opType accesslog.OperationType, target string, result netrules.ResolveResult) {
	logger := p.logger.Load()
	if logger == nil {
		return
	}

	logResult := accesslog.ResultOK
	if !result.Allowed {
		logResult = accesslog.ResultDeny
	}

	logger.Log(accesslog.Entry{
		Operation: opType,
		Target:    target,
		Result:    logResult,
		Rule:      result.Rule,
	})
}

// parseHostPort extracts host and port from a host:port string.
// If no port is present, defaultPort is used.
func parseHostPort(hostPort string, defaultPort uint16) (string, uint16, error) {
	if len(hostPort) == 0 {
		return "", 0, errors.New("empty host")
	}

	if host, portStr, err := net.SplitHostPort(hostPort); err == nil {
		// Port was specified, parse it
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || port == 0 {
			return "", 0, fmt.Errorf("invalid port %q", portStr)
		}
		return host, uint16(port), nil
	}

	// No port specified, use entire string as host with default port
	return hostPort, defaultPort, nil
}

// extractHTTPHostPort extracts host and port from a plain HTTP request.
// Uses the URL host if available, falls back to Host header.
// Default port is 80 for HTTP.
func extractHTTPHostPort(r *http.Request) (string, uint16, error) {
	hostPort := r.URL.Host
	if hostPort == "" {
		hostPort = r.Host
	}
	if hostPort == "" {
		return "", 0, errors.New("no host in request")
	}
	return parseHostPort(hostPort, 80) //nolint:mnd
}

// relay copies data bidirectionally between two connections.
// Returns when either direction's copy completes.
func relay(conn1, conn2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2) //nolint:mnd

	copyConn := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		// Signal the other goroutine by closing the write side.
		// This handles the case where one side closes first.
		switch c := dst.(type) {
		case *net.TCPConn:
			_ = c.CloseWrite()
		case *net.UnixConn:
			_ = c.CloseWrite()
		default:
			_ = dst.Close()
		}
	}

	go copyConn(conn1, conn2)
	go copyConn(conn2, conn1)

	wg.Wait()
}

// hopByHopHeaders are headers that must be removed when forwarding HTTP requests.
//
//nolint:gochecknoglobals // package-private, used read-only
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(header http.Header) {
	for _, conn := range header["Connection"] {
		for h := range strings.SplitSeq(conn, ",") {
			header.Del(strings.TrimSpace(h))
		}
	}

	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

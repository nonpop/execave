// Package webui provides a localhost web server for viewing access log entries in real-time.
//
// The Server displays access log entries via:
// - Server-rendered HTML page with initial entries (GET /)
// - Server-Sent Events for real-time updates (GET /events)
package webui

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/runner"
)

//go:embed templates/*.html
var templateFS embed.FS

//nolint:gochecknoglobals // read-only package internal
var indexTemplate = template.Must(template.ParseFS(templateFS, "templates/index.html"))

const (
	// httpReadHeaderTimeout is the maximum duration for reading HTTP request headers.
	httpReadHeaderTimeout = 10 * time.Second
	// sseKeepaliveInterval is the interval at which keepalive comments are sent over SSE.
	sseKeepaliveInterval = 30 * time.Second
)

// Server serves a localhost web UI for viewing access log entries and run status.
type Server struct {
	runner     *runner.Runner
	cfg        *config.Config
	command    []string
	port       string
	addr       string // actual bound address, set by Start
	sessionID  string
	httpServer *http.Server
	runCtx     context.Context //nolint:containedctx // stored from Start for use in HTTP handlers
}

// New creates a new Server that displays entries from the given runner.
// The server binds to 127.0.0.1:port when Start() is called.
// cfg and command are stored for run control endpoints (start/restart).
func New(rnr *runner.Runner, cfg *config.Config, command []string, port string) *Server {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(fmt.Sprintf("generate session ID: %v", err))
	}
	return &Server{
		runner:     rnr,
		cfg:        cfg,
		command:    command,
		port:       port,
		addr:       "",
		sessionID:  hex.EncodeToString(buf[:]),
		httpServer: nil,
		runCtx:     nil,
	}
}

// Start starts the HTTP server on 127.0.0.1:port.
// Returns an error if the port is already in use or invalid.
// Start is non-blocking; the server runs in a background goroutine.
func (s *Server) Start(ctx context.Context) error {
	// Store context for runner operations
	s.runCtx = ctx
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:"+s.port)
	if err != nil {
		return fmt.Errorf("listen on port %s: %w", s.port, err)
	}
	s.addr = listener.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/api/start", s.handleStart)
	mux.HandleFunc("/api/stop", s.handleStop)

	s.httpServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: httpReadHeaderTimeout,
	}

	go func() {
		if err := s.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "execave: serve: %v\n", err)
		}
	}()

	return nil
}

// Shutdown gracefully shuts down the HTTP server with a timeout.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx) //nolint:wrapcheck
}

// URL returns the server's full URL. Must be called after Start.
func (s *Server) URL() string {
	return "http://" + s.addr
}

// parseLastEventID parses a "sessionID:index" formatted SSE event ID.
// Returns the session ID, entry index, and whether parsing succeeded.
func parseLastEventID(raw string) (string, int, bool) {
	session, idxStr, ok := strings.Cut(raw, ":")
	if !ok {
		return "", 0, false
	}
	if session == "" {
		return "", 0, false
	}
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		return "", 0, false
	}
	return session, idx, true
}

// handleIndex serves the main HTML page with all current entries.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	logger := s.runner.Logger()
	var entries []accesslog.Entry
	if logger != nil {
		entries = logger.Entries()
	}
	status := s.runner.Status()

	data := struct {
		Entries    []accesslog.Entry
		EntryCount int
		Status     runner.RunStatus
		SessionID  string
		Command    string
	}{
		Entries:    entries,
		EntryCount: len(entries),
		Status:     status,
		SessionID:  s.sessionID,
		Command:    status.Command,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTemplate.Execute(w, data); err != nil {
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
	}
}

// resolveStartIndex determines the starting entry index for SSE streaming.
// It checks Last-Event-ID header first (for automatic reconnection), then
// falls back to the ?from query parameter.
func (s *Server) resolveStartIndex(r *http.Request) int {
	// Check Last-Event-ID header first (automatic reconnection).
	// Parse session:index format to detect cross-session reconnects.
	if lastEventID := r.Header.Get("Last-Event-ID"); lastEventID != "" {
		session, idx, ok := parseLastEventID(lastEventID)
		if ok && session == s.sessionID {
			return idx + 1 // Same session: resume from next entry
		}
		// Cross-session or malformed: replay from 0
		return 0
	}
	// Fall back to ?from query parameter (always current session)
	if fromParam := r.URL.Query().Get("from"); fromParam != "" {
		if id, err := strconv.Atoi(fromParam); err == nil {
			return id
		}
	}
	return 0
}

// sseStream holds mutable state for an SSE streaming session.
type sseStream struct {
	server  *Server
	logger  *accesslog.Logger
	entryCh chan struct{}
	entries []accesslog.Entry
}

// handleNewEntries sends any new entries since the last batch.
func (st *sseStream) handleNewEntries(w http.ResponseWriter) {
	if st.logger == nil {
		return
	}
	currentEntries := st.logger.Entries()
	lastSentIndex := len(st.entries) - 1
	for i := lastSentIndex + 1; i < len(currentEntries); i++ {
		st.server.sendEntryEvent(w, currentEntries[i], i)
	}
	st.entries = currentEntries
}

// handleStatusChange processes a status change event, switching loggers on new runs.
func (st *sseStream) handleStatusChange(w http.ResponseWriter, status runner.RunStatus) {
	st.server.sendStatusEvent(w, status)
	if !status.Running {
		return
	}
	// New run started — switch to the new logger
	if st.logger != nil && st.entryCh != nil {
		st.logger.Unsubscribe(st.entryCh)
	}
	st.logger = st.server.runner.Logger()
	if st.logger != nil {
		st.entryCh = st.logger.Subscribe()
	}
	st.server.sendSessionEvent(w, 0)
	st.entries = nil
}

// handleEvents serves Server-Sent Events for real-time entry updates.
// Supports ?from=N query parameter to replay from index N.
// Supports Last-Event-ID header for automatic reconnection.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	startIndex := s.resolveStartIndex(r)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Subscribe to status changes
	statusCh := s.runner.Subscribe()
	defer s.runner.Unsubscribe(statusCh)

	// Set up stream state
	stream := &sseStream{server: s, logger: s.runner.Logger(), entryCh: nil, entries: nil}
	if stream.logger != nil {
		stream.entryCh = stream.logger.Subscribe()
		defer stream.logger.Unsubscribe(stream.entryCh)
	}

	// Send session event, initial status, and initial entries from startIndex
	s.sendSessionEvent(w, startIndex)
	s.sendStatusEvent(w, s.runner.Status())
	if stream.logger != nil {
		stream.entries = stream.logger.Entries()
		for i := startIndex; i < len(stream.entries); i++ {
			s.sendEntryEvent(w, stream.entries[i], i)
		}
	}
	flusher.Flush()

	// Stream new entries and status changes as they arrive
	ctx := r.Context()
	keepaliveTicker := time.NewTicker(sseKeepaliveInterval)
	defer keepaliveTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stream.entryCh:
			stream.handleNewEntries(w)
			flusher.Flush()
		case <-statusCh:
			stream.handleStatusChange(w, s.runner.Status())
			flusher.Flush()
		case <-keepaliveTicker.C:
			// write fails on client disconnect; ctx.Done handles that
			_, _ = fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// sendEntryEvent sends a single entry as an SSE event.
// Write errors are ignored: they only occur on client disconnect, which ctx.Done handles.
func (s *Server) sendEntryEvent(w http.ResponseWriter, entry accesslog.Entry, index int) {
	entryDto := struct {
		Operation accesslog.OperationType `json:"operation"`
		Target    string                  `json:"target"`
		Result    accesslog.ResultType    `json:"result"`
		Rule      string                  `json:"rule"`
	}(entry)

	data, err := json.Marshal(entryDto)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal entry: %v", err))
	}
	_, _ = fmt.Fprintf(w, "id: %s:%d\n", s.sessionID, index)
	_, _ = fmt.Fprintf(w, "event: entry\n")
	_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
}

// sendSessionEvent sends the session ID as an SSE event with an id field
// encoding the resume point. This ensures Last-Event-ID is always set after
// the initial batch, so cross-session reconnects are detected even when no
// entry events are sent (e.g. when ?from matches the entry count).
// Write errors are ignored: they only occur on client disconnect, which ctx.Done handles.
func (s *Server) sendSessionEvent(w http.ResponseWriter, startIndex int) {
	_, _ = fmt.Fprintf(w, "id: %s:%d\n", s.sessionID, startIndex-1)
	_, _ = fmt.Fprintf(w, "event: session\n")
	_, _ = fmt.Fprintf(w, "data: %s\n\n", s.sessionID)
}

// sendStatusEvent sends the run status as an SSE event.
// Write errors are ignored: they only occur on client disconnect, which ctx.Done handles.
func (s *Server) sendStatusEvent(w http.ResponseWriter, status runner.RunStatus) {
	statusDto := struct {
		Running  bool   `json:"running"`
		ExitCode int    `json:"exitCode"`
		Error    string `json:"error"`
		Command  string `json:"command"`
	}(status)

	data, err := json.Marshal(statusDto)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal status: %v", err))
	}
	_, _ = fmt.Fprintf(w, "event: status\n")
	_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
}

// handleStart handles POST /api/start requests.
// Starts (or restarts) the monitored sandbox run with the CLI-provided command.
func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Start the run (stops any active run first)
	// Use the server's context, not the request context (which gets canceled immediately)
	if err := s.runner.Start(s.runCtx, s.cfg, s.command); err != nil { //nolint:contextcheck // intentionally use server ctx, not request ctx
		http.Error(w, fmt.Sprintf("Failed to start run: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// handleStop handles POST /api/stop requests.
// Stops the currently running sandbox process.
func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Stop the run (no-op if not running)
	s.runner.Stop()

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

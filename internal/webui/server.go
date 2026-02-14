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
	logger     *accesslog.Logger
	status     StatusProvider
	port       string
	addr       string // actual bound address, set by Start
	sessionID  string
	httpServer *http.Server
}

// RunStatus represents the current state of the sandboxed process.
type RunStatus struct {
	Running  bool
	ExitCode int
	Error    string
	Command  string
}

// StatusProvider provides read-only access to sandbox process status.
// Consumers call Status to get the current snapshot, Subscribe/Unsubscribe
// to receive change notifications.
type StatusProvider interface {
	Status() RunStatus
	Subscribe() chan struct{}
	Unsubscribe(ch chan struct{})
}

// New creates a new Server that displays entries from the given logger and status provider.
// The server binds to 127.0.0.1:port when Start() is called.
func New(logger *accesslog.Logger, status StatusProvider, port string) *Server {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(fmt.Sprintf("generate session ID: %v", err))
	}
	return &Server{
		logger:     logger,
		status:     status,
		port:       port,
		addr:       "",
		sessionID:  hex.EncodeToString(buf[:]),
		httpServer: nil,
	}
}

// Start starts the HTTP server on 127.0.0.1:port.
// Returns an error if the port is already in use or invalid.
// Start is non-blocking; the server runs in a background goroutine.
func (s *Server) Start(ctx context.Context) error {
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:"+s.port)
	if err != nil {
		return fmt.Errorf("listen on port %s: %w", s.port, err)
	}
	s.addr = listener.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/events", s.handleEvents)

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
	entries := s.logger.Entries()
	status := s.status.Status()

	data := struct {
		Entries    []accesslog.Entry
		EntryCount int
		Status     RunStatus
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

	// Subscribe to new entries and status changes. Do it before sending initial data to avoid
	// missing updates that arrive between initial data and subscription
	entryCh := s.logger.Subscribe()
	defer s.logger.Unsubscribe(entryCh)

	statusCh := s.status.Subscribe()
	defer s.status.Unsubscribe(statusCh)

	// Send session event, initial status, and initial entries from startIndex
	s.sendSessionEvent(w, startIndex)
	s.sendStatusEvent(w, s.status.Status())
	entries := s.logger.Entries()
	for i := startIndex; i < len(entries); i++ {
		s.sendEntryEvent(w, entries[i], i)
	}
	flusher.Flush()

	// Stream new entries as they arrive
	ctx := r.Context()
	keepaliveTicker := time.NewTicker(sseKeepaliveInterval)
	defer keepaliveTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-entryCh:
			// New entries available, send them
			currentEntries := s.logger.Entries()
			lastSentIndex := len(entries) - 1
			for i := lastSentIndex + 1; i < len(currentEntries); i++ {
				s.sendEntryEvent(w, currentEntries[i], i)
			}
			entries = currentEntries
			flusher.Flush()
		case <-statusCh:
			s.sendStatusEvent(w, s.status.Status())
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
func (s *Server) sendStatusEvent(w http.ResponseWriter, status RunStatus) {
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

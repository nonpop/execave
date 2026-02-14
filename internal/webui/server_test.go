package webui

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockStatus implements StatusProvider for testing.
type MockStatus struct {
	RunStatus RunStatus
	Subs      map[chan struct{}]bool
}

func NewMockStatus() *MockStatus {
	return &MockStatus{
		RunStatus: RunStatus{Running: true, ExitCode: 0, Error: "", Command: "echo hello"},
		Subs:      make(map[chan struct{}]bool),
	}
}

func (m *MockStatus) Status() RunStatus { return m.RunStatus }
func (m *MockStatus) Subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	m.Subs[ch] = true
	return ch
}
func (m *MockStatus) Unsubscribe(ch chan struct{}) { delete(m.Subs, ch) }

// --- parseLastEventID unit tests ---

func TestParseLastEventID_Valid(t *testing.T) {
	session, index, ok := parseLastEventID("abc123:42")
	require.True(t, ok)
	assert.Equal(t, "abc123", session)
	assert.Equal(t, 42, index)
}

func TestParseLastEventID_NoColon(t *testing.T) {
	_, _, ok := parseLastEventID("abc123")
	assert.False(t, ok)
}

func TestParseLastEventID_NonNumericIndex(t *testing.T) {
	_, _, ok := parseLastEventID("abc123:notanumber")
	assert.False(t, ok)
}

func TestParseLastEventID_Empty(t *testing.T) {
	_, _, ok := parseLastEventID("")
	assert.False(t, ok)
}

func TestParseLastEventID_MultipleColons(t *testing.T) {
	// Only first colon splits; "1:2" is not a valid int
	_, _, ok := parseLastEventID("abc:1:2")
	assert.False(t, ok)
}

func TestParseLastEventID_EmptySession(t *testing.T) {
	_, _, ok := parseLastEventID(":42")
	assert.False(t, ok)
}

func TestParseLastEventID_ZeroIndex(t *testing.T) {
	session, index, ok := parseLastEventID("abc:0")
	require.True(t, ok)
	assert.Equal(t, "abc", session)
	assert.Equal(t, 0, index)
}

// --- SSE integration tests ---

func TestSSE_SessionEventSentFirst(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger, NewMockStatus())

	sessionID := GetSessionID(t, srv.URL())

	// Connect to SSE
	resp, err := http.Get(srv.URL() + "/events")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// First event should be "session"
	events := ReadSSEEvents(t, resp, 2) // session + status
	require.GreaterOrEqual(t, len(events), 2)
	assert.Equal(t, "session", events[0].Event)
	assert.Equal(t, sessionID, events[0].Data)
	assert.Equal(t, "status", events[1].Event)
}

func TestSSE_EntryEventIDFormat(t *testing.T) {
	logger := accesslog.New(nil)
	require.NoError(t, logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/bin/test",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	}))

	srv := StartServer(t, logger, NewMockStatus())
	sessionID := GetSessionID(t, srv.URL())

	resp, err := http.Get(srv.URL() + "/events")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// session + status + 1 entry
	events := ReadSSEEvents(t, resp, 3)
	require.GreaterOrEqual(t, len(events), 3)

	entryEvent := events[2]
	assert.Equal(t, "entry", entryEvent.Event)
	assert.Equal(t, sessionID+":0", entryEvent.ID)
}

func TestSSE_SameSessionReconnect(t *testing.T) {
	logger := accesslog.New(nil)
	for i := range 3 {
		require.NoError(t, logger.Log(accesslog.Entry{
			Operation: accesslog.OperationRead,
			Target:    "/usr/bin/test" + strings.Repeat("x", i),
			Result:    accesslog.ResultOK,
			Rule:      "fs:ro:/usr",
		}))
	}

	srv := StartServer(t, logger, NewMockStatus())
	sessionID := GetSessionID(t, srv.URL())

	// Reconnect with Last-Event-ID from same session at index 1
	req, err := http.NewRequest(http.MethodGet, srv.URL()+"/events", nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", sessionID+":1")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// Should get: session + status + entry at index 2 only
	events := ReadSSEEvents(t, resp, 3)
	require.GreaterOrEqual(t, len(events), 3)
	assert.Equal(t, "session", events[0].Event)
	assert.Equal(t, "status", events[1].Event)
	assert.Equal(t, "entry", events[2].Event)
	assert.Equal(t, sessionID+":2", events[2].ID)
}

func TestSSE_CrossSessionReconnect(t *testing.T) {
	logger := accesslog.New(nil)
	for i := range 2 {
		require.NoError(t, logger.Log(accesslog.Entry{
			Operation: accesslog.OperationRead,
			Target:    "/usr/bin/test" + strings.Repeat("x", i),
			Result:    accesslog.ResultOK,
			Rule:      "fs:ro:/usr",
		}))
	}

	srv := StartServer(t, logger, NewMockStatus())
	sessionID := GetSessionID(t, srv.URL())

	// Reconnect with Last-Event-ID from a different session
	req, err := http.NewRequest(http.MethodGet, srv.URL()+"/events", nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", "oldsession:50")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// Should replay from 0: session + status + 2 entries
	events := ReadSSEEvents(t, resp, 4)
	require.GreaterOrEqual(t, len(events), 4)
	assert.Equal(t, "session", events[0].Event)
	assert.Equal(t, sessionID, events[0].Data)
	assert.Equal(t, "entry", events[2].Event)
	assert.Equal(t, sessionID+":0", events[2].ID)
	assert.Equal(t, "entry", events[3].Event)
	assert.Equal(t, sessionID+":1", events[3].ID)
}

// TestSSE_SessionEventIDEnablesCrossSessionDetection verifies that when a
// client connects with ?from=N (matching the entry count, so no entry events
// are sent), the session event still carries an id that enables cross-session
// detection on reconnection to a different server.
func TestSSE_SessionEventIDEnablesCrossSessionDetection(t *testing.T) {
	// Server 1: 3 entries, connect with ?from=3 (no entry events sent)
	logger1 := accesslog.New(nil)
	for i := range 3 {
		require.NoError(t, logger1.Log(accesslog.Entry{
			Operation: accesslog.OperationRead,
			Target:    "/usr/bin/test" + strings.Repeat("x", i),
			Result:    accesslog.ResultOK,
			Rule:      "fs:ro:/usr",
		}))
	}
	srv1 := StartServer(t, logger1, NewMockStatus())

	resp1, err := http.Get(srv1.URL() + "/events?from=3")
	require.NoError(t, err)
	events1 := ReadSSEEvents(t, resp1, 2) // session + status only
	resp1.Body.Close()                    //nolint:errcheck,gosec // best-effort close in test
	require.Len(t, events1, 2)
	sessionEventID := events1[0].ID
	require.NotEmpty(t, sessionEventID, "session event must have an id for Last-Event-ID")

	// Server 2: 2 entries, reconnect with Last-Event-ID from server1's session event
	logger2 := accesslog.New(nil)
	for i := range 2 {
		require.NoError(t, logger2.Log(accesslog.Entry{
			Operation: accesslog.OperationWrite,
			Target:    "/tmp/file" + strings.Repeat("y", i),
			Result:    accesslog.ResultDeny,
			Rule:      "fs:deny:/tmp",
		}))
	}
	srv2 := StartServer(t, logger2, NewMockStatus())
	srv2SessionID := GetSessionID(t, srv2.URL())

	req, err := http.NewRequest(http.MethodGet, srv2.URL()+"/events", nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", sessionEventID)

	resp2, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp2.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// Should detect cross-session and replay from 0: session + status + 2 entries
	events2 := ReadSSEEvents(t, resp2, 4)
	require.Len(t, events2, 4)
	assert.Equal(t, "session", events2[0].Event)
	assert.Equal(t, srv2SessionID, events2[0].Data)
	assert.Equal(t, "entry", events2[2].Event)
	assert.Equal(t, srv2SessionID+":0", events2[2].ID)
	assert.Equal(t, "entry", events2[3].Event)
	assert.Equal(t, srv2SessionID+":1", events2[3].ID)
}

func TestSSE_MalformedLastEventID(t *testing.T) {
	logger := accesslog.New(nil)
	require.NoError(t, logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/bin/test",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	}))

	srv := StartServer(t, logger, NewMockStatus())
	sessionID := GetSessionID(t, srv.URL())

	// Reconnect with malformed Last-Event-ID (old numeric format)
	req, err := http.NewRequest(http.MethodGet, srv.URL()+"/events", nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", "42")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// Should replay from 0: session + status + 1 entry
	events := ReadSSEEvents(t, resp, 3)
	require.GreaterOrEqual(t, len(events), 3)
	assert.Equal(t, "session", events[0].Event)
	assert.Equal(t, sessionID, events[0].Data)
	assert.Equal(t, "entry", events[2].Event)
	assert.Equal(t, sessionID+":0", events[2].ID)
}

func TestIndex_SessionIDInHTML(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger, NewMockStatus())

	resp, err := http.Get(srv.URL() + "/")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	scanner := bufio.NewScanner(resp.Body)
	found := false
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), `data-session-id="`) {
			found = true
			break
		}
	}
	assert.True(t, found)
}

func TestIndex_CommandInHTML(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger, NewMockStatus())

	resp, err := http.Get(srv.URL() + "/")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test

	scanner := bufio.NewScanner(resp.Body)
	found := false
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "echo hello") {
			found = true
			break
		}
	}
	assert.True(t, found, "command should appear in HTML response")
}

func TestSSE_CommandInStatusEvent(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger, NewMockStatus())

	resp, err := http.Get(srv.URL() + "/events")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// session + status
	events := ReadSSEEvents(t, resp, 2)
	require.GreaterOrEqual(t, len(events), 2)
	assert.Equal(t, "status", events[1].Event)
	assert.Contains(t, events[1].Data, `"command":"echo hello"`)
}

// --- helpers ---

// StartServer creates and starts a Server on an OS-assigned port, returning it.
// Use srv.URL() to get the actual bound address.
func StartServer(t *testing.T, logger *accesslog.Logger, status StatusProvider) *Server {
	t.Helper()
	srv := New(logger, status, "0")
	require.NoError(t, srv.Start(t.Context()))
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })
	return srv
}

type SSEEvent struct {
	Event string
	Data  string
	ID    string
}

// HasContent reports whether any field is non-empty.
func (e SSEEvent) HasContent() bool {
	return e.Event != "" || e.Data != "" || e.ID != ""
}

// ReadSSEEvents reads n SSE events from the response body.
func ReadSSEEvents(t *testing.T, resp *http.Response, n int) []SSEEvent {
	t.Helper()
	scanner := bufio.NewScanner(resp.Body)
	var events []SSEEvent
	var current SSEEvent

	for len(events) < n && scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			current.Event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			current.Data = strings.TrimPrefix(line, "data: ")
		case strings.HasPrefix(line, "id: "):
			current.ID = strings.TrimPrefix(line, "id: ")
		case line == "":
			if current.Event != "" || current.Data != "" || current.ID != "" {
				events = append(events, current)
				current = SSEEvent{Event: "", Data: "", ID: ""}
			}
		}
	}
	return events
}

// GetSessionID extracts the session ID from the index HTML page.
func GetSessionID(t *testing.T, baseURL string) string {
	t.Helper()
	resp, err := http.Get(baseURL + "/")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if _, after, ok := strings.Cut(line, `data-session-id="`); ok {
			rest := after
			end := strings.IndexByte(rest, '"')
			if end > 0 {
				return rest[:end]
			}
		}
	}
	t.Fatal("data-session-id attribute not found in HTML response")
	return ""
}

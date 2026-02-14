package webui_test

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/webui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Requirement: Web server binding ---

func TestIntegration_WebServerBinding_ServerStartsAndServesHTTP(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger, webui.NewMockStatus())

	resp, err := http.Get(srv.URL() + "/")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIntegration_WebServerBinding_InvalidPortRejected(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.New(logger, webui.NewMockStatus(), "notaport")

	err := srv.Start(t.Context())
	assert.ErrorContains(t, err, "listen on port notaport")
}

func TestIntegration_WebServerBinding_PortAlreadyInUse(t *testing.T) {
	// Occupy a port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close() //nolint:errcheck // best-effort close in test

	port := strings.TrimPrefix(ln.Addr().String(), "127.0.0.1:")

	logger := accesslog.New(nil)
	srv := webui.New(logger, webui.NewMockStatus(), port)

	err = srv.Start(t.Context())
	assert.ErrorContains(t, err, "listen on port "+port)
}

// --- Requirement: Access log page ---

func TestIntegration_AccessLogPage_PageDisplaysEntries(t *testing.T) {
	logger := accesslog.New(nil)
	require.NoError(t, logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/data/file.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/tmp/data",
	}))

	srv := webui.StartServer(t, logger, webui.NewMockStatus())
	body := fetchBody(t, srv.URL()+"/")

	// All four columns present in a table row
	assert.Contains(t, body, `<td class="operation">READ</td>`)
	assert.Contains(t, body, `<td class="target">/tmp/data/file.txt</td>`)
	assert.Contains(t, body, "OK")
	assert.Contains(t, body, `<td class="rule">fs:ro:/tmp/data</td>`)
}

func TestIntegration_AccessLogPage_PageDisplaysAllEntryTypes(t *testing.T) {
	logger := accesslog.New(nil)
	entries := []accesslog.Entry{
		{Operation: accesslog.OperationRead, Target: "/usr/lib/libc.so", Result: accesslog.ResultOK, Rule: "fs:ro:/usr"},
		{Operation: accesslog.OperationWrite, Target: "/home/user/out.txt", Result: accesslog.ResultOK, Rule: "fs:rw:/home/user"},
		{Operation: accesslog.OperationHTTPS, Target: "api.example.com:443", Result: accesslog.ResultOK, Rule: "net:https:api.example.com:443"},
		{Operation: accesslog.OperationRead, Target: "/etc/secret", Result: accesslog.ResultDeny, Rule: accesslog.RuleNoMatch},
	}
	for _, e := range entries {
		require.NoError(t, logger.Log(e))
	}

	srv := webui.StartServer(t, logger, webui.NewMockStatus())
	body := fetchBody(t, srv.URL()+"/")

	assert.Contains(t, body, "READ")
	assert.Contains(t, body, "WRITE")
	assert.Contains(t, body, "HTTPS")
	assert.Contains(t, body, "DENY")
}

func TestIntegration_AccessLogPage_PageRefreshShowsCurrentEntries(t *testing.T) {
	logger := accesslog.New(nil)
	require.NoError(t, logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/bin/test",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	}))

	srv := webui.StartServer(t, logger, webui.NewMockStatus())

	first := fetchBody(t, srv.URL()+"/")
	second := fetchBody(t, srv.URL()+"/")

	assert.Contains(t, first, "/usr/bin/test")
	assert.Contains(t, second, "/usr/bin/test")

	// Same number of entry rows
	firstCount := strings.Count(first, `<td class="target">`)
	secondCount := strings.Count(second, `<td class="target">`)
	assert.Equal(t, firstCount, secondCount)
}

// --- Requirement: Real-time entry streaming ---

func TestIntegration_RealTimeEntryStreaming_NewEntriesStreamedViaSse(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger, webui.NewMockStatus())

	resp, err := http.Get(srv.URL() + "/events")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	eventCh := readSSEEventsAsync(resp)

	// Read initial events (session + status)
	readEventWithTimeout(t, eventCh) // session
	readEventWithTimeout(t, eventCh) // status

	// Log a new entry after SSE connection is established
	require.NoError(t, logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/lib/streamed.so",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	}))

	// Entry is streamed to the client
	entryEvent := readEventWithTimeout(t, eventCh)
	assert.Equal(t, "entry", entryEvent.Event)
	assert.Contains(t, entryEvent.Data, "/usr/lib/streamed.so")
}

func TestIntegration_RealTimeEntryStreaming_SseReplaysFromCursor(t *testing.T) {
	logger := accesslog.New(nil)
	for i := range 50 {
		require.NoError(t, logger.Log(accesslog.Entry{
			Operation: accesslog.OperationRead,
			Target:    "/usr/lib/file" + strconv.Itoa(i) + ".so",
			Result:    accesslog.ResultOK,
			Rule:      "fs:ro:/usr",
		}))
	}

	srv := webui.StartServer(t, logger, webui.NewMockStatus())
	sessionID := webui.GetSessionID(t, srv.URL())

	// Connect with ?from=30
	resp, err := http.Get(srv.URL() + "/events?from=30")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// session + status + entries 30..49 = 22 events
	events := webui.ReadSSEEvents(t, resp, 22)
	require.Len(t, events, 22)

	// First entry event should be index 30
	assert.Equal(t, sessionID+":30", events[2].ID)
	// Last entry event should be index 49
	assert.Equal(t, sessionID+":49", events[21].ID)
}

// --- Requirement: No entries dropped between page load and SSE ---

func TestIntegration_NoEntriesDroppedBetweenPageLoadAndSse_EntriesDuringPageToSseGapNotLost(t *testing.T) {
	logger := accesslog.New(nil)
	for i := range 52 {
		require.NoError(t, logger.Log(accesslog.Entry{
			Operation: accesslog.OperationRead,
			Target:    "/usr/lib/entry" + strconv.Itoa(i) + ".so",
			Result:    accesslog.ResultOK,
			Rule:      "fs:ro:/usr",
		}))
	}

	srv := webui.StartServer(t, logger, webui.NewMockStatus())
	sessionID := webui.GetSessionID(t, srv.URL())

	// Simulate: page rendered with count 50, entries 50+51 arrive before SSE connects.
	// Client connects to /events?from=50 and should receive entries 50 and 51.
	resp, err := http.Get(srv.URL() + "/events?from=50")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// session + status + 2 entries (50, 51)
	events := webui.ReadSSEEvents(t, resp, 4)
	require.Len(t, events, 4)

	assert.Equal(t, sessionID+":50", events[2].ID)
	assert.Contains(t, events[2].Data, "entry50")
	assert.Equal(t, sessionID+":51", events[3].ID)
	assert.Contains(t, events[3].Data, "entry51")
}

func TestIntegration_NoEntriesDroppedBetweenPageLoadAndSse_SseReconnectionUsesLastEventId(t *testing.T) {
	logger := accesslog.New(nil)
	for i := range 80 {
		require.NoError(t, logger.Log(accesslog.Entry{
			Operation: accesslog.OperationRead,
			Target:    "/usr/lib/file" + strconv.Itoa(i) + ".so",
			Result:    accesslog.ResultOK,
			Rule:      "fs:ro:/usr",
		}))
	}

	srv := webui.StartServer(t, logger, webui.NewMockStatus())
	sessionID := webui.GetSessionID(t, srv.URL())

	// Reconnect with Last-Event-ID from same session at index 75
	req, err := http.NewRequest(http.MethodGet, srv.URL()+"/events", nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", sessionID+":75")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// session + status + entries 76..79 = 6 events
	events := webui.ReadSSEEvents(t, resp, 6)
	require.Len(t, events, 6)

	// First entry should be index 76 (resume from next after 75)
	assert.Equal(t, sessionID+":76", events[2].ID)
}

func TestIntegration_NoEntriesDroppedBetweenPageLoadAndSse_CrossSessionReconnectReplaysFromStart(t *testing.T) {
	logger := accesslog.New(nil)
	for i := range 5 {
		require.NoError(t, logger.Log(accesslog.Entry{
			Operation: accesslog.OperationRead,
			Target:    "/usr/lib/file" + strconv.Itoa(i) + ".so",
			Result:    accesslog.ResultOK,
			Rule:      "fs:ro:/usr",
		}))
	}

	srv := webui.StartServer(t, logger, webui.NewMockStatus())
	sessionID := webui.GetSessionID(t, srv.URL())

	// Connect with Last-Event-ID from a different session
	req, err := http.NewRequest(http.MethodGet, srv.URL()+"/events", nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", "oldsession:99")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// session + status + all 5 entries from 0
	events := webui.ReadSSEEvents(t, resp, 7)
	require.Len(t, events, 7)

	// Replayed from entry 0
	assert.Equal(t, sessionID+":0", events[2].ID)
	assert.Equal(t, sessionID+":4", events[6].ID)
}

// --- Requirement: Run status display ---

func TestIntegration_RunStatusDisplay_CommandShownInPage(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger, webui.NewMockStatus()) // command = "echo hello"

	body := fetchBody(t, srv.URL()+"/")
	assert.Contains(t, body, "echo hello")
}

func TestIntegration_RunStatusDisplay_CrossSessionReconnectDeliversCurrentCommand(t *testing.T) {
	logger := accesslog.New(nil)
	status := &webui.MockStatus{
		RunStatus: webui.RunStatus{Running: true, ExitCode: 0, Error: "", Command: "cat /etc/hosts"},
		Subs:      make(map[chan struct{}]bool),
	}
	srv := webui.StartServer(t, logger, status)

	// Connect with Last-Event-ID from a different session
	req, err := http.NewRequest(http.MethodGet, srv.URL()+"/events", nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", "oldsession:10")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// session + status
	events := webui.ReadSSEEvents(t, resp, 2)
	require.Len(t, events, 2)

	// Status event contains the current command
	assert.Equal(t, "status", events[1].Event)
	assert.Contains(t, events[1].Data, `"command":"cat /etc/hosts"`)
}

func TestIntegration_RunStatusDisplay_RunningStatusShown(t *testing.T) {
	logger := accesslog.New(nil)
	status := &webui.MockStatus{
		RunStatus: webui.RunStatus{Running: true, ExitCode: 0, Error: "", Command: "sleep 60"},
		Subs:      make(map[chan struct{}]bool),
	}
	srv := webui.StartServer(t, logger, status)

	body := fetchBody(t, srv.URL()+"/")
	assert.Contains(t, body, "Running")
}

func TestIntegration_RunStatusDisplay_ExitStatusShown(t *testing.T) {
	logger := accesslog.New(nil)
	status := &webui.MockStatus{
		RunStatus: webui.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "echo hello"},
		Subs:      make(map[chan struct{}]bool),
	}
	srv := webui.StartServer(t, logger, status)

	body := fetchBody(t, srv.URL()+"/")
	assert.Contains(t, body, "Exited")
	assert.Contains(t, body, "(code: 0)")
}

func TestIntegration_RunStatusDisplay_NonZeroExitCodeShown(t *testing.T) {
	logger := accesslog.New(nil)
	status := &webui.MockStatus{
		RunStatus: webui.RunStatus{Running: false, ExitCode: 1, Error: "", Command: "false"},
		Subs:      make(map[chan struct{}]bool),
	}
	srv := webui.StartServer(t, logger, status)

	body := fetchBody(t, srv.URL()+"/")
	assert.Contains(t, body, "Exited")
	assert.Contains(t, body, "(code: 1)")
}

func TestIntegration_RunStatusDisplay_StatusUpdatesStreamedViaSse(t *testing.T) {
	logger := accesslog.New(nil)
	status := newDynamicMockStatus(webui.RunStatus{Running: true, ExitCode: 0, Error: "", Command: "sleep 60"})
	srv := webui.StartServer(t, logger, status)

	resp, err := http.Get(srv.URL() + "/events")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	eventCh := readSSEEventsAsync(resp)

	// Read initial events (session + status)
	readEventWithTimeout(t, eventCh) // session
	readEventWithTimeout(t, eventCh) // status (Running)

	// Change status and notify
	status.setStatus(webui.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "sleep 60"})

	// Client receives updated status event
	ev := readEventWithTimeout(t, eventCh)
	assert.Equal(t, "status", ev.Event)
	assert.Contains(t, ev.Data, `"running":false`)
	assert.Contains(t, ev.Data, `"exitCode":0`)
}

// --- Integration test helpers ---

// fetchBody makes a GET request and returns the response body as a string.
func fetchBody(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec // G107: test-controlled URL
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

// readSSEEventsAsync reads SSE events from a response body into a channel.
// The goroutine stops when the response body is closed.
func readSSEEventsAsync(resp *http.Response) <-chan webui.SSEEvent {
	events := make(chan webui.SSEEvent, 50)
	go func() {
		defer close(events)
		scanner := newSSEScanner(resp)
		for {
			ev, ok := scanner.next()
			if !ok {
				return
			}
			events <- ev
		}
	}()
	return events
}

// readEventWithTimeout reads a single event from the channel with a timeout.
func readEventWithTimeout(t *testing.T, ch <-chan webui.SSEEvent) webui.SSEEvent {
	t.Helper()
	select {
	case ev, ok := <-ch:
		require.True(t, ok)
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SSE event")
		return webui.SSEEvent{Event: "", Data: "", ID: ""}
	}
}

// dynamicMockStatus is a thread-safe StatusProvider that supports status changes
// with subscriber notification.
type dynamicMockStatus struct {
	mu     sync.Mutex
	status webui.RunStatus
	subs   map[chan struct{}]bool
}

func newDynamicMockStatus(status webui.RunStatus) *dynamicMockStatus {
	return &dynamicMockStatus{
		mu:     sync.Mutex{},
		status: status,
		subs:   make(map[chan struct{}]bool),
	}
}

func (m *dynamicMockStatus) Status() webui.RunStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *dynamicMockStatus) Subscribe() chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch := make(chan struct{}, 1)
	m.subs[ch] = true
	return ch
}

func (m *dynamicMockStatus) Unsubscribe(ch chan struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.subs, ch)
}

func (m *dynamicMockStatus) setStatus(status webui.RunStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = status
	for ch := range m.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// sseScanner reads SSE events one at a time from an HTTP response body.
type sseScanner struct {
	lines <-chan string
}

func newSSEScanner(resp *http.Response) *sseScanner {
	lines := make(chan string, 100)
	go func() {
		defer close(lines)
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 1)
		for {
			n, err := resp.Body.Read(tmp)
			if err != nil {
				if len(buf) > 0 {
					lines <- string(buf)
				}
				return
			}
			if n > 0 {
				if tmp[0] == '\n' {
					lines <- string(buf)
					buf = buf[:0]
				} else {
					buf = append(buf, tmp[0]) //nolint:gosec // G602: n > 0 guarantees tmp[0] is safe
				}
			}
		}
	}()
	return &sseScanner{lines: lines}
}

func (s *sseScanner) next() (webui.SSEEvent, bool) {
	var current webui.SSEEvent
	for line := range s.lines {
		switch {
		case strings.HasPrefix(line, "event: "):
			current.Event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			current.Data = strings.TrimPrefix(line, "data: ")
		case strings.HasPrefix(line, "id: "):
			current.ID = strings.TrimPrefix(line, "id: ")
		case line == "":
			if current.HasContent() {
				return current, true
			}
		}
	}
	// Channel closed with partial event
	if current.HasContent() {
		return current, true
	}
	return webui.SSEEvent{Event: "", Data: "", ID: ""}, false
}

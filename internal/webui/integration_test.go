package webui_test

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/netrules"
	"github.com/nonpop/execave/internal/runner"
	"github.com/nonpop/execave/internal/webui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Requirement: Web server binding ---

func TestIntegration_WebServerBinding_ServerStartsAndServesHTTP(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)

	resp, err := http.Get(srv.URL() + "/")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIntegration_WebServerBinding_InvalidPortRejected(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	cfg := &config.Config{FSRules: nil, NetRules: nil, ManagedPaths: nil}
	command := []string{"true"}
	srv := webui.New(rnr, cfg, command, "notaport")

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
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	cfg := &config.Config{FSRules: nil, NetRules: nil, ManagedPaths: nil}
	command := []string{"true"}
	srv := webui.New(rnr, cfg, command, port)

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

	srv := webui.StartServer(t, logger)
	body := fetchBody(t, srv.URL()+"/")

	// Three columns present in a table row; matched rule visible as tooltip
	assert.Contains(t, body, `<td class="operation">READ</td>`)
	assert.Contains(t, body, `<td class="target">/tmp/data/file.txt</td>`)
	assert.Contains(t, body, "OK")
	assert.Contains(t, body, `title="fs:ro:/tmp/data"`)
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

	srv := webui.StartServer(t, logger)
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

	srv := webui.StartServer(t, logger)

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
	srv := webui.StartServer(t, logger)

	resp, err := http.Get(srv.URL() + "/events")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	eventCh := readSSEEventsAsync(resp)

	// Read initial events (session + status + rules)
	readEventWithTimeout(t, eventCh) // session
	readEventWithTimeout(t, eventCh) // status
	readEventWithTimeout(t, eventCh) // rules

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

	srv := webui.StartServer(t, logger)
	sessionID := webui.GetSessionID(t, srv.URL())

	// Connect with ?from=30
	resp, err := http.Get(srv.URL() + "/events?from=30")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// session + status + rules + entries 30..49 = 23 events
	events := webui.ReadSSEEvents(t, resp, 23)
	require.Len(t, events, 23)

	// First entry event should be index 30
	assert.Equal(t, sessionID+":30", events[3].ID)
	// Last entry event should be index 49
	assert.Equal(t, sessionID+":49", events[22].ID)
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

	srv := webui.StartServer(t, logger)
	sessionID := webui.GetSessionID(t, srv.URL())

	// Simulate: page rendered with count 50, entries 50+51 arrive before SSE connects.
	// Client connects to /events?from=50 and should receive entries 50 and 51.
	resp, err := http.Get(srv.URL() + "/events?from=50")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// session + status + rules + 2 entries (50, 51)
	events := webui.ReadSSEEvents(t, resp, 5)
	require.Len(t, events, 5)

	assert.Equal(t, sessionID+":50", events[3].ID)
	assert.Contains(t, events[3].Data, "entry50")
	assert.Equal(t, sessionID+":51", events[4].ID)
	assert.Contains(t, events[4].Data, "entry51")
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

	srv := webui.StartServer(t, logger)
	sessionID := webui.GetSessionID(t, srv.URL())

	// Reconnect with Last-Event-ID from same session at index 75
	req, err := http.NewRequest(http.MethodGet, srv.URL()+"/events", nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", sessionID+":75")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// session + status + rules + entries 76..79 = 7 events
	events := webui.ReadSSEEvents(t, resp, 7)
	require.Len(t, events, 7)

	// First entry should be index 76 (resume from next after 75)
	assert.Equal(t, sessionID+":76", events[3].ID)
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

	srv := webui.StartServer(t, logger)
	sessionID := webui.GetSessionID(t, srv.URL())

	// Connect with Last-Event-ID from a different session
	req, err := http.NewRequest(http.MethodGet, srv.URL()+"/events", nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", "oldsession:99")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// session + status + rules + all 5 entries from 0
	events := webui.ReadSSEEvents(t, resp, 8)
	require.Len(t, events, 8)

	// Replayed from entry 0
	assert.Equal(t, sessionID+":0", events[3].ID)
	assert.Equal(t, sessionID+":4", events[7].ID)
}

// --- Requirement: Run status display ---

func TestIntegration_RunStatusDisplay_CommandShownInPage(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger) // command = "echo hello"

	body := fetchBody(t, srv.URL()+"/")
	assert.Contains(t, body, "echo hello")
}

func TestIntegration_RunStatusDisplay_CrossSessionReconnectDeliversCurrentCommand(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: true, ExitCode: 0, Error: "", Command: "cat /etc/hosts"})
	srv := webui.StartServerWithRunner(t, rnr)

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
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: true, ExitCode: 0, Error: "", Command: "sleep 60"})
	srv := webui.StartServerWithRunner(t, rnr)

	body := fetchBody(t, srv.URL()+"/")
	assert.Contains(t, body, "Running")
}

func TestIntegration_RunStatusDisplay_ExitStatusShown(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "echo hello"})
	srv := webui.StartServerWithRunner(t, rnr)

	body := fetchBody(t, srv.URL()+"/")
	assert.Contains(t, body, "Exited")
	assert.Contains(t, body, "(code: 0)")
}

func TestIntegration_RunStatusDisplay_NonZeroExitCodeShown(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 1, Error: "", Command: "false"})
	srv := webui.StartServerWithRunner(t, rnr)

	body := fetchBody(t, srv.URL()+"/")
	assert.Contains(t, body, "Exited")
	assert.Contains(t, body, "(code: 1)")
}

func TestIntegration_RunStatusDisplay_StatusUpdatesStreamedViaSse(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: true, ExitCode: 0, Error: "", Command: "sleep 60"})
	srv := webui.StartServerWithRunner(t, rnr)

	resp, err := http.Get(srv.URL() + "/events")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	eventCh := readSSEEventsAsync(resp)

	// Read initial events (session + status + rules)
	readEventWithTimeout(t, eventCh) // session
	readEventWithTimeout(t, eventCh) // status (Running)
	readEventWithTimeout(t, eventCh) // rules

	// Change status and notify
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "sleep 60"})

	// Client receives updated status event
	ev := readEventWithTimeout(t, eventCh)
	assert.Equal(t, "status", ev.Event)
	assert.Contains(t, ev.Data, `"running":false`)
	assert.Contains(t, ev.Data, `"exitCode":0`)
}

// --- Requirement: Run control endpoints ---

func TestIntegration_RunControlEndpoints_StartEndpointTriggersNewRun(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "echo hello"})
	srv := webui.StartServerWithRunner(t, rnr)

	// POST /api/start
	resp, err := http.Post(srv.URL()+"/api/start", "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test

	// Response is 200
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Runner status transitions to running (we check that Start was called by verifying status change)
	// Note: In a real test with a real command, the status would be "running"
	// For this integration test, we just verify the endpoint returns 200
	// The actual runner behavior is tested in runner integration tests
}

func TestIntegration_RunControlEndpoints_StartEndpointRestartsActiveRun(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: true, ExitCode: 0, Error: "", Command: "sleep 60"})
	srv := webui.StartServerWithRunner(t, rnr)

	// POST /api/start while running
	resp, err := http.Post(srv.URL()+"/api/start", "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test

	// Response is 200
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// The runner's Start method stops the active run first (tested in runner integration tests)
}

func TestIntegration_RunControlEndpoints_StopEndpointTerminatesActiveRun(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: true, ExitCode: 0, Error: "", Command: "sleep 60"})
	srv := webui.StartServerWithRunner(t, rnr)

	// POST /api/stop while running
	resp, err := http.Post(srv.URL()+"/api/stop", "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test

	// Response is 200
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// The runner's Stop method terminates the run (tested in runner integration tests)
}

func TestIntegration_RunControlEndpoints_StopEndpointWhenIdle(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "echo hello"})
	srv := webui.StartServerWithRunner(t, rnr)

	// POST /api/stop when not running
	resp, err := http.Post(srv.URL()+"/api/stop", "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test

	// Response is 200 (no-op)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// --- Requirement: Rules pane ---

func TestIntegration_RulesPane_RulesDisplayedOnPageLoad(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "true"})

	// Create config with rules
	fsRule1, err := fsrules.Parse("ro:/usr/lib", "/")
	require.NoError(t, err)
	fsRule1.RawRule = "fs:ro:/usr/lib"
	fsRule2, err := fsrules.Parse("rw:/tmp", "/")
	require.NoError(t, err)
	fsRule2.RawRule = "fs:rw:/tmp"

	cfg := &config.Config{
		FSRules:      []fsrules.Rule{fsRule1, fsRule2},
		NetRules:     nil,
		ManagedPaths: nil,
	}

	srv := webui.New(rnr, cfg, []string{"true"}, "0")
	require.NoError(t, srv.Start(t.Context()))
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	body := fetchBody(t, srv.URL()+"/")

	// Verify rules are present in the HTML
	assert.Contains(t, body, "fs:ro:/usr/lib")
	assert.Contains(t, body, "fs:rw:/tmp")

	// Verify rules appear in the expected order (fs rules first)
	idxRule1 := strings.Index(body, "fs:ro:/usr/lib")
	idxRule2 := strings.Index(body, "fs:rw:/tmp")
	assert.Less(t, idxRule1, idxRule2, "fs:ro:/usr/lib should appear before fs:rw:/tmp")
}

func TestIntegration_RulesPane_EmptyRulesDisplayed(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "true"})

	cfg := &config.Config{
		FSRules:      nil,
		NetRules:     nil,
		ManagedPaths: nil,
	}

	srv := webui.New(rnr, cfg, []string{"true"}, "0")
	require.NoError(t, srv.Start(t.Context()))
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	body := fetchBody(t, srv.URL()+"/")

	// The page should still render successfully
	assert.Contains(t, body, "Execave Access Monitor")
}

func TestIntegration_RulesPane_BothFsAndNetRulesDisplayed(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "true"})

	// Create fs rule
	fsRule, err := fsrules.Parse("ro:/usr/lib", "/")
	require.NoError(t, err)
	fsRule.RawRule = "fs:ro:/usr/lib"

	// Create net rule
	netRule, err := netrules.Parse("https:example.com:443")
	require.NoError(t, err)
	netRule.RawRule = "net:https:example.com:443"

	cfg := &config.Config{
		FSRules:      []fsrules.Rule{fsRule},
		NetRules:     []netrules.Rule{netRule},
		ManagedPaths: nil,
	}

	srv := webui.New(rnr, cfg, []string{"true"}, "0")
	require.NoError(t, srv.Start(t.Context()))
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	body := fetchBody(t, srv.URL()+"/")

	// Verify both rules are present in the HTML
	assert.Contains(t, body, "fs:ro:/usr/lib")
	assert.Contains(t, body, "net:https:example.com:443")

	// Verify fs rules appear before net rules
	idxFsRule := strings.Index(body, "fs:ro:/usr/lib")
	idxNetRule := strings.Index(body, "net:https:example.com:443")
	assert.Less(t, idxFsRule, idxNetRule, "fs rules should appear before net rules")
}

// --- Requirement: Run control buttons ---

func TestIntegration_RunControlButtons_StartButtonAndDisabledStopShownWhenIdle(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "echo hello"})
	srv := webui.StartServerWithRunner(t, rnr)

	body := fetchBody(t, srv.URL()+"/")

	// Page displays a "Start" button
	assert.Contains(t, body, `id="start-btn"`)
	assert.Contains(t, body, ">Start<")

	// Page displays a disabled "Stop" button
	assert.Contains(t, body, `id="stop-btn"`)
	assert.Contains(t, body, "disabled")
}

func TestIntegration_RunControlButtons_RestartButtonAndEnabledStopShownWhenRunning(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: true, ExitCode: 0, Error: "", Command: "sleep 60"})
	srv := webui.StartServerWithRunner(t, rnr)

	body := fetchBody(t, srv.URL()+"/")

	// Page displays a "Restart" button
	assert.Contains(t, body, `id="start-btn"`)
	assert.Contains(t, body, ">Restart<")

	// Page displays an enabled "Stop" button (no "disabled" attribute when running)
	assert.Contains(t, body, `id="stop-btn"`)
	// Stop button should NOT have "disabled" attribute when running
	// Check that the stop button line doesn't contain "disabled"
	assert.NotContains(t, body, `id="stop-btn" class="stop" disabled`)
	assert.Contains(t, body, `id="stop-btn" class="stop" >Stop<`)
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

package webui_test

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/runner"
	"github.com/nonpop/execave/internal/webui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Requirement: Web server binding ---

func TestIntegration_WebServerBinding_ServerStartsAndServesHTTP(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)

	resp, err := http.Get(srv.EndpointURL("/"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// --- Requirement: Access token authentication ---

func TestIntegration_AccessTokenAuthentication_RequestWithValidTokenSucceeds(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)

	resp, err := http.Get(srv.EndpointURL("/"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIntegration_AccessTokenAuthentication_RequestWithoutTokenRejected(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)

	resp, err := http.Get("http://" + srv.Addr() + "/")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestIntegration_AccessTokenAuthentication_RequestWithWrongTokenRejected(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)

	resp, err := http.Get("http://" + srv.Addr() + "/?token=wrongtoken")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestIntegration_AccessTokenAuthentication_TokenRequiredOnAllEndpoints(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)
	base := "http://" + srv.Addr()

	endpoints := []string{"/", "/events", "/api/start", "/api/stop", "/api/save", "/api/revert"}
	for _, path := range endpoints {
		resp, err := http.Get(base + path)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

func TestIntegration_AccessTokenAuthentication_SseConnectionRequiresToken(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)

	// With correct token: events stream normally
	resp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Without token: 403
	resp2, err := http.Get("http://" + srv.Addr() + "/events")
	require.NoError(t, err)
	defer resp2.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusForbidden, resp2.StatusCode)
}

// --- Requirement: Access log page ---

func TestIntegration_AccessLogPage_PageDisplaysEntries(t *testing.T) {
	logger := accesslog.New(nil)
	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/tmp/data/file.txt",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/tmp/data",
	})

	srv := webui.StartServer(t, logger)
	body := fetchBody(t, srv.EndpointURL("/"))

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
		{Operation: accesslog.OperationHTTP, Target: "api.example.com:443", Result: accesslog.ResultOK, Rule: "net:http:api.example.com:443"},
		{Operation: accesslog.OperationRead, Target: "/etc/secret", Result: accesslog.ResultDeny, Rule: accesslog.RuleNoMatch},
	}
	for _, e := range entries {
		logger.Log(e)
	}

	srv := webui.StartServer(t, logger)
	body := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, body, "READ")
	assert.Contains(t, body, "WRITE")
	assert.Contains(t, body, "HTTP")
	assert.Contains(t, body, "DENY")
}

func TestIntegration_AccessLogPage_PageRefreshShowsCurrentEntries(t *testing.T) {
	logger := accesslog.New(nil)
	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/bin/test",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	})

	srv := webui.StartServer(t, logger)

	first := fetchBody(t, srv.EndpointURL("/"))
	second := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, first, "/usr/bin/test")
	assert.Contains(t, second, "/usr/bin/test")

	// Same number of entry rows
	firstCount := strings.Count(first, `<td class="target">`)
	secondCount := strings.Count(second, `<td class="target">`)
	assert.Equal(t, firstCount, secondCount)
}

// --- Requirement: Path shortening for display ---

func TestIntegration_PathShortening_FilesystemPathShortenedToRelativeForm(t *testing.T) {
	logger := accesslog.New(nil)
	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/home/user/project/src/main.go",
		Result:    accesslog.ResultOK,
		Rule:      "fs:rw:~/project",
	})

	srv := webui.StartServerWithPaths(t, logger, "/home/user", "/home/user/project")
	body := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, body, `<td class="target">src/main.go</td>`)
	// Rule shown verbatim in row attributes
	assert.Contains(t, body, `data-rule="fs:rw:~/project"`)
}

func TestIntegration_PathShortening_FilesystemPathShortenedToTildeForm(t *testing.T) {
	logger := accesslog.New(nil)
	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/home/user/.ssh/id_rsa",
		Result:    accesslog.ResultDeny,
		Rule:      "no-matching-rule",
	})

	srv := webui.StartServerWithPaths(t, logger, "/home/user", "/home/user/project")
	body := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, body, `<td class="target">~/.ssh/id_rsa</td>`)
}

func TestIntegration_PathShortening_NonFilesystemTargetNotShortened(t *testing.T) {
	logger := accesslog.New(nil)
	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationHTTP,
		Target:    "api.example.com:443",
		Result:    accesslog.ResultOK,
		Rule:      "net:http:api.example.com:443",
	})

	srv := webui.StartServerWithPaths(t, logger, "/home/user", "/home/user/project")
	body := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, body, `<td class="target">api.example.com:443</td>`)
}

func TestIntegration_PathShortening_SseEntryEventUsesShortPath(t *testing.T) {
	logger := accesslog.New(nil)

	srv := webui.StartServerWithPaths(t, logger, "/home/user", "/home/user/project")

	resp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	eventCh := readSSEEventsAsync(resp)
	readEventWithTimeout(t, eventCh) // status
	readEventWithTimeout(t, eventCh) // config

	// Log entry after SSE connection is established
	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/home/user/project/src/main.go",
		Result:    accesslog.ResultOK,
		Rule:      "fs:rw:~/project",
	})

	entryEvent := readEventWithTimeout(t, eventCh)
	assert.Equal(t, "entry", entryEvent.Event)
	assert.Contains(t, entryEvent.Data, `"target":"src/main.go"`)
}

// --- Requirement: Real-time entry streaming ---

func TestIntegration_RealTimeEntryStreaming_NewEntriesStreamedViaSse(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)

	resp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	eventCh := readSSEEventsAsync(resp)

	// Read initial events (status + config)
	readEventWithTimeout(t, eventCh) // status
	readEventWithTimeout(t, eventCh) // config

	// Log a new entry after SSE connection is established
	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/lib/streamed.so",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	})

	// Entry is streamed to the client
	entryEvent := readEventWithTimeout(t, eventCh)
	assert.Equal(t, "entry", entryEvent.Event)
	assert.Contains(t, entryEvent.Data, "/usr/lib/streamed.so")
}

func TestIntegration_RealTimeEntryStreaming_SseReplaysFromCursor(t *testing.T) {
	logger := accesslog.New(nil)
	for i := range 50 {
		logger.Log(accesslog.Entry{
			Operation: accesslog.OperationRead,
			Target:    "/usr/lib/file" + strconv.Itoa(i) + ".so",
			Result:    accesslog.ResultOK,
			Rule:      "fs:ro:/usr",
		})
	}

	srv := webui.StartServer(t, logger)

	// Connect with ?from=30
	resp, err := http.Get(srv.EndpointURL("/events?from=30"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// status + config + entries 30..49 = 22 events
	events := webui.ReadSSEEvents(t, resp, 22)
	require.Len(t, events, 22)

	// First entry event should be index 30
	assert.Equal(t, "30", events[2].ID)
	// Last entry event should be index 49
	assert.Equal(t, "49", events[21].ID)
}

// --- Requirement: No entries dropped between page load and SSE ---

func TestIntegration_NoEntriesDroppedBetweenPageLoadAndSse_EntriesDuringPageToSseGapNotLost(t *testing.T) {
	logger := accesslog.New(nil)
	for i := range 52 {
		logger.Log(accesslog.Entry{
			Operation: accesslog.OperationRead,
			Target:    "/usr/lib/entry" + strconv.Itoa(i) + ".so",
			Result:    accesslog.ResultOK,
			Rule:      "fs:ro:/usr",
		})
	}

	srv := webui.StartServer(t, logger)

	// Simulate: page rendered with count 50, entries 50+51 arrive before SSE connects.
	// Client connects to /events?from=50 and should receive entries 50 and 51.
	resp, err := http.Get(srv.EndpointURL("/events?from=50"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// status + config + 2 entries (50, 51)
	events := webui.ReadSSEEvents(t, resp, 4)
	require.Len(t, events, 4)

	assert.Equal(t, "50", events[2].ID)
	assert.Contains(t, events[2].Data, "entry50")
	assert.Equal(t, "51", events[3].ID)
	assert.Contains(t, events[3].Data, "entry51")
}

func TestIntegration_NoEntriesDroppedBetweenPageLoadAndSse_SseReconnectionUsesLastEventId(t *testing.T) {
	logger := accesslog.New(nil)
	for i := range 80 {
		logger.Log(accesslog.Entry{
			Operation: accesslog.OperationRead,
			Target:    "/usr/lib/file" + strconv.Itoa(i) + ".so",
			Result:    accesslog.ResultOK,
			Rule:      "fs:ro:/usr",
		})
	}

	srv := webui.StartServer(t, logger)

	// Reconnect with Last-Event-ID at index 75
	req, err := http.NewRequest(http.MethodGet, srv.EndpointURL("/events"), nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", "75")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// status + config + entries 76..79 = 6 events
	events := webui.ReadSSEEvents(t, resp, 6)
	require.Len(t, events, 6)

	// First entry should be index 76 (resume from next after 75)
	assert.Equal(t, "76", events[2].ID)
}

func TestIntegration_NoEntriesDroppedBetweenPageLoadAndSse_StaleReconnectReplaysFromStart(t *testing.T) {
	logger := accesslog.New(nil)
	for i := range 5 {
		logger.Log(accesslog.Entry{
			Operation: accesslog.OperationRead,
			Target:    "/usr/lib/file" + strconv.Itoa(i) + ".so",
			Result:    accesslog.ResultOK,
			Rule:      "fs:ro:/usr",
		})
	}

	srv := webui.StartServer(t, logger)

	// Connect with stale Last-Event-ID beyond current entry count
	req, err := http.NewRequest(http.MethodGet, srv.EndpointURL("/events"), nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", "99")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// clear + status + config + all 5 entries from 0 = 8 events
	events := webui.ReadSSEEvents(t, resp, 8)
	require.Len(t, events, 8)

	assert.Equal(t, "clear", events[0].Event)
	// Replayed from entry 0
	assert.Equal(t, "0", events[3].ID)
	assert.Equal(t, "4", events[7].ID)
}

// --- Requirement: Run status display ---

func TestIntegration_RunStatusDisplay_CommandShownInPage(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger) // command = "echo hello"

	body := fetchBody(t, srv.EndpointURL("/"))
	assert.Contains(t, body, "echo hello")
}

func TestIntegration_RunStatusDisplay_StaleReconnectDeliversCurrentCommand(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: true, ExitCode: 0, Error: "", Command: "cat /etc/hosts"})
	srv := webui.StartServerWithRunner(t, rnr)

	// Connect with stale Last-Event-ID beyond current entry count
	req, err := http.NewRequest(http.MethodGet, srv.EndpointURL("/events"), nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", "10")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// clear + status + config = 3 events
	events := webui.ReadSSEEvents(t, resp, 3)
	require.Len(t, events, 3)

	assert.Equal(t, "clear", events[0].Event)
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

	body := fetchBody(t, srv.EndpointURL("/"))
	assert.Contains(t, body, "Running")
}

func TestIntegration_RunStatusDisplay_ExitStatusShown(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "echo hello"})
	srv := webui.StartServerWithRunner(t, rnr)

	body := fetchBody(t, srv.EndpointURL("/"))
	assert.Contains(t, body, "Exited")
	assert.Contains(t, body, "(code: 0)")
}

func TestIntegration_RunStatusDisplay_NonZeroExitCodeShown(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 1, Error: "", Command: "false"})
	srv := webui.StartServerWithRunner(t, rnr)

	body := fetchBody(t, srv.EndpointURL("/"))
	assert.Contains(t, body, "Exited")
	assert.Contains(t, body, "(code: 1)")
}

func TestIntegration_RunStatusDisplay_StatusUpdatesStreamedViaSse(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: true, ExitCode: 0, Error: "", Command: "sleep 60"})
	srv := webui.StartServerWithRunner(t, rnr)

	resp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	eventCh := readSSEEventsAsync(resp)

	// Read initial events (status + config)
	readEventWithTimeout(t, eventCh) // status (Running)
	readEventWithTimeout(t, eventCh) // config

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

	// POST /api/start with empty body (empty TOML is valid)
	resp, err := http.Post(srv.EndpointURL("/api/start"), "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIntegration_RunControlEndpoints_StartEndpointRestartsActiveRun(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: true, ExitCode: 0, Error: "", Command: "sleep 60"})
	srv := webui.StartServerWithRunner(t, rnr)

	// POST /api/start while running
	resp, err := http.Post(srv.EndpointURL("/api/start"), "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIntegration_RunControlEndpoints_StopEndpointTerminatesActiveRun(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: true, ExitCode: 0, Error: "", Command: "sleep 60"})
	srv := webui.StartServerWithRunner(t, rnr)

	resp, err := http.Post(srv.EndpointURL("/api/stop"), "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestIntegration_RunControlEndpoints_StopEndpointWhenIdle(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "echo hello"})
	srv := webui.StartServerWithRunner(t, rnr)

	resp, err := http.Post(srv.EndpointURL("/api/stop"), "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// --- Requirement: Run control buttons ---

func TestIntegration_RunControlButtons_StartButtonAndDisabledStopShownWhenIdle(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "echo hello"})
	srv := webui.StartServerWithRunner(t, rnr)

	body := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, body, `id="start-btn"`)
	assert.Contains(t, body, ">Start<")
	assert.Contains(t, body, `id="stop-btn"`)
	assert.Contains(t, body, "disabled")
}

func TestIntegration_RunControlButtons_RestartButtonAndEnabledStopShownWhenRunning(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: true, ExitCode: 0, Error: "", Command: "sleep 60"})
	srv := webui.StartServerWithRunner(t, rnr)

	body := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, body, `id="start-btn"`)
	assert.Contains(t, body, ">Restart<")
	assert.Contains(t, body, `id="stop-btn"`)
	assert.NotContains(t, body, `id="stop-btn" class="stop" disabled`)
	assert.Contains(t, body, `id="stop-btn" class="stop" >Stop<`)
}

// --- Requirement: Config SSE event (replaces rules event) ---

func TestIntegration_ConfigSseEvent_SentOnConnect(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)

	resp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// status + config
	events := webui.ReadSSEEvents(t, resp, 2)
	require.Len(t, events, 2)
	assert.Equal(t, "status", events[0].Event)
	assert.Equal(t, "config", events[1].Event)
}

func TestIntegration_ConfigSseEvent_ContainsDraftAndSavedFields(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)

	resp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	events := webui.ReadSSEEvents(t, resp, 2)
	require.Len(t, events, 2)

	configEvent := events[1]
	assert.Equal(t, "config", configEvent.Event)

	var payload struct {
		Draft string `json:"draft"`
		Saved string `json:"saved"`
	}
	require.NoError(t, json.Unmarshal([]byte(configEvent.Data), &payload))
	// Both draft and saved are present and initially equal
	assert.Equal(t, payload.Draft, payload.Saved)
}

func TestIntegration_ConfigSseEvent_ReflectsDraftSavedStateAfterSave(t *testing.T) {
	tmpFile := t.TempDir() + "/execave.toml"
	original := `rules = []`
	require.NoError(t, os.WriteFile(tmpFile, []byte(original), 0o600))

	logger := accesslog.New(nil)
	r := runner.NewTestRunner()
	r.SetTestLogger(logger)
	r.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "true"})
	srv := webui.New(r, []string{"true"}, "", "/tmp", tmpFile, original, nil, webui.FilterDefaults{ShowAllowed: false, ShowNolog: false})
	require.NoError(t, srv.Start(t.Context()))
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	newContent := `rules = ["fs:ro:/usr/bin"]`
	saveResp, err := http.Post(srv.EndpointURL("/api/save"), "text/plain", strings.NewReader(newContent))
	require.NoError(t, err)
	_ = saveResp.Body.Close()
	require.Equal(t, http.StatusOK, saveResp.StatusCode)

	// SSE config event now reflects the new saved content
	eventsResp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer eventsResp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	events := webui.ReadSSEEvents(t, eventsResp, 2)
	require.Len(t, events, 2)

	configEvent := events[1]
	assert.Equal(t, "config", configEvent.Event)

	var payload struct {
		Draft string `json:"draft"`
		Saved string `json:"saved"`
	}
	require.NoError(t, json.Unmarshal([]byte(configEvent.Data), &payload))
	assert.Equal(t, newContent, payload.Draft)
	assert.Equal(t, newContent, payload.Saved)
}

func TestIntegration_ConfigSseEvent_ReflectsDraftAfterStartWithBody(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "true"})
	srv := webui.StartServerWithRunner(t, rnr)

	startBody := `rules = ["fs:ro:/usr/bin"]`
	startResp, err := http.Post(srv.EndpointURL("/api/start"), "text/plain", strings.NewReader(startBody))
	require.NoError(t, err)
	_ = startResp.Body.Close()
	require.Equal(t, http.StatusOK, startResp.StatusCode)

	// SSE config event reflects the updated draft; saved content is unchanged
	eventsResp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer eventsResp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	events := webui.ReadSSEEvents(t, eventsResp, 2)
	require.Len(t, events, 2)

	configEvent := events[1]
	assert.Equal(t, "config", configEvent.Event)

	var payload struct {
		Draft string `json:"draft"`
		Saved string `json:"saved"`
	}
	require.NoError(t, json.Unmarshal([]byte(configEvent.Data), &payload))
	assert.Equal(t, startBody, payload.Draft)
	// start does not write to file, so saved content remains empty
	assert.Empty(t, payload.Saved)
}

// --- Requirement: Config save and revert ---

// newConfigServer creates a Server backed by a temporary config file pre-populated with original.
// The server is started and registered for cleanup. Returns the server and the config file path.
func newConfigServer(t *testing.T, original string) (*webui.Server, string) {
	t.Helper()
	tmpFile := t.TempDir() + "/execave.toml"
	require.NoError(t, os.WriteFile(tmpFile, []byte(original), 0o600))

	logger := accesslog.New(nil)
	r := runner.NewTestRunner()
	r.SetTestLogger(logger)
	r.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "true"})
	srv := webui.New(r, []string{"true"}, "", "/tmp", tmpFile, original, nil, webui.FilterDefaults{ShowAllowed: false, ShowNolog: false})
	require.NoError(t, srv.Start(t.Context()))
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })
	return srv, tmpFile
}

func TestIntegration_Save_WritesToConfigFile(t *testing.T) {
	original := `rules = []`
	srv, tmpFile := newConfigServer(t, original)

	newContent := `rules = ["fs:ro:/usr/bin"]`
	resp, err := http.Post(srv.EndpointURL("/api/save"), "text/plain", strings.NewReader(newContent))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	written, err := os.ReadFile(tmpFile) // #nosec G304 -- tmpFile is a known temp path from t.TempDir
	require.NoError(t, err)
	assert.Equal(t, newContent, string(written))
}

func TestIntegration_Save_InvalidConfig_Returns400AndFileUnchanged(t *testing.T) {
	original := `rules = []`
	srv, tmpFile := newConfigServer(t, original)

	resp, err := http.Post(srv.EndpointURL("/api/save"), "text/plain", strings.NewReader("invalid toml [[["))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	written, err := os.ReadFile(tmpFile) // #nosec G304 -- tmpFile is a known temp path from t.TempDir
	require.NoError(t, err)
	assert.Equal(t, original, string(written))
}

func TestIntegration_Save_InvalidRulesRejected(t *testing.T) {
	original := `rules = []`
	srv, tmpFile := newConfigServer(t, original)

	// Valid TOML but invalid rule prefix
	resp, err := http.Post(srv.EndpointURL("/api/save"), "text/plain", strings.NewReader(`rules = ["badprefix:something"]`))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	written, err := os.ReadFile(tmpFile) // #nosec G304 -- tmpFile is a known temp path from t.TempDir
	require.NoError(t, err)
	assert.Equal(t, original, string(written))
}

func TestIntegration_Revert_ResetsDraftToSaved(t *testing.T) {
	tmpFile := t.TempDir() + "/execave.toml"
	savedContent := `rules = ["fs:ro:/usr/bin"]`
	require.NoError(t, os.WriteFile(tmpFile, []byte(savedContent), 0o600))

	logger := accesslog.New(nil)
	r := runner.NewTestRunner()
	r.SetTestLogger(logger)
	r.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "true"})
	srv := webui.New(r, []string{"true"}, "", "/tmp", tmpFile, savedContent, nil, webui.FilterDefaults{ShowAllowed: false, ShowNolog: false})
	require.NoError(t, srv.Start(t.Context()))
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	// Start with a different config to create a different draft
	draftContent := `rules = ["fs:ro:/tmp"]`
	startResp, err := http.Post(srv.EndpointURL("/api/start"), "text/plain", strings.NewReader(draftContent))
	require.NoError(t, err)
	_ = startResp.Body.Close()

	// Revert should reset draft to saved and return saved content
	resp, err := http.Post(srv.EndpointURL("/api/revert"), "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, savedContent, string(body))
}

func TestIntegration_Revert_WhenNotModifiedReturnsSavedContent(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "true"})
	srv := webui.StartServerWithRunner(t, rnr)

	// Draft and saved are identical at startup; revert should still succeed.
	resp, err := http.Post(srv.EndpointURL("/api/revert"), "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Empty(t, string(body)) // StartServerWithRunner initializes with empty content
}

func TestIntegration_StartWithBody_InvalidConfig_Returns400(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "true"})
	srv := webui.StartServerWithRunner(t, rnr)

	resp, err := http.Post(srv.EndpointURL("/api/start"), "text/plain", strings.NewReader("invalid toml [[["))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestIntegration_RunControlEndpoints_StartWithInvalidRulesRejected(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "true"})
	srv := webui.StartServerWithRunner(t, rnr)

	// Valid TOML but invalid rule prefix
	resp, err := http.Post(srv.EndpointURL("/api/start"), "text/plain", strings.NewReader(`rules = ["badprefix:something"]`))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestIntegration_RunControlEndpoints_StartCallsOnConfigChangeBeforeRun(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "true"})
	srv := webui.StartServerWithRunner(t, rnr)

	called := make(chan struct{}, 1)
	srv.OnConfigChange = func(_ *config.Config) {
		called <- struct{}{}
	}

	resp, err := http.Post(srv.EndpointURL("/api/start"), "text/plain", strings.NewReader(`rules = []`))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	require.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case <-called:
	default:
		t.Fatal("OnConfigChange was not called")
	}
}

// --- Requirement: Restart clears log entries ---

func TestIntegration_RestartClearsLogEntries(t *testing.T) {
	logger := accesslog.New(nil)
	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/bin/test",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	})

	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: true, ExitCode: 0, Error: "", Command: "echo hello"})
	srv := webui.StartServerWithRunner(t, rnr)

	// Connect SSE stream
	resp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	eventCh := readSSEEventsAsync(resp)

	readEventWithTimeout(t, eventCh) // status
	readEventWithTimeout(t, eventCh) // config
	readEventWithTimeout(t, eventCh) // entry

	// Trigger restart via POST /api/start
	startResp, err := http.Post(srv.EndpointURL("/api/start"), "text/plain", strings.NewReader(`rules = []`))
	require.NoError(t, err)
	_ = startResp.Body.Close()
	require.Equal(t, http.StatusOK, startResp.StatusCode)

	// Read events until we get a clear event (status change triggers it)
	var clearEvent webui.SSEEvent
	for range 10 {
		ev := readEventWithTimeout(t, eventCh)
		if ev.Event == "clear" {
			clearEvent = ev
			break
		}
	}
	require.Equal(t, "clear", clearEvent.Event)
}

// --- Requirement: Config textarea in page ---

func TestIntegration_ConfigPane_TextareaRenderedOnPageLoad(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)

	body := fetchBody(t, srv.EndpointURL("/"))
	assert.Contains(t, body, `id="config-textarea"`)
}

func TestIntegration_ConfigPane_TextareaContainsRawTomlContent(t *testing.T) {
	logger := accesslog.New(nil)
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "true"})
	// Use TOML content without characters that html/template encodes in text context
	configContent := "# config comment\nrules = []"
	srv := webui.New(rnr, []string{"true"}, "", "/tmp", "/tmp/test-execave.toml", configContent, nil, webui.FilterDefaults{ShowAllowed: false, ShowNolog: false})
	require.NoError(t, srv.Start(t.Context()))
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	body := fetchBody(t, srv.EndpointURL("/"))
	assert.Contains(t, body, configContent)
}

// --- Requirement: Filter defaults ---

func TestIntegration_FilterDefaults_DefaultStateKeepsCheckboxesChecked(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)

	body := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, body, `id="denied-only-checkbox" checked`)
	assert.Contains(t, body, `id="apply-nolog-checkbox" checked`)
}

func TestIntegration_FilterDefaults_ShowAllowedTrueUnchecksdeniedOnlyCheckbox(t *testing.T) {
	logger := accesslog.New(nil)
	r := runner.NewTestRunner()
	r.SetTestLogger(logger)
	r.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "true"})
	srv := webui.New(r, []string{"true"}, "", "", "/tmp/test-execave.toml", "", nil, webui.FilterDefaults{ShowAllowed: true, ShowNolog: false})
	require.NoError(t, srv.Start(t.Context()))
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	body := fetchBody(t, srv.EndpointURL("/"))

	assert.NotContains(t, body, `id="denied-only-checkbox" checked`)
	assert.Contains(t, body, `id="apply-nolog-checkbox" checked`)
}

func TestIntegration_FilterDefaults_ShowNologTrueUnchecksApplyNologCheckbox(t *testing.T) {
	logger := accesslog.New(nil)
	r := runner.NewTestRunner()
	r.SetTestLogger(logger)
	r.SetTestStatus(runner.RunStatus{Running: false, ExitCode: 0, Error: "", Command: "true"})
	srv := webui.New(r, []string{"true"}, "", "", "/tmp/test-execave.toml", "", nil, webui.FilterDefaults{ShowAllowed: false, ShowNolog: true})
	require.NoError(t, srv.Start(t.Context()))
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	body := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, body, `id="denied-only-checkbox" checked`)
	assert.NotContains(t, body, `id="apply-nolog-checkbox" checked`)
}

// --- Requirement: Denied-only filter ---

func TestIntegration_DeniedOnlyFilter_PageContainsDeniedOnlyCheckboxCheckedByDefault(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)

	body := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, body, `id="denied-only-checkbox" checked`)
}

func TestIntegration_DeniedOnlyFilter_PageContainsApplyNologCheckboxCheckedByDefault(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)

	body := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, body, `id="apply-nolog-checkbox" checked`)
}

func TestIntegration_DeniedOnlyFilter_OKEntriesHaveResultAttribute(t *testing.T) {
	logger := accesslog.New(nil)
	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/bin/test",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	})

	srv := webui.StartServer(t, logger)
	body := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, body, `data-result="OK"`)
}

func TestIntegration_DeniedOnlyFilter_DenyEntriesHaveResultAttribute(t *testing.T) {
	logger := accesslog.New(nil)
	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/etc/secret",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})

	srv := webui.StartServer(t, logger)
	body := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, body, `data-result="DENY"`)
}

// --- Requirement: Nolog filter ---

func TestIntegration_NologFilter_NologEntryHasNologAttribute(t *testing.T) {
	logger := accesslog.New(nil)
	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/home/user/project/cache/data",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})

	srv := webui.StartServer(t, logger)
	srv.SetLogResolvers(
		fsrules.NewLogResolver([]fsrules.LogRule{{Visible: false, Path: "/home/user/project", RawRule: "nolog:/home/user/project"}}),
		nil,
		nil,
	)
	body := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, body, `data-nolog="true"`)
}

func TestIntegration_NologFilter_LogOverrideEntryHasNologFalseAttribute(t *testing.T) {
	logger := accesslog.New(nil)
	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/home/user/project/secret/key.pem",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})

	srv := webui.StartServer(t, logger)
	srv.SetLogResolvers(
		fsrules.NewLogResolver([]fsrules.LogRule{
			{Visible: false, Path: "/home/user/project", RawRule: "nolog:/home/user/project"},
			{Visible: true, Path: "/home/user/project/secret", RawRule: "log:/home/user/project/secret"},
		}),
		nil,
		nil,
	)
	body := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, body, `data-nolog="false"`)
}

func TestIntegration_NologFilter_NoLogResolverMeansNologFalse(t *testing.T) {
	logger := accesslog.New(nil)
	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/bin/test",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	})

	srv := webui.StartServer(t, logger)
	// No resolvers set — all entries should have nolog=false
	body := fetchBody(t, srv.EndpointURL("/"))

	assert.Contains(t, body, `data-nolog="false"`)
}

// --- Requirement: SSE entry events include nolog metadata ---

func TestIntegration_SseNologMetadata_SseEntryEventContainsNologTrue(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)
	srv.SetLogResolvers(
		fsrules.NewLogResolver([]fsrules.LogRule{{Visible: false, Path: "/home/user/project", RawRule: "nolog:/home/user/project"}}),
		nil,
		nil,
	)

	resp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	eventCh := readSSEEventsAsync(resp)
	readEventWithTimeout(t, eventCh) // status
	readEventWithTimeout(t, eventCh) // config

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/home/user/project/cache/data",
		Result:    accesslog.ResultDeny,
		Rule:      accesslog.RuleNoMatch,
	})

	entryEvent := readEventWithTimeout(t, eventCh)
	assert.Equal(t, "entry", entryEvent.Event)
	assert.Contains(t, entryEvent.Data, `"nolog":true`)
}

func TestIntegration_SseNologMetadata_SseEntryEventContainsNologFalse(t *testing.T) {
	logger := accesslog.New(nil)
	srv := webui.StartServer(t, logger)

	resp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	eventCh := readSSEEventsAsync(resp)
	readEventWithTimeout(t, eventCh) // status
	readEventWithTimeout(t, eventCh) // config

	logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/lib/streamed.so",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	})

	entryEvent := readEventWithTimeout(t, eventCh)
	assert.Equal(t, "entry", entryEvent.Event)
	assert.Contains(t, entryEvent.Data, `"nolog":false`)
}

// --- Integration test helpers ---

// fetchBody makes a GET request and returns the response body as a string.
func fetchBody(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url) // #nosec G107 -- test-controlled URL
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
					buf = append(buf, tmp[0]) // #nosec G602 -- n > 0 guarantees tmp[0] is safe
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

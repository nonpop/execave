package webui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/accesslog"
	"github.com/nonpop/execave/internal/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRunnerWithLogger creates a runner for testing with a pre-populated logger.
func newTestRunnerWithLogger(logger *accesslog.Logger) *runner.Runner {
	rnr := runner.NewTestRunner()
	rnr.SetTestLogger(logger)
	rnr.SetTestStatus(runner.RunStatus{
		Running:  true,
		ExitCode: 0,
		Error:    "",
		Command:  "echo hello",
	})
	return rnr
}

// --- shortenPath unit tests ---

func TestShortenPath_PathUnderConfigDirShortenedToRelative(t *testing.T) {
	result := shortenPath("/home/user/project/src/main.go", "/home/user", "/home/user/project")
	assert.Equal(t, "src/main.go", result)
}

func TestShortenPath_PathUnderHomeDirButOutsideConfigDirShortenedToTilde(t *testing.T) {
	result := shortenPath("/home/user/.ssh/id_rsa", "/home/user", "/home/user/project")
	assert.Equal(t, "~/.ssh/id_rsa", result)
}

func TestShortenPath_PathUnderBothConfigDirTakesPriority(t *testing.T) {
	result := shortenPath("/home/user/project/src/main.go", "/home/user", "/home/user/project")
	assert.Equal(t, "src/main.go", result)
}

func TestShortenPath_PathOutsideHomeDirShownAsAbsolute(t *testing.T) {
	result := shortenPath("/usr/lib/libc.so", "/home/user", "/home/user/project")
	assert.Equal(t, "/usr/lib/libc.so", result)
}

func TestShortenPath_PathEqualToConfigDirShortenedToDot(t *testing.T) {
	result := shortenPath("/home/user/project", "/home/user", "/home/user/project")
	assert.Equal(t, ".", result)
}

func TestShortenPath_EmptyHomeDirDisablesTildeShortening(t *testing.T) {
	result := shortenPath("/home/user/.ssh/id_rsa", "", "/home/user/project")
	assert.Equal(t, "/home/user/.ssh/id_rsa", result)
}

func TestShortenPath_PathEqualToHomeDir(t *testing.T) {
	result := shortenPath("/home/user", "/home/user", "/home/user/project")
	assert.Equal(t, "~", result)
}

func TestShortenPath_EmptyConfigDirUsesAbsoluteOrTilde(t *testing.T) {
	result := shortenPath("/home/user/project/src/main.go", "/home/user", "")
	assert.Equal(t, "~/project/src/main.go", result)
}

func TestShortenPath_BothEmptyReturnsAbsolute(t *testing.T) {
	result := shortenPath("/home/user/project/src/main.go", "", "")
	assert.Equal(t, "/home/user/project/src/main.go", result)
}

// --- Token authentication unit tests ---

func TestToken_MissingToken_Returns403(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger)

	// Request without token
	resp, err := http.Get("http://" + srv.addr + "/")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestToken_WrongToken_Returns403(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger)

	resp, err := http.Get("http://" + srv.addr + "/?token=wrongtoken")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestToken_ValidToken_Succeeds(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger)

	resp, err := http.Get(srv.EndpointURL("/"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestToken_RequiredOnAllEndpoints(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger)
	base := "http://" + srv.addr

	endpoints := []string{"/", "/events", "/api/start", "/api/stop", "/api/save", "/api/revert"}
	for _, path := range endpoints {
		resp, err := http.Get(base + path)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

// --- SSE integration tests ---

func TestSSE_EntryEventIDFormat(t *testing.T) {
	logger := accesslog.New(nil)
	require.NoError(t, logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/bin/test",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	}))

	srv := StartServer(t, logger)

	resp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// status + config + 1 entry
	events := ReadSSEEvents(t, resp, 3)
	require.GreaterOrEqual(t, len(events), 3)

	entryEvent := events[2]
	assert.Equal(t, "entry", entryEvent.Event)
	assert.Equal(t, "0", entryEvent.ID)
}

func TestSSE_ReconnectResumesFromLastEventID(t *testing.T) {
	logger := accesslog.New(nil)
	for i := range 3 {
		require.NoError(t, logger.Log(accesslog.Entry{
			Operation: accesslog.OperationRead,
			Target:    "/usr/bin/test" + strings.Repeat("x", i),
			Result:    accesslog.ResultOK,
			Rule:      "fs:ro:/usr",
		}))
	}

	srv := StartServer(t, logger)

	// Reconnect with Last-Event-ID at index 1
	req, err := http.NewRequest(http.MethodGet, srv.EndpointURL("/events"), nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", "1")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// Should get: status + config + entry at index 2 only
	events := ReadSSEEvents(t, resp, 3)
	require.GreaterOrEqual(t, len(events), 3)
	assert.Equal(t, "status", events[0].Event)
	assert.Equal(t, "config", events[1].Event)
	assert.Equal(t, "entry", events[2].Event)
	assert.Equal(t, "2", events[2].ID)
}

func TestSSE_StaleReconnectSendsClearAndReplaysFromStart(t *testing.T) {
	logger := accesslog.New(nil)
	for i := range 2 {
		require.NoError(t, logger.Log(accesslog.Entry{
			Operation: accesslog.OperationRead,
			Target:    "/usr/bin/test" + strings.Repeat("x", i),
			Result:    accesslog.ResultOK,
			Rule:      "fs:ro:/usr",
		}))
	}

	srv := StartServer(t, logger)

	// Reconnect with stale Last-Event-ID (beyond current entry count)
	req, err := http.NewRequest(http.MethodGet, srv.EndpointURL("/events"), nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", "50")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// clear + status + config + 2 entries
	events := ReadSSEEvents(t, resp, 5)
	require.GreaterOrEqual(t, len(events), 5)
	assert.Equal(t, "clear", events[0].Event)
	assert.Equal(t, "status", events[1].Event)
	assert.Equal(t, "config", events[2].Event)
	assert.Equal(t, "entry", events[3].Event)
	assert.Equal(t, "0", events[3].ID)
	assert.Equal(t, "entry", events[4].Event)
	assert.Equal(t, "1", events[4].ID)
}

func TestSSE_MalformedLastEventID_ReplaysFromStart(t *testing.T) {
	logger := accesslog.New(nil)
	require.NoError(t, logger.Log(accesslog.Entry{
		Operation: accesslog.OperationRead,
		Target:    "/usr/bin/test",
		Result:    accesslog.ResultOK,
		Rule:      "fs:ro:/usr",
	}))

	srv := StartServer(t, logger)

	// Reconnect with non-numeric Last-Event-ID
	req, err := http.NewRequest(http.MethodGet, srv.EndpointURL("/events"), nil)
	require.NoError(t, err)
	req.Header.Set("Last-Event-ID", "abc")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// Malformed → replay from 0: status + config + 1 entry
	events := ReadSSEEvents(t, resp, 3)
	require.GreaterOrEqual(t, len(events), 3)
	assert.Equal(t, "status", events[0].Event)
	assert.Equal(t, "config", events[1].Event)
	assert.Equal(t, "entry", events[2].Event)
	assert.Equal(t, "0", events[2].ID)
}

func TestIndex_CommandInHTML(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger)

	resp, err := http.Get(srv.EndpointURL("/"))
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
	srv := StartServer(t, logger)

	resp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	events := ReadSSEEvents(t, resp, 1)
	require.GreaterOrEqual(t, len(events), 1)
	assert.Equal(t, "status", events[0].Event)
	assert.Contains(t, events[0].Data, `"command":"echo hello"`)
}

func TestSSE_ConfigEventSentOnConnect(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger)

	resp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// status + config
	events := ReadSSEEvents(t, resp, 2)
	require.Len(t, events, 2)
	assert.Equal(t, "status", events[0].Event)
	assert.Equal(t, "config", events[1].Event)
}

func TestSSE_ConfigEventContainsDraftAndSavedFields(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger)

	// Set a non-empty config content
	srv.savedContent = `rules = ["fs:ro:/usr/bin"]`
	srv.draftContent = srv.savedContent

	resp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	// status + config
	events := ReadSSEEvents(t, resp, 2)
	require.Len(t, events, 2)

	configEvent := events[1]
	assert.Equal(t, "config", configEvent.Event)

	var payload struct {
		Draft string `json:"draft"`
		Saved string `json:"saved"`
	}
	require.NoError(t, json.Unmarshal([]byte(configEvent.Data), &payload))
	assert.Equal(t, `rules = ["fs:ro:/usr/bin"]`, payload.Draft)
	assert.Equal(t, `rules = ["fs:ro:/usr/bin"]`, payload.Saved)
}

func TestSSE_ConfigEventDraftDiffersFromSavedAfterStartWithEditedConfig(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger)

	savedTOML := `rules = ["fs:ro:/usr/bin"]`
	srv.savedContent = savedTOML
	srv.draftContent = savedTOML

	// Simulate handleStart updating draftContent (with invalid TOML to avoid runner.Start)
	editedTOML := `rules = ["fs:ro:/tmp"]`
	srv.mu.Lock()
	srv.draftContent = editedTOML
	srv.mu.Unlock()

	resp, err := http.Get(srv.EndpointURL("/events"))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // SSE stream; best-effort close

	events := ReadSSEEvents(t, resp, 2)
	require.Len(t, events, 2)

	configEvent := events[1]
	assert.Equal(t, "config", configEvent.Event)

	var payload struct {
		Draft string `json:"draft"`
		Saved string `json:"saved"`
	}
	require.NoError(t, json.Unmarshal([]byte(configEvent.Data), &payload))
	assert.Equal(t, editedTOML, payload.Draft)
	assert.Equal(t, savedTOML, payload.Saved)
}

// --- handleStart/handleSave/handleRevert unit tests ---

func TestHandleStart_ValidBody_Returns200(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger)

	// Valid TOML with an absolute configPath for ParseTOML
	body := `rules = ["fs:ro:/usr/bin"]`
	resp, err := http.Post(srv.EndpointURL("/api/start"), "text/plain", strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandleStart_InvalidBody_Returns400(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger)

	body := "invalid toml [[["
	resp, err := http.Post(srv.EndpointURL("/api/start"), "text/plain", strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleStart_InvalidBody_UpdatesDraft(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger)

	body := "invalid toml [[["
	resp, err := http.Post(srv.EndpointURL("/api/start"), "text/plain", strings.NewReader(body))
	require.NoError(t, err)
	_ = resp.Body.Close()

	// Draft is updated even on invalid TOML
	srv.mu.Lock()
	draft := srv.draftContent
	srv.mu.Unlock()
	assert.Equal(t, body, draft)
}

func TestHandleSave_ValidBody_WritesFile(t *testing.T) {
	tmpFile := t.TempDir() + "/execave.toml"
	require.NoError(t, os.WriteFile(tmpFile, []byte(`rules = []`), 0o600))

	logger := accesslog.New(nil)
	r := newTestRunnerWithLogger(logger)
	srv := New(r, []string{"true"}, "", "/tmp", tmpFile, `rules = []`, nil)
	require.NoError(t, srv.Start(t.Context()))
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	newContent := `rules = ["fs:ro:/usr/bin"]`
	resp, err := http.Post(srv.EndpointURL("/api/save"), "text/plain", strings.NewReader(newContent))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	written, err := os.ReadFile(tmpFile) // #nosec G304 -- tmpFile is a known temp path from t.TempDir
	require.NoError(t, err)
	assert.Equal(t, newContent, string(written))
}

func TestHandleSave_InvalidBody_Returns400AndFileUnchanged(t *testing.T) {
	tmpFile := t.TempDir() + "/execave.toml"
	original := `rules = []`
	require.NoError(t, os.WriteFile(tmpFile, []byte(original), 0o600))

	logger := accesslog.New(nil)
	r := newTestRunnerWithLogger(logger)
	srv := New(r, []string{"true"}, "", "/tmp", tmpFile, original, nil)
	require.NoError(t, srv.Start(t.Context()))
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })

	body := "invalid toml [[["
	resp, err := http.Post(srv.EndpointURL("/api/save"), "text/plain", strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// File must be unchanged
	written, err := os.ReadFile(tmpFile) // #nosec G304 -- tmpFile is a known temp path from t.TempDir
	require.NoError(t, err)
	assert.Equal(t, original, string(written))
}

func TestHandleRevert_ReturnsSavedContent(t *testing.T) {
	logger := accesslog.New(nil)
	srv := StartServer(t, logger)

	savedTOML := `rules = ["fs:ro:/usr/bin"]`
	srv.savedContent = savedTOML
	srv.draftContent = `rules = ["fs:ro:/tmp"]` // different draft

	resp, err := http.Post(srv.EndpointURL("/api/revert"), "text/plain", nil)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck // best-effort close in test
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := readAll(resp)
	require.NoError(t, err)
	assert.Equal(t, savedTOML, body)

	// Draft is updated to saved
	srv.mu.Lock()
	draft := srv.draftContent
	srv.mu.Unlock()
	assert.Equal(t, savedTOML, draft)
}

// readAll reads the response body as a string.
func readAll(resp *http.Response) (string, error) {
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}
	return string(b), nil
}

// --- helpers ---

// StartServer creates and starts a Server on an OS-assigned port, returning it.
// Use srv.EndpointURL(path) to construct URLs with the access token.
// If logger is nil, the runner will have no logger (nil Logger() return value).
// Path shortening is disabled (empty homeDir and configDir).
func StartServer(t *testing.T, logger *accesslog.Logger) *Server {
	t.Helper()
	return StartServerWithPaths(t, logger, "", "")
}

// StartServerWithPaths creates and starts a Server with the given homeDir and configDir
// for path shortening.
func StartServerWithPaths(t *testing.T, logger *accesslog.Logger, homeDir, configDir string) *Server {
	t.Helper()
	r := newTestRunnerWithLogger(logger)
	command := []string{"true"}
	srv := New(r, command, homeDir, configDir, "/tmp/test-execave.toml", "", nil)
	require.NoError(t, srv.Start(t.Context()))
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })
	return srv
}

// StartServerWithRunner creates and starts a Server with the given runner.
// Use this when you need a runner in a specific state.
// Path shortening is disabled (empty homeDir and configDir).
func StartServerWithRunner(t *testing.T, r *runner.Runner) *Server {
	t.Helper()
	srv := New(r, []string{"true"}, "", "", "/tmp/test-execave.toml", "", nil)
	require.NoError(t, srv.Start(t.Context()))
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })
	return srv
}

// SSEEvent represents a parsed Server-Sent Event for test assertions.
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

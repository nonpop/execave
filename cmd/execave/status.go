package main

import (
	"strings"
	"sync"

	"github.com/nonpop/execave/internal/webui"
)

// statusTracker tracks sandbox process lifecycle state and notifies subscribers on changes.
// statusTracker is safe for concurrent use by multiple goroutines.
//
// Producers (CLI orchestrator) call SetRunning/SetExited.
// Consumers (webui.Server via webui.StatusProvider) call Status and Subscribe.
type statusTracker struct {
	mu          sync.Mutex
	command     string
	status      webui.RunStatus
	subscribers map[chan struct{}]bool
}

// newStatusTracker creates a new statusTracker with initial state set to not running.
// command is the sandboxed command being tracked.
func newStatusTracker(command []string) *statusTracker {
	return &statusTracker{
		mu:      sync.Mutex{},
		command: strings.Join(command, " "),
		status: webui.RunStatus{
			Running:  false,
			ExitCode: 0,
			Error:    "",
			Command:  "",
		},
		subscribers: make(map[chan struct{}]bool),
	}
}

// SetRunning marks the sandboxed process as running.
func (t *statusTracker) SetRunning() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.status = webui.RunStatus{
		Running:  true,
		ExitCode: 0,
		Error:    "",
		Command:  t.command,
	}
	t.notifySubscribers()
}

// SetExited marks the sandboxed process as exited with the given exit code and optional error.
func (t *statusTracker) SetExited(exitCode int, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	t.status = webui.RunStatus{
		Running:  false,
		ExitCode: exitCode,
		Error:    errMsg,
		Command:  t.command,
	}
	t.notifySubscribers()
}

// Status returns a copy of the current run status.
func (t *statusTracker) Status() webui.RunStatus {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.status
}

// Subscribe registers a channel to receive notifications when the run status changes.
// The channel receives a non-blocking signal on each status change.
// Callers should use Status() to retrieve the current status snapshot.
// The returned channel should only be used for receiving.
func (t *statusTracker) Subscribe() chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()

	ch := make(chan struct{}, 1)
	t.subscribers[ch] = true
	return ch
}

// Unsubscribe removes a previously registered subscriber channel.
func (t *statusTracker) Unsubscribe(ch chan struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.subscribers, ch)
}

// notifySubscribers sends a non-blocking notification to all subscribers.
// Must be called with t.mu held.
func (t *statusTracker) notifySubscribers() {
	for ch := range t.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

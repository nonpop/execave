# Runner Capability

## Purpose

The runner manages the lifecycle of monitored sandbox executions — starting, stopping, tracking status, and providing the current access log. It enables programmatic run control from the web UI.

## Requirements

### Requirement: Start a monitored run

Start SHALL create a fresh `accesslog.Logger`, build a sandbox+monitor from the provided config and command, and execute the run in a background goroutine. Start SHALL return after the goroutine is launched. The runner's status SHALL transition to running.

#### Scenario: Start launches a monitored run
- **WHEN** Start is called with a config and command
- **THEN** Status returns Running=true
- **AND** Logger returns a non-nil logger with zero entries

### Requirement: Stop an active run

Stop SHALL cancel the active run's context and wait for the run goroutine to exit. If no run is active, Stop SHALL be a no-op.

#### Scenario: Stop terminates a running process
- **WHEN** a run is active
- **AND** Stop is called
- **THEN** the run is terminated
- **AND** Status returns Running=false

#### Scenario: Stop is no-op when idle
- **WHEN** no run is active
- **AND** Stop is called
- **THEN** no error occurs
- **AND** Status remains unchanged

### Requirement: Start stops any active run first

If a run is active when Start is called, Start SHALL stop the active run and wait for it to exit before starting the new one.

#### Scenario: Start while running stops the previous run
- **WHEN** a run is active
- **AND** Start is called with a new command
- **THEN** the previous run is terminated
- **AND** a new run starts with a fresh access log
- **AND** Status returns Running=true

### Requirement: Fresh access log per run

Each Start SHALL create a new `accesslog.Logger`. The previous logger SHALL no longer receive entries. Logger() SHALL return the current run's logger. If OnLoggerChange is set, Start SHALL call it with the new logger before launching the run goroutine. This enables external components sharing the logger (e.g., network proxy) to switch to the current run's logger.

#### Scenario: Logger is replaced on start
- **WHEN** a run has completed with logged entries
- **AND** Start is called again
- **THEN** Logger returns a new logger with zero entries
- **AND** the previous logger's entries are no longer accessible via Logger()

#### Scenario: Logger change callback invoked on start
- **WHEN** OnLoggerChange is set
- **AND** Start is called
- **THEN** the callback is invoked with the new logger

### Requirement: Status tracking

The runner SHALL track run status with transitions: idle → running → exited. Status() SHALL return the current status including Running flag, exit code, error message, and command. Subscribers SHALL be notified on every status change via non-blocking channel send.

#### Scenario: Status reflects running state
- **WHEN** Start is called
- **THEN** Status returns Running=true and the command string

#### Scenario: Status reflects exit state
- **WHEN** a run completes with exit code 0
- **THEN** Status returns Running=false and ExitCode=0

#### Scenario: Status reflects non-zero exit
- **WHEN** a run completes with exit code 1
- **THEN** Status returns Running=false and ExitCode=1

#### Scenario: Subscribers notified on status change
- **WHEN** a subscriber is registered
- **AND** the run status changes
- **THEN** the subscriber channel receives a notification

### Requirement: Thread safety

All Runner methods SHALL be safe for concurrent use by multiple goroutines.

#### Scenario: Concurrent status reads during run
- **WHEN** a run is active
- **AND** Status is called concurrently from multiple goroutines
- **THEN** all calls return consistent snapshots without data races

### Requirement: Terminal state restoration

Start SHALL restore the terminal to its initial state before launching a new run. This ensures each run starts with a clean terminal, even if the previous run was killed and left the terminal in a bad state (e.g., echo disabled, raw mode enabled).

#### Scenario: Terminal restored after killed process
- **WHEN** a run leaves the terminal in a bad state (no echo)
- **AND** Start is called to begin a new run
- **THEN** the terminal is restored to normal state
- **AND** the new run has working terminal echo

### Requirement: Stdin buffer clearing

Start SHALL discard any buffered input from stdin before launching a new run. This prevents input typed while no process is running from being sent to the next process.

#### Scenario: Buffered input discarded on restart
- **WHEN** a user types input while no process is running
- **AND** Start is called to begin a new run
- **THEN** the buffered input is discarded
- **AND** the new process starts with empty input buffer

### Requirement: Foreground process group reclaim

When a run exits, the runner SHALL reclaim the terminal's foreground process group. Without `--new-session` (Linux 6.2+), the sandboxed process can take over the foreground group via `tcsetpgrp()`. When killed, execave is left as a background group, preventing Ctrl-C delivery and stopping terminal ioctls with SIGTTOU.

#### Scenario: Foreground reclaimed after killed process
- **WHEN** a sandboxed process has taken over the foreground process group
- **AND** the process is killed
- **THEN** execave reclaims the foreground process group
- **AND** Ctrl-C delivers SIGINT to execave

### Requirement: TUI cleanup

When a run exits, the runner SHALL clear any TUI artifacts left by the process. This includes exiting alternate screen buffer, clearing the screen, resetting cursor position and visibility, disabling focus reporting, disabling mouse tracking modes, and resetting terminal modes.

#### Scenario: TUI artifacts cleared on exit
- **WHEN** a TUI application exits or is stopped
- **THEN** the alternate screen buffer is exited
- **AND** the screen is cleared
- **AND** the cursor is visible and at home position
- **AND** focus reporting is disabled
- **AND** mouse tracking modes are disabled
- **AND** terminal modes are reset to defaults

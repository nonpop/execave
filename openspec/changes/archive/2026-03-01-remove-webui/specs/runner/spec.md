## MODIFIED Requirements

### Requirement: Start a monitored run

The runner SHALL start a monitored sandbox execution when `Start(ctx, cfg, command)` is called. It SHALL create a fresh `accesslog.Logger`, configure the sandbox with the given config, and launch the sandbox+monitor process. The runner SHALL track the running state and notify subscribers of status changes. If a run is already active, Start SHALL stop the existing run before starting the new one with a fresh access log.

#### Scenario: Start creates fresh logger and launches sandbox

- **WHEN** `Start(ctx, cfg, command)` is called with valid config and command
- **THEN** a new `accesslog.Logger` is created
- **AND** `OnLoggerChange` is called with the new logger (if set)
- **AND** the sandbox+monitor process is launched
- **AND** `Status().Running` is true

#### Scenario: Start replaces active run

- **WHEN** `Start` is called while a run is active
- **THEN** the active run is stopped first
- **AND** a new run starts with a fresh access log

#### Scenario: Start with invalid config

- **WHEN** `Start` is called with invalid config
- **THEN** an error is returned
- **AND** no run is started

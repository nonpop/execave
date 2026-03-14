## ADDED Requirements

### Requirement: Mutable syscall filtering toggle

The runner SHALL have a mutable `allowAllSyscalls` field initialized from the constructor parameter. `SetAllowAllSyscalls(bool)` SHALL update this field (thread-safe). When `Start()` is called, the current value SHALL determine whether the seccomp filter is created and passed to the monitor.

#### Scenario: Seccomp enabled by default
- **WHEN** Runner is created with `allowAllSyscalls=false`
- **AND** `Start()` is called
- **THEN** the monitor receives a seccomp filter pipe

#### Scenario: Seccomp disabled via setter
- **WHEN** Runner is created with `allowAllSyscalls=false`
- **AND** `SetAllowAllSyscalls(true)` is called
- **AND** `Start()` is called
- **THEN** the monitor receives a nil seccomp file

#### Scenario: Toggle between runs
- **WHEN** a run completes with seccomp enabled
- **AND** `SetAllowAllSyscalls(true)` is called
- **AND** `Start()` is called again
- **THEN** the new run has no seccomp filter

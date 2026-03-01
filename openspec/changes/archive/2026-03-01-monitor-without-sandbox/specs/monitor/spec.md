## ADDED Requirements

### Requirement: Extra environment variable injection

When `extraEnv` is non-nil, the monitor SHALL set the strace-traced child process's environment to the current process's environment (`os.Environ()`) extended with the entries in `extraEnv`. This allows the caller to inject variables such as `HTTP_PROXY` into the traced command's environment without affecting the monitor process itself.

#### Scenario: Extra env vars injected into traced command

- **WHEN** the monitor is constructed with `extraEnv` containing `HTTP_PROXY=http://127.0.0.1:12345`
- **AND** Run is called
- **THEN** the strace-traced command receives `HTTP_PROXY=http://127.0.0.1:12345` in its environment

#### Scenario: Nil extraEnv inherits parent environment unchanged

- **WHEN** the monitor is constructed with `extraEnv=nil`
- **AND** Run is called
- **THEN** the strace-traced command inherits the parent process's environment unchanged

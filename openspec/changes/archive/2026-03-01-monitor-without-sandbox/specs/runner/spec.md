## ADDED Requirements

### Requirement: Unsandboxed run mode

When constructed with `noSandbox=true`, the runner SHALL skip bwrap invocation, seccomp filter creation, and network namespace setup. Instead, the runner SHALL create an `accesslog.Logger` with `unenforced=true` and start the monitor with empty bwrap args so strace traces the command directly on the host filesystem. Using `unenforced=true` ensures all log entries — including network entries logged by the proxy — carry result `UNENFORCED`.

When `noSandbox=true` and a network path is configured (proxy is running), the runner SHALL start a host-side TCP-to-UDS bridge and inject `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, and `https_proxy` environment variables into the traced command's environment, pointing to the bridge's TCP address. The bridge SHALL be stopped after the monitored run completes.

#### Scenario: Unsandboxed run traces command directly

- **WHEN** the runner is constructed with `noSandbox=true`
- **AND** Start is called with a config and command
- **THEN** the command is executed directly under strace (no bwrap)
- **AND** the command has full access to the host filesystem

#### Scenario: Unsandboxed run injects HTTP_PROXY when proxy is configured

- **WHEN** the runner is constructed with `noSandbox=true`
- **AND** a network path (proxy UDS) is configured
- **AND** Start is called
- **THEN** a TCP-to-UDS bridge is started on the host
- **AND** the traced command receives HTTP_PROXY and HTTPS_PROXY pointing to the bridge's TCP address

#### Scenario: Unsandboxed run produces UNENFORCED log entries

- **WHEN** the runner is constructed with `noSandbox=true`
- **AND** Start is called with a config and command
- **THEN** all access log entries have result `UNENFORCED`
- **AND** no entries have result `OK` or `DENY`



- **WHEN** the runner is constructed with `noSandbox=true`
- **AND** the config includes syscall rules
- **AND** Start is called
- **THEN** no seccomp filter is created or applied
- **AND** the traced command can execute any syscall

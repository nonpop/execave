# Tunnel Capability

## Purpose

The tunnel capability provides a TCP-to-UDS bridge that runs inside the sandboxed environment. It listens on a local TCP port, sets HTTP proxy environment variables, runs the user command as a subprocess, and relays proxy-aware network traffic to the host-side proxy via the UDS.

## Requirements

### Requirement: TCP-to-UDS bridge

The tunnel SHALL listen on `127.0.0.1:0` (ephemeral port) inside the sandbox and bridge each TCP connection to the proxy's UDS. For each accepted TCP connection, the tunnel SHALL dial the UDS and relay data bidirectionally until either side closes.

#### Scenario: TCP connection bridged to UDS
- **WHEN** tunnel is running inside the sandbox
- **AND** a sandboxed process connects to the tunnel's TCP listener
- **THEN** tunnel dials the UDS
- **AND** relays data bidirectionally between the TCP connection and the UDS

#### Scenario: UDS unavailable
- **WHEN** tunnel attempts to dial the UDS
- **AND** the UDS is not available (proxy stopped or crashed)
- **THEN** tunnel closes the TCP connection with an error

### Requirement: Proxy environment variables

The tunnel SHALL set `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, and `https_proxy` environment variables to `http://127.0.0.1:<port>` (where `<port>` is the ephemeral port) before running the user command. The tunnel SHALL unset `NO_PROXY` and `no_proxy` to prevent proxy bypass.

#### Scenario: Proxy env vars set
- **WHEN** tunnel starts and listens on port 12345
- **THEN** user command runs with `HTTP_PROXY=http://127.0.0.1:12345`
- **AND** `HTTPS_PROXY=http://127.0.0.1:12345`
- **AND** `http_proxy=http://127.0.0.1:12345`
- **AND** `https_proxy=http://127.0.0.1:12345`

#### Scenario: No-proxy vars unset
- **WHEN** tunnel starts
- **AND** the inherited environment contains `NO_PROXY=*`
- **THEN** `NO_PROXY` and `no_proxy` are unset before running the user command

### Requirement: User command execution

The tunnel SHALL run the user command as a subprocess after setting up the TCP listener and environment variables. The tunnel SHALL propagate the user command's exit code as its own exit code.

#### Scenario: User command exit code propagated
- **WHEN** tunnel runs user command `sh -c 'exit 42'`
- **THEN** tunnel exits with code 42

#### Scenario: User command runs with proxy env
- **WHEN** tunnel runs user command `env`
- **THEN** command output includes `HTTP_PROXY=http://127.0.0.1:<port>`

### Requirement: Tunnel failure is fail-closed

If the tunnel fails to start (cannot bind to loopback, cannot access UDS), the user command SHALL NOT run. The tunnel SHALL exit with a non-zero exit code.

#### Scenario: Tunnel bind failure
- **WHEN** tunnel cannot bind to `127.0.0.1:0`
- **THEN** tunnel exits with non-zero exit code
- **AND** user command does not run

#### Scenario: Tunnel UDS inaccessible
- **WHEN** the UDS path does not exist
- **AND** a sandboxed process attempts to connect through the tunnel
- **THEN** the connection fails

### Requirement: Connection draining on exit

When the user command exits, the tunnel SHALL wait for in-flight relay goroutines to complete before exiting, ensuring data in transit is not lost.

#### Scenario: In-flight data drained
- **WHEN** user command exits
- **AND** there are active relay connections
- **THEN** tunnel waits for relays to complete before exiting

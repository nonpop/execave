# Tunnel Capability

## Purpose

The tunnel capability provides a TCP-to-UDS bridge. It listens on a local TCP port, sets HTTP proxy environment variables, runs the user command as a subprocess, and relays proxy-aware network traffic to the host-side proxy via the UDS.

## Requirements

### Requirement: TCP-to-UDS bridge

The tunnel SHALL listen on `127.0.0.1:0` (ephemeral port) and bridge each accepted TCP connection to the proxy's UDS, relaying data bidirectionally until either side closes.

#### Scenario: TCP connection bridged to UDS
- **GIVEN** an HTTP server is listening on the UDS
- **WHEN** `tunnel.Run` executes a command that sends an HTTP request via `$HTTP_PROXY`
- **THEN** the command receives the response from the UDS server

#### Scenario: UDS unavailable
- **GIVEN** the UDS path does not exist
- **WHEN** `tunnel.Run` executes a command that attempts an HTTP request via `$HTTP_PROXY`
- **THEN** the request fails

### Requirement: Proxy environment variables

The tunnel SHALL set `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, and `https_proxy` to `http://127.0.0.1:<port>` (where `<port>` is the ephemeral port) before running the user command. The tunnel SHALL unset `NO_PROXY` and `no_proxy` to prevent proxy bypass.

#### Scenario: Proxy env vars set
- **WHEN** `tunnel.Run` executes a command
- **THEN** `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, and `https_proxy` are all non-empty in the command's environment

#### Scenario: No-proxy vars unset
- **GIVEN** the inherited environment contains `NO_PROXY=*` and `no_proxy=*`
- **WHEN** `tunnel.Run` executes a command
- **THEN** `NO_PROXY` and `no_proxy` are unset in the command's environment

### Requirement: User command execution

The tunnel SHALL run the user command as a subprocess after setting up the TCP listener and environment variables. The tunnel SHALL propagate the user command's exit code via its return value.

#### Scenario: User command exit code propagated
- **WHEN** `tunnel.Run` executes `sh -c 'exit 42'`
- **THEN** `tunnel.Run` returns exit code 42

#### Scenario: User command runs with proxy env
- **WHEN** `tunnel.Run` executes a command that inspects `$HTTP_PROXY`
- **THEN** `HTTP_PROXY` matches the pattern `http://127.0.0.1:<port>`

### Requirement: Tunnel failure is fail-closed

When the UDS is inaccessible, connections through the tunnel SHALL fail rather than bypass the proxy.

#### Scenario: Tunnel UDS inaccessible
- **GIVEN** the UDS path does not exist
- **WHEN** `tunnel.Run` executes a command that attempts an HTTP request via `$HTTP_PROXY`
- **THEN** the request fails

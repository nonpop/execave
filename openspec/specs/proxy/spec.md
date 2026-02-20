# Proxy Capability

## Purpose

The proxy capability provides a forward HTTP/HTTPS proxy that enforces network access controls for sandboxed processes. It listens on a Unix domain socket (UDS), handles CONNECT requests for HTTPS tunneling and plain HTTP requests, validates each request against the network rules allowlist, and integrates with the access log to record network operations.

## Requirements

### Requirement: Proxy listens on UDS

The proxy SHALL listen on a Unix domain socket (UDS). The proxy SHALL NOT listen on any TCP port or network interface.

#### Scenario: Proxy accepts connection on UDS
- **WHEN** proxy is started with a UDS path
- **AND** a client connects to the UDS
- **THEN** the connection succeeds

#### Scenario: Proxy does not listen on TCP
- **WHEN** proxy is started
- **THEN** the proxy's listener address is on the `unix` network

### Requirement: CONNECT handling for HTTPS

The proxy SHALL handle HTTP CONNECT requests for HTTPS tunneling. When a CONNECT request arrives, the proxy extracts the `host:port`, checks it against the allowlist, and either tunnels the connection (if allowed) or responds with `403 Forbidden` (if denied).

#### Scenario: Allowed CONNECT request tunneled
- **WHEN** a local TLS test server is running
- **AND** the allowlist permits the server's `host:port`
- **AND** an HTTPS GET is made through the proxy to the server
- **THEN** the client receives HTTP 200 with the server's response body

#### Scenario: Denied CONNECT request rejected
- **WHEN** the allowlist does not permit `evil.example.com:443`
- **AND** proxy receives a CONNECT request for `evil.example.com:443`
- **THEN** proxy responds with `403`

#### Scenario: CONNECT tunnel closes when target disconnects
- **WHEN** a local TLS test server sends a response and closes
- **AND** an HTTPS GET is made through the proxy to the server
- **THEN** the client receives the complete response body without error

### Requirement: Plain HTTP forwarding

The proxy SHALL handle plain HTTP requests (non-CONNECT). When a plain HTTP request arrives, the proxy extracts the `host:port` (defaulting to port 80 if not specified), checks it against the allowlist, and either forwards the request (if allowed) or responds with `403 Forbidden` (if denied).

#### Scenario: Allowed HTTP request forwarded
- **WHEN** a local HTTP test server is running
- **AND** the allowlist permits the server's `host:port`
- **AND** an HTTP GET is made through the proxy to the server
- **THEN** the client receives HTTP 200 with the server's response body

#### Scenario: Denied HTTP request rejected
- **WHEN** the allowlist does not permit `evil.example.com:80`
- **AND** an HTTP GET is made through the proxy to `evil.example.com:80`
- **THEN** the client receives HTTP 403

#### Scenario: HTTP request without port defaults to 80 (allowed)
- **WHEN** the allowlist permits `localhost:80`
- **AND** an HTTP GET is made through the proxy to `http://localhost/status` (no port)
- **THEN** the access log records the target as `localhost:80` with result `OK`

#### Scenario: HTTP request without port defaults to 80 (denied)
- **WHEN** the allowlist does not permit `evil.example.com:80`
- **AND** an HTTP GET is made through the proxy to `http://evil.example.com/status` (no port)
- **THEN** the client receives HTTP 403
- **AND** the access log records the target as `evil.example.com:80` with result `DENY`

### Requirement: Malformed request handling

The proxy SHALL reject malformed requests with `400 Bad Request`.

#### Scenario: Raw bytes sent to UDS
- **WHEN** a client connects to the UDS and sends non-HTTP data
- **THEN** proxy responds with `400`

#### Scenario: CONNECT with missing host
- **WHEN** proxy receives a CONNECT request without a valid `host:port`
- **THEN** proxy responds with `400`

### Requirement: Allowlist enforcement

The proxy SHALL evaluate each request against the net rules allowlist using single-dimension target specificity (see net-rules spec). An exact match takes precedence over a wildcard match.

#### Scenario: Request allowed by most specific rule
- **WHEN** the allowlist contains `net:https:*.example.com:443` and `net:none:evil.example.com:443`
- **AND** proxy receives a CONNECT request for `api.example.com:443`
- **THEN** the access log records the target `api.example.com:443` with result `OK`

#### Scenario: Request denied by most specific rule
- **WHEN** the allowlist contains `net:https:*.example.com:443` and `net:none:evil.example.com:443`
- **AND** proxy receives a CONNECT request for `evil.example.com:443`
- **THEN** proxy responds with `403`

### Requirement: Access log integration

The proxy SHALL record each request in the access log with: operation (`HTTPS` for CONNECT, `HTTP` for plain HTTP), target (`host:port`), result (`OK` or `DENY`), and matching rule (or `no-matching-rule`).

#### Scenario: Allowed request logged
- **WHEN** proxy allows a CONNECT request for a target `host:port`
- **THEN** the access log contains `HTTPS`, the target `host:port`, and `OK`

#### Scenario: Denied request logged
- **WHEN** proxy denies a CONNECT request for `evil.example.com:443`
- **THEN** the access log contains `HTTPS`, `evil.example.com:443`, `DENY`, and `no-matching-rule`

### Requirement: Runtime resolver replacement

`proxy.SetResolver` SHALL atomically replace the net rules resolver used by the proxy for all subsequent requests. In-flight requests that have already loaded the previous resolver SHALL complete with the old rules; new requests SHALL use the new resolver. `SetResolver` SHALL be safe for concurrent use with request handlers.

#### Scenario: SetResolver updates rules for new requests

- **WHEN** the proxy is started with a resolver that denies `evil.example.com:443`
- **AND** SetResolver is called with a new resolver that allows `evil.example.com:443`
- **AND** a CONNECT request for `evil.example.com:443` is received after SetResolver returns
- **THEN** the request is allowed (tunneled)

#### Scenario: SetResolver from deny-all to allow

- **WHEN** the proxy is started with an empty resolver (deny-all)
- **AND** SetResolver is called with a resolver containing `net:https:api.example.com:443`
- **AND** a CONNECT request for `api.example.com:443` is received after SetResolver returns
- **THEN** the request is allowed

#### Scenario: SetResolver from allow to deny-all

- **WHEN** the proxy is started with a resolver allowing `api.example.com:443`
- **AND** SetResolver is called with an empty resolver (deny-all)
- **AND** a CONNECT request for `api.example.com:443` is received after SetResolver returns
- **THEN** the request is denied with 403

### Requirement: Proxy lifecycle

The proxy SHALL be startable and stoppable. Starting the proxy creates the UDS and begins accepting connections. Stopping the proxy closes the listener and removes the UDS.

#### Scenario: Proxy start
- **WHEN** proxy is started
- **THEN** the proxy's listener address is non-nil

#### Scenario: Proxy stop
- **WHEN** proxy is started and then stopped
- **THEN** connecting to the UDS path fails

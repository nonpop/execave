# Proxy Capability

## Purpose

The proxy capability provides a forward HTTP/HTTPS proxy that enforces network access controls for sandboxed processes. It listens on a Unix domain socket (UDS), handles CONNECT requests for HTTPS tunneling and plain HTTP requests, validates each request against the network rules allowlist, and integrates with the access log to record network operations.

## Requirements

### Requirement: Proxy listens on UDS

The proxy SHALL listen on a Unix domain socket (UDS) created in a temporary directory on the host. The proxy SHALL NOT listen on any TCP port or network interface.

#### Scenario: Proxy accepts connection on UDS
- **WHEN** proxy is started with a UDS path
- **AND** a client connects to the UDS
- **THEN** proxy accepts the connection

#### Scenario: Proxy does not listen on TCP
- **WHEN** proxy is started
- **THEN** no TCP port is opened on the host

### Requirement: CONNECT handling for HTTPS

The proxy SHALL handle HTTP CONNECT requests for HTTPS tunneling. When a CONNECT request arrives:
1. Extract the `host:port` from the request line
2. Check the target against the allowlist
3. If allowed: dial the target on the host, respond `200 Connection Established`, relay data bidirectionally until either side closes
4. If denied: respond with `403 Forbidden` and close the connection

The proxy SHALL NOT inspect or modify the encrypted tunnel contents.

#### Scenario: Allowed CONNECT request tunneled
- **WHEN** proxy receives CONNECT request for `example.com:443`
- **AND** net rules allow `example.com:443` via `net:https:example.com:443`
- **THEN** proxy dials `example.com:443`
- **AND** responds with `200 Connection Established`
- **AND** relays data bidirectionally

#### Scenario: Denied CONNECT request rejected
- **WHEN** proxy receives CONNECT request for `evil.example.com:443`
- **AND** no net rule allows `evil.example.com:443`
- **THEN** proxy responds with `403 Forbidden`
- **AND** closes the connection

#### Scenario: CONNECT tunnel closes when target disconnects
- **WHEN** an active CONNECT tunnel exists for `example.com:443`
- **AND** the remote server closes the connection
- **THEN** proxy closes the client side of the tunnel

### Requirement: Plain HTTP forwarding

The proxy SHALL handle plain HTTP requests (non-CONNECT). When a plain HTTP request arrives:
1. Extract the `host:port` from the request URL or `Host` header (defaulting to port 80 for HTTP if not specified)
2. Check the target against the allowlist
3. If allowed: forward the request to the target, copy the response back to the client (stripping hop-by-hop headers)
4. If denied: respond with `403 Forbidden`

#### Scenario: Allowed HTTP request forwarded
- **WHEN** proxy receives plain HTTP GET for `http://example.com:3000/status`
- **AND** net rules allow `example.com:3000` via `net:http:example.com:3000`
- **THEN** proxy dials `example.com:3000`
- **AND** forwards the HTTP request
- **AND** relays the HTTP response back to the client

#### Scenario: Denied HTTP request rejected
- **WHEN** proxy receives plain HTTP GET for `http://evil.example.com:3000/status`
- **AND** no net rule allows `evil.example.com:3000`
- **THEN** proxy responds with `403 Forbidden`

#### Scenario: HTTP request without port defaults to 80 (allowed)
- **WHEN** proxy receives plain HTTP GET for `http://example.com/status`
- **AND** net rules allow `example.com:80` via `net:http:example.com:80`
- **THEN** proxy dials `example.com:80`
- **AND** forwards the HTTP request
- **AND** relays the HTTP response back to the client

#### Scenario: HTTP request without port defaults to 80 (denied)
- **WHEN** proxy receives plain HTTP GET for `http://evil.example.com/status`
- **AND** no net rule allows `evil.example.com:80`
- **THEN** proxy responds with `403 Forbidden`

### Requirement: Malformed request handling

The proxy SHALL reject malformed HTTP requests with an appropriate error response. A sandboxed process that opens the UDS directly and sends raw (non-HTTP) bytes SHALL receive an error response.

#### Scenario: Raw bytes sent to UDS
- **WHEN** a client connects to the UDS
- **AND** sends non-HTTP data
- **THEN** proxy responds with `400 Bad Request`

#### Scenario: CONNECT with missing host
- **WHEN** proxy receives a CONNECT request without a host:port
- **THEN** proxy responds with `400 Bad Request`

### Requirement: Allowlist enforcement

The proxy SHALL evaluate each request against the net rules allowlist using single-dimension target specificity (see net-rules spec). The allowlist is constructed from net rules at proxy startup and is read-only — no locks are needed for concurrent access.

#### Scenario: Request allowed by most specific rule
- **WHEN** net rules contain `net:https:*.example.com:443` and `net:none:evil.example.com:443`
- **AND** proxy receives CONNECT for `api.example.com:443`
- **THEN** proxy allows the request (wildcard matches, no more specific deny)

#### Scenario: Request denied by most specific rule
- **WHEN** net rules contain `net:https:*.example.com:443` and `net:none:evil.example.com:443`
- **AND** proxy receives CONNECT for `evil.example.com:443`
- **THEN** proxy denies the request (exact deny beats wildcard allow)

### Requirement: Access log integration

The proxy SHALL feed each request to the access log as an entry with:
- Operation: `HTTPS` for CONNECT requests, `HTTP` for plain HTTP requests
- Target: the `host:port` from the request
- Result: `OK` if allowed, `DENY` if denied
- Rule: the matching rule string (e.g., `net:https:example.com:443`) or `no-matching-rule`

#### Scenario: Allowed request logged
- **WHEN** proxy allows a CONNECT request for `example.com:443`
- **AND** the matching rule is `net:https:example.com:443`
- **THEN** access log contains: `HTTPS example.com:443 OK net:https:example.com:443`

#### Scenario: Denied request logged
- **WHEN** proxy denies a CONNECT request for `evil.example.com:443`
- **AND** there is no matching rule
- **THEN** access log contains: `HTTPS evil.example.com:443 DENY no-matching-rule`

### Requirement: Proxy lifecycle

The proxy SHALL be startable and stoppable. Starting the proxy creates the UDS and begins accepting connections. Stopping the proxy closes the listener, drains in-flight connections (with a timeout), and removes the UDS. Connections that don't complete within the drain timeout are forcibly closed. If the proxy crashes or is stopped, the UDS becomes unavailable and new connections from the sandbox fail (fail-closed).

#### Scenario: Proxy start
- **WHEN** proxy is started
- **THEN** UDS is created and proxy accepts connections

#### Scenario: Proxy stop
- **WHEN** proxy is stopped
- **THEN** listener is closed
- **AND** UDS is removed

#### Scenario: In-flight connections drained on stop
- **WHEN** proxy has an active CONNECT tunnel for `example.com:443`
- **AND** proxy is stopped
- **THEN** existing tunnel continues until completion
- **AND** no new connections are accepted
- **AND** UDS is removed after all connections drain

#### Scenario: Drain timeout forcibly closes connections
- **WHEN** proxy has an active CONNECT tunnel for `example.com:443`
- **AND** proxy is stopped
- **AND** connection does not complete within drain timeout
- **THEN** proxy forcibly closes the connection
- **AND** UDS is removed

#### Scenario: Proxy crash is fail-closed
- **WHEN** proxy process terminates unexpectedly
- **AND** sandboxed process attempts a new connection via UDS
- **THEN** connection fails (UDS unavailable)

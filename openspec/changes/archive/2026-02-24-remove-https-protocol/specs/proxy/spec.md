## MODIFIED Requirements

### Requirement: CONNECT handling for HTTPS

The proxy SHALL handle HTTP CONNECT requests for tunneling. When a CONNECT request arrives, the proxy extracts the `host:port`, checks it against the allowlist using `ProtocolHTTP`, and either tunnels the connection (if allowed) or responds with `403 Forbidden` (if denied).

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

### Requirement: Allowlist enforcement

The proxy SHALL evaluate each request against the net rules allowlist using single-dimension target specificity (see net-rules spec). An exact match takes precedence over a wildcard match. Both CONNECT and plain HTTP requests resolve against `ProtocolHTTP`.

#### Scenario: Request allowed by most specific rule
- **WHEN** the allowlist contains `net:http:*.example.com:443` and `net:none:evil.example.com:443`
- **AND** proxy receives a CONNECT request for `api.example.com:443`
- **THEN** the access log records the target `api.example.com:443` with result `OK`

#### Scenario: Request denied by most specific rule
- **WHEN** the allowlist contains `net:http:*.example.com:443` and `net:none:evil.example.com:443`
- **AND** proxy receives a CONNECT request for `evil.example.com:443`
- **THEN** proxy responds with `403`

### Requirement: Access log integration

The proxy SHALL record each request in the access log with: operation `HTTP` (for both CONNECT and plain HTTP), target (`host:port`), result (`OK` or `DENY`), and matching rule (or `no-matching-rule`).

#### Scenario: Allowed request logged
- **WHEN** proxy allows a CONNECT request for a target `host:port`
- **THEN** the access log contains `HTTP`, the target `host:port`, and `OK`

#### Scenario: Denied request logged
- **WHEN** proxy denies a CONNECT request for `evil.example.com:443`
- **THEN** the access log contains `HTTP`, `evil.example.com:443`, `DENY`, and `no-matching-rule`

### Requirement: Runtime resolver replacement

`proxy.SetResolver` SHALL atomically replace the net rules resolver used by the proxy for all subsequent requests. In-flight requests that have already loaded the previous resolver SHALL complete with the old rules; new requests SHALL use the new resolver. `SetResolver` SHALL be safe for concurrent use with request handlers.

#### Scenario: SetResolver updates rules for new requests

- **WHEN** the proxy is started with a resolver that denies `evil.example.com:443`
- **AND** SetResolver is called with a new resolver that allows `evil.example.com:443`
- **AND** a CONNECT request for `evil.example.com:443` is received after SetResolver returns
- **THEN** the request is allowed (tunneled)

#### Scenario: SetResolver from deny-all to allow

- **WHEN** the proxy is started with an empty resolver (deny-all)
- **AND** SetResolver is called with a resolver containing `net:http:api.example.com:443`
- **AND** a CONNECT request for `api.example.com:443` is received after SetResolver returns
- **THEN** the request is allowed

#### Scenario: SetResolver from allow to deny-all

- **WHEN** the proxy is started with a resolver allowing `api.example.com:443`
- **AND** SetResolver is called with an empty resolver (deny-all)
- **AND** a CONNECT request for `api.example.com:443` is received after SetResolver returns
- **THEN** the request is denied with 403

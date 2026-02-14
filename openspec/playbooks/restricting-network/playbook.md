# Restricting Network — Controlling network access for sandboxed commands

## Purpose

The user runs commands inside the sandbox with network access controlled by rules. Rules grant HTTPS, HTTP, or no-access permissions on specific endpoints. Without any net rules, the sandbox has no network interface at all (default-deny). When net rules are present, network traffic flows through a forward proxy that enforces the allowlist.

## Use Cases

### Use Case: Run command with no network access (default-deny)

The user runs a command without any net rules in the config. The sandbox has no network interface, so all network access fails regardless of protocol.

- **GIVEN** a config with only filesystem rules (no `net:` rules)
- **WHEN** the user runs `execave -- curl https://example.com`
- **THEN** the connection fails (no network interface available inside the sandbox)
- **AND** DNS resolution also fails (no network interface)

### Use Case: Allow specific HTTPS endpoints

The user grants access to a specific HTTPS endpoint so the sandboxed command can make TLS connections to that host.

- **GIVEN** a config with rule `net:https:api.example.com:443`
- **WHEN** the user runs `execave -- curl https://api.example.com/data`
- **THEN** the HTTPS request succeeds through the proxy
- **AND** HTTPS requests to any other host are denied with `403 Forbidden`

### Use Case: Allow specific HTTP endpoints

The user grants access to a specific plain HTTP endpoint so the sandboxed command can make unencrypted requests to that host.

- **GIVEN** a config with rule `net:http:internal.example.com:3000`
- **WHEN** the user runs `execave -- curl http://internal.example.com:3000/status`
- **THEN** the HTTP request succeeds through the proxy
- **AND** HTTP requests to any other host are denied with `403 Forbidden`

### Use Case: Block specific domain within wildcard allow

The user allows all subdomains of a domain but blocks a specific subdomain using a `none` rule. The most specific rule wins.

- **GIVEN** a config with rules `net:https:*.example.com:443` and `net:none:evil.example.com:443`
- **WHEN** the user runs `execave -- curl https://api.example.com/data`
- **THEN** the request to `api.example.com` succeeds (wildcard matches)
- **AND** a request to `evil.example.com` is denied (exact domain beats wildcard)

### Use Case: Block specific IP within CIDR allow

The user allows a CIDR range but blocks a specific IP within it using a `none` rule. The longer prefix wins.

- **GIVEN** a config with rules `net:http:10.0.0.0/24:*` and `net:none:10.0.0.99/32:*`
- **WHEN** the user runs `execave -- curl http://10.0.0.5:8080/status`
- **THEN** the request to `10.0.0.5` succeeds (`/24` matches)
- **AND** a request to `10.0.0.99` is denied (`/32` beats `/24`)

### Use Case: Direct TCP connections fail (process ignores HTTP_PROXY)

The user configures net rules, but the sandboxed process ignores the `HTTP_PROXY` environment variable and attempts a direct TCP connection. The connection fails because the sandbox has no network interface — isolation is enforced by the kernel, not by the proxy.

- **GIVEN** a config with rule `net:https:api.example.com:443`
- **WHEN** the user runs a command that ignores `HTTP_PROXY` and attempts a direct TCP connection to `api.example.com:443`
- **THEN** the connection fails (no NIC, no route in the sandbox network namespace)

### Use Case: UDP traffic blocked

The user configures net rules, but the sandboxed process attempts to send UDP traffic. All UDP fails because the sandbox has no network interface and the proxy only handles HTTP/HTTPS.

- **GIVEN** a config with net rules
- **WHEN** the user runs a command that attempts to send a UDP packet (e.g., DNS query to `8.8.8.8:53`)
- **THEN** the packet send fails (no network interface in the sandbox)

### Use Case: Exit code preserved with net rules

The user runs a command that exits with a non-zero code while net rules are active. The tunnel and proxy layers must not swallow the exit code.

- **GIVEN** a config with rule `net:http:127.0.0.1:*`
- **WHEN** the user runs `execave -- sh -c 'exit 42'`
- **THEN** execave exits with code 42

### Use Case: Wildcard port access

The user allows access to a host on any port using a wildcard port rule, so the sandboxed command can connect to any port on that host.

- **GIVEN** a config with rule `net:https:api.example.com:*`
- **WHEN** the user runs `execave -- curl https://api.example.com:8443/data`
- **THEN** the request succeeds (wildcard port matches any port)
- **AND** a request to `api.example.com:443` also succeeds

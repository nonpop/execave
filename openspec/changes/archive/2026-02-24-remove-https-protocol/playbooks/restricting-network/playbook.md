## MODIFIED Use Cases

### Use Case: Allow specific HTTPS endpoints

The user grants access to a specific endpoint so the sandboxed command can make HTTPS connections to that host. The `http` rule allows both plain HTTP and CONNECT-tunneled (HTTPS) requests.

- **GIVEN** a config with rule `net:http:api.example.com:443`
- **WHEN** the user runs `execave -- curl https://api.example.com/data`
- **THEN** the HTTPS request succeeds through the proxy (via CONNECT tunnel)
- **AND** requests to any other host are denied with `403 Forbidden`

### Use Case: Allow specific HTTP endpoints

The user grants access to a specific plain HTTP endpoint so the sandboxed command can make unencrypted requests to that host.

- **GIVEN** a config with rule `net:http:internal.example.com:3000`
- **WHEN** the user runs `execave -- curl http://internal.example.com:3000/status`
- **THEN** the HTTP request succeeds through the proxy
- **AND** HTTP requests to any other host are denied with `403 Forbidden`

### Use Case: Block specific domain within wildcard allow

The user allows all subdomains of a domain but blocks a specific subdomain using a `none` rule. The most specific rule wins.

- **GIVEN** a config with rules `net:http:*.example.com:443` and `net:none:evil.example.com:443`
- **WHEN** the user runs `execave -- curl https://api.example.com/data`
- **THEN** the request to `api.example.com` succeeds (wildcard matches)
- **AND** a request to `evil.example.com` is denied (exact domain beats wildcard)

### Use Case: Direct TCP connections fail (process ignores HTTP_PROXY)

The user configures net rules, but the sandboxed process ignores the `HTTP_PROXY` environment variable and attempts a direct TCP connection. The connection fails because the sandbox has no network interface — isolation is enforced by the kernel, not by the proxy.

- **GIVEN** a config with rule `net:http:api.example.com:443`
- **WHEN** the user runs a command that ignores `HTTP_PROXY` and attempts a direct TCP connection to `api.example.com:443`
- **THEN** the connection fails (no NIC, no route in the sandbox network namespace)

### Use Case: Wildcard port access

The user allows access to a host on any port using a wildcard port rule, so the sandboxed command can connect to any port on that host.

- **GIVEN** a config with rule `net:http:api.example.com:*`
- **WHEN** the user runs `execave -- curl https://api.example.com:8443/data`
- **THEN** the request succeeds (wildcard port matches any port)
- **AND** a request to `api.example.com:443` also succeeds


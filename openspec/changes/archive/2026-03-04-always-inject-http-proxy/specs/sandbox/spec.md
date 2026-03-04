## MODIFIED Requirements

### Requirement: Proxy-tunnel path setup

When a NetworkPath is provided, BuildBwrapArgs SHALL bind-mount the proxy UDS and execave binary into the sandbox read-only, and wrap the user command with `execave network-tunnel`.

Note: The CLI always provides a NetworkPath; testing the always-on proxy behavior requires bwrap + proxy orchestration and cannot be tested at the sandbox package level.

#### Scenario: Proxy-tunnel setup
- **WHEN** NetworkPath is provided
- **THEN** BuildBwrapArgs wraps the command with `network-tunnel` and the sandbox-internal UDS path

#### Scenario: Proxy UDS bind-mounted into sandbox
- **WHEN** NetworkPath has UDSPath `/tmp/test-proxy.sock`
- **THEN** BuildBwrapArgs includes `--ro-bind /tmp/test-proxy.sock /tmp/execave-proxy.sock`

#### Scenario: Execave binary bind-mounted read-only
- **WHEN** NetworkPath has ExecaveBinary `/usr/local/bin/execave`
- **THEN** BuildBwrapArgs includes `--ro-bind /usr/local/bin/execave /tmp/execave`

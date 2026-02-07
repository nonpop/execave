## ADDED Requirements

### Requirement: Default-deny network

The sandbox SHALL isolate the network namespace unconditionally (no `--share-net`). Without net rules, sandboxed processes SHALL have no network access — no NIC, no route, no DNS.

#### Scenario: No net rules means no network
- **WHEN** config contains only fs rules (no `net:` rules)
- **AND** sandboxed process attempts to connect to `api.anthropic.com:443`
- **THEN** connection fails (no network interface available)

#### Scenario: No net rules means no DNS
- **WHEN** config contains only fs rules (no `net:` rules)
- **AND** sandboxed process attempts DNS resolution
- **THEN** resolution fails (no network interface available)

### Requirement: Proxy-tunnel path setup

When net rules are present in the config or monitoring is enabled, the sandbox SHALL:
1. Create a temporary directory for the proxy UDS
2. Start the proxy on the host, listening on the UDS
3. Bind-mount the UDS read-only into the sandbox at a fixed path
4. Bind-mount the execave binary read-only into the sandbox
5. Wrap the user command with `execave network-tunnel`

#### Scenario: Net rules trigger proxy-tunnel setup
- **WHEN** config contains `net:https:api.anthropic.com:443`
- **AND** sandboxed process uses `HTTP_PROXY` to connect to `api.anthropic.com:443`
- **THEN** connection succeeds through the proxy-tunnel path

#### Scenario: Proxy UDS bind-mounted into sandbox
- **WHEN** config contains net rules
- **THEN** the proxy UDS is accessible inside the sandbox as a filesystem object

#### Scenario: Execave binary bind-mounted read-only
- **WHEN** config contains net rules
- **THEN** the execave binary inside the sandbox is read-only (cannot be overwritten by sandboxed processes)

#### Scenario: Monitoring without net rules starts proxy-tunnel
- **WHEN** monitoring is enabled
- **AND** config contains no `net:` rules
- **THEN** the proxy-tunnel path is started with an empty rule set (deny-all)
- **AND** HTTP-proxy-aware programs' network access attempts are logged

### Requirement: Proxy lifecycle management

The sandbox SHALL start the proxy before the sandboxed process begins and stop the proxy after the sandboxed process exits. The temporary directory and UDS SHALL be cleaned up on exit.

#### Scenario: Proxy started before sandbox
- **WHEN** config contains net rules
- **THEN** proxy is accepting connections before the sandboxed process starts

#### Scenario: Cleanup on exit
- **WHEN** sandboxed process exits
- **THEN** proxy is stopped
- **AND** temporary directory and UDS are removed

### Requirement: Processes ignoring HTTP_PROXY have no network

Sandboxed processes that ignore `HTTP_PROXY` and attempt direct TCP connections SHALL fail because the sandbox has no NIC and no route. This is enforced by the kernel's network namespace isolation, not by the proxy.

#### Scenario: Direct connection fails
- **WHEN** config contains `net:https:api.anthropic.com:443`
- **AND** sandboxed process ignores `HTTP_PROXY` and attempts a direct TCP connection to `api.anthropic.com:443`
- **THEN** connection fails (no NIC, no route)

#### Scenario: UDP fails
- **WHEN** config contains net rules
- **AND** sandboxed process attempts to send a UDP packet
- **THEN** packet send fails (no network interface)

## MODIFIED Requirements

### Requirement: CLI command execution

The system SHALL execute the command specified after `--` in the sandboxed environment. When net rules are present, the command is wrapped with `execave network-tunnel` which sets up the proxy bridge and then runs the user command as a subprocess. The user command's exit code SHALL be propagated as execave's exit code.

#### Scenario: Command execution without net rules
- **WHEN** user runs `execave -- python script.py`
- **AND** config contains no net rules
- **THEN** `python script.py` runs directly inside the sandbox

#### Scenario: Command execution with net rules
- **WHEN** user runs `execave -- python script.py`
- **AND** config contains net rules
- **THEN** `python script.py` runs inside the sandbox as a subprocess of the tunnel
- **AND** proxy environment variables are set

#### Scenario: Exit code propagation with tunnel
- **WHEN** config contains net rules
- **AND** sandboxed command exits with code 42
- **THEN** execave exits with code 42

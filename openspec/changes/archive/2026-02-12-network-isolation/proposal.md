## Why

Execave provides filesystem sandboxing but currently shares the host's network (`--share-net`), allowing sandboxed processes to send data anywhere. This enables data exfiltration — the primary threat model gap. Network isolation with a configurable allowlist closes this gap while preserving access to specific services (LLM APIs, package registries).

## What Changes

- **BREAKING**: Network is isolated by default. Existing configs lose network access unless `net:` rules are added.
- New `net:<action>:<target>:<port>` rule format for domain, IP, and CIDR allowlisting
- Sandboxed processes can only reach the network through an allowlist-filtered proxy
- Access log extended with network operation types (`HTTPS`, `HTTP`) alongside existing `READ`/`WRITE`

## Capabilities

### New Capabilities
- `net-rules`: Net rule parsing, target types (domain/IP/CIDR), matching with single-dimension target specificity, and config validation (no duplicate identity, no mixed port patterns)
- `proxy`: Forward HTTP proxy with domain/IP/CIDR allowlist enforcement; feeds resolved access entries to `access-log`
- `tunnel`: In-sandbox network bridge that connects sandboxed processes to the proxy and runs the user command

### Modified Capabilities
- `config`: Routes `net:` rules to `net-rules`
- `sandbox`: Remove `--share-net`; when net rules are present, set up the proxy-tunnel path into the sandbox
- `monitor`: Update setup phase detection (3 execve calls when tunnel is present, 2 otherwise)
- `access-log`: Add `HTTPS` and `HTTP` operation types for proxy entries

## Security Impact

- **Sandbox boundaries**: Network namespace isolation replaces shared network. Enforcement through absence of connectivity rather than filtering — no NIC, no route in sandbox.
- **Permission checks**: Net rule resolution uses single-dimension target specificity, analogous to fs rule path-length specificity.
- **Config parsing**: Config adds `net:` → `net-rules` routing. Net rule parsing introduces new user-controlled input to parse and validate.
- **Bwrap invocation**: `--share-net` removed unconditionally; new bind-mounts added when net rules are present.

**Trust boundaries:**
- **User input -> Config -> Rule domains**: Config routes raw rules by prefix; `fs-rules` and `net-rules` each parse and validate their own rule format
- **Config -> Proxy**: Validated net rules determine proxy allowlist
- **Config -> Sandbox**: Net rule presence determines sandbox network setup (no --share-net, proxy-tunnel bind-mounts)
- **Sandbox -> Host (proxy)**: Proxy is the only network exit path; enforces allowlist on every request

**Threat model implications:**
- Proxy bugs could allow access to non-allowlisted domains/IPs
- Net rule resolution errors could grant unintended network access (analogous to fs rule resolution risks)
- Sandbox has no NIC and no route — processes that ignore HTTP_PROXY simply have no network path, not bypassed filtering
- DNS exfiltration impossible: no DNS resolver in sandbox, proxy resolves on host
- Tunnel binary bind-mounted read-only; even if compromised, all traffic still routes through proxy allowlist
- Proxy crash makes UDS unavailable — new connections fail (fail-closed)

## Impact

- **Breaking change**: All existing configs lose network access. Users must add `net:` rules to restore connectivity.
- **New packages**: `internal/netrules/`, `internal/proxy/`, `internal/tunnel/`
- **Modified packages**: `internal/config/`, `internal/sandbox/`, `internal/monitor/`, `internal/accesslog/`, `cmd/execave/`
- **Dependencies**: None (pure Go stdlib)

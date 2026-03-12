## Why (Rejected)

> **Note: This approach was rejected as fundamentally unsafe.**
>
> An agent inside the sandbox can write to rw-mounted files and then trigger a host command that reads those files (e.g. `go run .`, `npm start`, `make`). The rule engine gates which command runs but not what the command reads — so the agent controls the payload. Any allowed command that touches sandbox-writable paths executes attacker-controlled code on the host. This cannot be mitigated without either defeating the purpose of the feature or restricting it to commands that never read rw-mounted paths (a narrow, hard-to-enforce set).

Sandboxed applications sometimes need to run host-side commands (servers, game engines, build tools) to get feedback, but the sandbox provides no mechanism for this. The only cross-boundary channel is the HTTP proxy for network access. Adding a command proxy lets sandboxed apps execute pre-approved commands on the host with streaming I/O.

## What Changes

- New config section `cmd` with rules like `allow:npm start` (exact command match, default-deny)
- New host-side command proxy daemon on a dedicated UDS, enforcing cmd rules
- New `execave host-cmd` CLI subcommand (runs inside sandbox) that connects to the cmd proxy and relays stdin/stdout/stderr, exit codes, and signals
- `network-tunnel` subcommand renamed to `sandbox-tunnel` (reflects its broader role bridging all cross-boundary channels)
- Tunnel extended to pass the cmd proxy UDS path and set `EXECAVE_CMD_SOCKET` env var
- Access log extended with `CMD` operation type for monitoring command executions
- Rename `internal/proxy/` to `internal/netproxy/` for clarity alongside the new `internal/cmdproxy/`
- Config parsing extended to handle `cmd` section with parse/validate/merge pipeline
- **Security impact**: This intentionally creates a new cross-boundary channel. The sandboxed process (untrusted) can request command execution on the host (trusted). Mitigation: exact string match only (no wildcards, no shell interpretation), default-deny, user explicitly configures allowed commands. Each allowed command runs with full host privileges -- the blast radius depends on what commands the user permits (analogous to `rw:` fs rules).

## Playbooks

### New Playbooks
- `running-host-commands`: Configuring and using host-side command execution from within the sandbox

### Modified Playbooks
- `monitoring-access`: Access log gains CMD operation type entries for command executions

## Capabilities

### New Capabilities
- `cmd-rules`: Parsing, validation, and resolution of command execution rules (`allow:<exact command>`)
- `cmd-proxy`: Host-side command proxy daemon that accepts connections over UDS, enforces cmd rules, spawns host commands, and multiplexes stdin/stdout/stderr/exit code/signals over a framed protocol

### Modified Capabilities
- `proxy`: Renamed to `netproxy` to distinguish from the new cmd proxy
- `config`: New `cmd` section in TOML config for command execution rules
- `tunnel`: Extended to accept cmd proxy UDS path and inject `EXECAVE_CMD_SOCKET` env var
- `access-log`: New `CMD` operation type for command execution entries
- `runner`: Orchestrates cmd proxy lifecycle alongside existing network proxy

## Impact

- **New packages**: `internal/cmdrules/`, `internal/cmdproxy/`
- **New CLI subcommand**: `cmd/execave/commands/host_cmd.go`
- **Renamed package**: `internal/proxy/` -> `internal/netproxy/`
- **Modified packages**: `internal/config/`, `internal/tunnel/`, `internal/accesslog/`, `internal/run/`
- **Config format**: Additive (new optional `cmd` section). Backward-compatible.
- **Security model**: New trust boundary crossing. Must be documented in `docs/security-model.md`.
- **No new dependencies**: Uses stdlib only (net, os/exec, encoding/binary).

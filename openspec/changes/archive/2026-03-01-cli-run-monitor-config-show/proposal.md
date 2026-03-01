## Why

Layered configs make policy composition easier, but users currently cannot inspect the final merged policy that execave actually enforces. At the same time, monitor behavior is exposed as root flags, which makes command intent and flag scope harder to understand.

## What Changes

- Add explicit CLI subcommands:
  - `run` for sandboxed execution
  - `monitor` for strace-based monitoring execution
  - `config show` for printing the effective merged config
- Make `--config` a global root flag (`execave [--config PATH] <command>`).
- Scope monitor-only flags (`--show-allowed`, `--show-nolog`, `--no-sandbox`, monitor output selection) to the `monitor` command.
- Keep backward compatibility by making bare execution default to `run` behavior when no explicit subcommand is provided.
- Add effective-config rendering as TOML only (no format flag), with source provenance included as comments for emitted rules.
- Preserve existing security model and enforcement semantics; this is a CLI surface and observability improvement.
- **BREAKING**: none (implicit run remains supported).

## Playbooks

### New Playbooks
- `inspecting-effective-config`: Inspect the final merged layered config and understand where each emitted rule originated.

### Modified Playbooks
- `configuring-execave`: Update command usage to include `run`, `monitor`, and `config show`, with global `--config`.
- `monitoring-access`: Update monitor invocation and monitor-specific flag usage under the `monitor` subcommand.

## Capabilities

### New Capabilities
- `commands`: Define root/subcommand behavior, implicit-run fallback, and command-scoped flag semantics.

### Modified Capabilities
- `config`: Add requirements for rendering effective merged config as TOML with source comments.
- `monitor`: Align monitor entrypoint/flag contract with the `monitor` subcommand.

## Impact

- `cmd/execave/main.go`: root command structure, global/persistent flag handling, run/monitor/config subcommands, and implicit run dispatch.
- `internal/config`: serialization/formatting path for effective merged config output with source comments.
- `README.md`, `docs/architecture.md`, `docs/security-model.md`: CLI and effective-config documentation updates.
- `openspec/playbooks/*` and `openspec/specs/*`: new/modified artifacts for command surface and effective-config behavior.
- Tests: E2E coverage for new command forms and effective-config output; integration coverage for config rendering/provenance formatting.

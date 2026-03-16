## Why

Running execave always requires a TOML config file, even for one-off commands or quick experiments. Users need a way to add rules directly from the command line — both to augment an existing config and to run without any config file at all.

## What Changes

- Add repeatable CLI flags for all rule sections: `--fs`, `--net`, `--syscall`, `--env`, `--extends`
- Add `--no-config` flag to opt out of config file loading entirely
- CLI flags are modeled as a virtual `<cli>` config: `--extends` and the implicit config file populate its `extends` field; `--fs`/`--net`/`--syscall`/`--env` populate the corresponding rule sections
- When a config file is used (no `--no-config`), it becomes an implicit entry in the virtual config's extends chain
- `--config` and `--no-config` together is an error
- Cross-source conflicts (e.g., `none:/foo` in config + `rw:/foo` on CLI) are rejected by existing duplicate-path/identity validation
- CLI rule flags apply to `run` (implicit and explicit), `monitor`, and `config show`

**Security impact**: CLI rules are fed through the same parse → merge → validate pipeline as file rules. No new trust boundary or validation bypass is introduced. Cross-source conflicts (same path, different permission) are rejected by existing validators. The config file (if present) is still protected from explicit writability.

## Playbooks

### New Playbooks
(none)

### Modified Playbooks
- `configuring-execave`: Gains use cases for CLI rule flags (`--fs`, `--net`, `--syscall`, `--env`, `--extends`), `--no-config` flag, and interaction between CLI rules and config file

## Capabilities

### New Capabilities
(none)

### Modified Capabilities
- `config`: Gains requirements for CLI rule parsing, `--no-config` flag, and the virtual `<cli>` config model
- `commands`: Gains requirements for new CLI flags (`--fs`, `--net`, `--syscall`, `--env`, `--extends`, `--no-config`) on root, `run`, and `monitor` commands

## Impact

- `cmd/execave/commands/`: New flag definitions on root/run/monitor commands
- `internal/config/`: New entry point to build config from CLI flags + optional file; virtual config participates in existing merge/validate pipeline
- `internal/run/`: `SandboxConfig` and `LoadRuntimeConfig` gain CLI rule fields; must handle no-config-file case
- `config show` output: CLI-sourced rules render with `<cli>` provenance instead of a file path
- No dependency changes

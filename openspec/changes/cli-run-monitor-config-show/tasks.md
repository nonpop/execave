## 1. Security and CLI surface preparation

- [x] 1.1 Read `docs/security-model.md` and preserve sandbox-boundary invariants while refactoring CLI command routing.
- [x] 1.2 Refactor `cmd/execave/main.go` to add `run`, `monitor`, and `config show` subcommands with global `--config` as a persistent root flag.
- [x] 1.3 Implement implicit-run dispatch so `execave -- <command>` remains behavior-equivalent to `execave run -- <command>`.

## 2. Monitor command scoping

- [x] 2.1 Move monitor-only options (`show-allowed`, `show-nolog`, `no-sandbox`, output mode/path) from root to `monitor`.
- [x] 2.2 Keep existing monitored execution semantics unchanged when invoked via `monitor`.
- [x] 2.3 Add/update CLI and E2E tests for monitor subcommand invocation and flag scoping errors.

## 3. Effective config output

- [x] 3.1 Add `config show` command that loads config through `config.Load` and renders effective TOML sections (`fs`, `net`, `syscall`).
- [x] 3.2 Include source provenance comments for each emitted rule in `config show` output.
- [x] 3.3 Add integration tests for effective TOML rendering and source-comment output for layered configs.

## 4. Documentation and verification

- [x] 4.1 Update `README.md`, `docs/architecture.md`, and `docs/security-model.md` for new command forms and `config show`.
- [x] 4.2 Update E2E playbook-aligned tests for `configuring-execave`, `monitoring-access`, and `inspecting-effective-config`.
- [x] 4.3 Run affected fuzz targets for config parsing/validation for at least 30 seconds and run `go test ./...`.

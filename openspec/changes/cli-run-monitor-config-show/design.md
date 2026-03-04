## Context

The current CLI treats command execution as the root action and exposes monitoring through root flags. With layered config now available, users need a first-class way to inspect the effective merged policy. This change is security-relevant because it touches config parsing/display paths and command dispatch, which influence how trusted config input is interpreted before untrusted child processes run.

## Goals / Non-Goals

**Goals:**
- Introduce explicit `run`, `monitor`, and `config show` commands with a global `--config` flag.
- Preserve existing behavior for bare command execution by making it equivalent to `run`.
- Move monitor-specific controls to the `monitor` command surface.
- Add effective merged config rendering as TOML, including source-path provenance comments.
- Keep sandbox and enforcement semantics unchanged.

**Non-Goals:**
- No changes to bwrap namespace model, seccomp behavior, or net allow/deny resolution.
- No new output formats for effective config.
- No change to layered merge semantics (dedup/validation rules remain in `internal/config`).

## Decisions

### Decision: Root command becomes a dispatcher with explicit subcommands
`cmd/execave/main.go` will define `run`, `monitor`, and `config show`. The root command keeps `--config` as a persistent flag and dispatches implicit execution to `run` when no subcommand is selected.

**Why:** Better UX and clearer flag ownership while preserving compatibility for existing `execave -- <cmd>` workflows.

**Alternative considered:** Keep root-only execution and add aliases. Rejected because monitor flag scoping remains ambiguous and discoverability stays poor.

### Decision: Monitor-only flags are scoped to `monitor`
`--show-allowed`, `--show-nolog`, `--no-sandbox`, and monitor output selection move under the `monitor` subcommand.

**Why:** Prevents accidental mixing of monitor behavior with non-monitor runs and keeps the root surface minimal.

**Alternative considered:** Keep root monitor flags for compatibility. Rejected because it conflicts with explicit command boundaries requested by users.

### Decision: `config show` renders effective merged config with source comments
`config show` uses the same layered load path as runtime (`config.Load`) and renders effective TOML sections (`fs`, `net`, `syscall`) with deterministic ordering and per-rule source comments.

**Why:** Guarantees what users inspect is what execave enforces; source comments improve auditability and troubleshooting in layered setups.

**Alternative considered:** Raw JSON or TOML without provenance. Rejected because JSON was not requested and TOML without sources is less actionable for layered debugging.

## Risks / Trade-offs

- [Risk] Implicit-run dispatch could misclassify user commands that share names with subcommands.  
  → Mitigation: Cobra subcommand precedence stays explicit; bare command fallback only applies when no known subcommand is matched.

- [Risk] Effective-config output may be mistaken as a config parser input due to source comments and normalization.  
  → Mitigation: Document that output is an inspection view; enforce deterministic rendering and keep comments display-only.

- [Risk] CLI refactor may regress existing monitor/no-sandbox workflows.  
  → Mitigation: Add E2E coverage for `run`, `monitor`, implicit run, and `config show`.

- [Risk] Security expectations could shift if users think `config show` changes enforcement.  
  → Mitigation: Keep load/validation path unchanged and explicitly state no sandbox boundary changes in docs.

## Migration Plan

1. Introduce subcommands while retaining implicit run behavior.
2. Move monitor flags under `monitor` and update help/docs/examples.
3. Add `config show` wired to `config.Load` + TOML renderer with source comments.
4. Update E2E/integration tests for new command forms and output behavior.
5. Validate with full test suite and sync docs/specs/playbooks.

Rollback: revert CLI dispatch and `config show` additions; runtime enforcement logic remains untouched.

## Open Questions

- None currently.

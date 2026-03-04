## Context

Log/nolog visibility rules were introduced to let users suppress known-harmless access log entries from display. They are display-only (no security impact) but span 6+ packages: `fsrules`, `netrules`, `syscallrules`, `config`, `logfilter`, and `textlog`. The implementation includes ~200 LOC plus corresponding tests. The `--show-nolog` CLI flag and the `IsNolog` logic add branching in the text log writer's hot path.

The complexity is disproportionate to the benefit. Users can achieve the same result via external filtering (`grep`, `tail -f | grep -v`, etc.) with no config changes.

## Goals / Non-Goals

**Goals:**
- Remove all log/nolog rule types from config (`fs:log:`, `fs:nolog:`, `net:log:`, `net:nolog:`, `syscall:nolog:`)
- Remove `--show-nolog` flag from the `monitor` command
- Delete `logrules.go` files from fsrules, netrules, syscallrules packages
- Remove `IsNolog` from logfilter, `showNolog` from textlog, nolog fields from Config
- Remove all corresponding tests (integration, unit, E2E)

**Non-Goals:**
- Providing a replacement feature for log suppression
- Deprecation period or backwards-compat shim — this is a hard break

## Decisions

**Full removal, no deprecation.** A compatibility shim (silently ignoring log/nolog rules) would be worse than a hard error because users would lose suppression silently. Failing fast on unknown rule prefixes lets users find and fix their configs immediately.

**No new filtering mechanism.** External tools (`grep`, shell pipelines) are sufficient for filtering text log output. Adding a replacement would re-introduce the same complexity in a different form.

**Breaking config format change is acceptable.** The feature has marginal real-world adoption; the TOML config is user-editable and easy to update. The error message on parse failure will identify the offending rule.

## Risks / Trade-offs

**Config breakage for existing users** → Mitigation: Load returns a clear error naming the unrecognized rule prefix (`fs:nolog:`, `net:log:`, `syscall:nolog:`); the error is actionable (delete the rule).

**Test surface reduction** → Mitigation: Removing tests of deleted functionality is correct; no coverage is lost for remaining behavior.

## Migration Plan

1. Remove log/nolog rules from any `execave.toml` files.
2. If log suppression was used, replace with external filtering on the text log output (e.g., `execave monitor ... 2>&1 | grep -v DENY`).

No rollback is needed — this is a unidirectional simplification.

## Open Questions

None.

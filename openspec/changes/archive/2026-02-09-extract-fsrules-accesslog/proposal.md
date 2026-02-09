## Why

The config and monitor packages each mix two concerns: config handles both JSON loading and FS rule parsing/validation; monitor handles both strace integration and access log writing. Extracting `fsrules` and `accesslog` into their own packages is needed to support network isolation, which will add `netrules` (parallel to `fsrules`) and feed network events into the same access log. Without this separation, network rules would either duplicate FS-specific logic in config or create circular dependencies between config, monitor, and the new proxy.

## What Changes

- Extract FS rule parsing (`parseFSRule`, path normalization), FS-specific validation (duplicate paths, managed paths, config-not-writable), and rule resolution (`CheckAccess`, `PermissionFor`, path prefix matching, symlink handling, longest-match specificity) into a new `internal/fsrules` package. The existing `internal/rules` package is absorbed entirely.
- Extract access log writing from monitor into a new `internal/accesslog` package: log file creation, entry format (`<OP> <TARGET> <RESULT> <RULE>`), deduplication (`seen` map), infrastructure path filtering. Expose an `Entry` type and a `Logger` with `Log(Entry)` method.
- Thin `internal/config` to a JSON loader that splits raw rules by resource prefix and delegates to `fsrules.Parse()`.
- Thin `internal/monitor` to strace integration only — runs strace, parses output, maps syscalls, filters setup, resolves via fsrules, feeds entries to accesslog.
- Pure refactor — no behavioral change. All existing tests pass with equivalent coverage.

## Capabilities

### New Capabilities

- `fs-rules`: FS rule parsing, validation, and resolution — the self-contained rule engine extracted from config and rules packages.
- `access-log`: Access log writing, formatting, deduplication, and infrastructure filtering — the logging engine extracted from monitor.

### Modified Capabilities

- `config`: Thinned to JSON loading and rule routing. FS rule parsing and validation moves to `fs-rules`. Requirements unchanged — config still rejects invalid rules, duplicates, managed paths, and writable config file — but the responsibility shifts to `fsrules.Parse()`.
- `monitor`: Thinned to strace integration. Log writing, formatting, deduplication, and infrastructure filtering move to `access-log`. Requirements unchanged — monitor still produces the same log output — but delegates to `accesslog.Logger`.
- `sandbox`: "Most specific rule wins" requirement moves to `fs-rules` — it defines rule resolution semantics (longest matching prefix), which belongs with the rule engine rather than sandbox mount mechanics.

## Impact

- **Code:** `internal/rules/` removed (absorbed into `internal/fsrules/`). `internal/config/` and `internal/monitor/` significantly thinned. New packages `internal/fsrules/` and `internal/accesslog/` created.
- **Tests:** Existing tests migrated to new packages. No test behavior changes.
- **APIs:** Internal package boundaries shift. No public API or CLI changes. No config format changes. No behavioral changes.
- **Security:** Rule resolution logic is moved, not rewritten. The trust boundary (config → rules → sandbox) is preserved. The refactor must not alter rule matching, path normalization, symlink resolution, or validation behavior.

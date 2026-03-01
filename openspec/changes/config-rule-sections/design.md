## Context

The config file currently uses a flat `rules = [...]` array where every entry is prefixed with its resource type (`fs:`, `net:`, `syscall:`). As rule lists grow, the repeated prefixes add visual noise and make it harder to scan rules by category. The fix uses top-level typed array keys (`fs = [...]`, `net = [...]`, `syscall = [...]`) so the type is implicit from the key name. This is purely a config surface change; the internal `ParseRules` API (prefixed strings) remains unchanged.

## Goals / Non-Goals

**Goals:**
- Replace the flat `rules` array with top-level `fs`, `net`, `syscall` array keys in `ParseTOML`/`Load`
- Drop the resource-type prefix from rule strings within each section
- Keep all validation behavior identical (error messages may differ slightly where they reference rule index)
- Update `execave.toml.example`, README, docs, and all tests

**Non-Goals:**
- Changing `ParseRules` (the in-memory API) — it keeps prefixed strings and is used internally and by tests
- Supporting both old and new formats simultaneously (no migration compat layer; no existing configs to migrate)
- Adding structured sub-keys per action type (e.g., `fs.ro = [...]`) — flat rule array per key only

## Decisions

### Decision: `ParseRules` keeps prefixed strings; only `ParseTOML` changes

`ParseTOML` reads three separate arrays from the `fs`, `net`, and `syscall` top-level keys, prepends the resource-type prefix to each string, and passes the combined slice to `ParseRules`. All validation logic stays unchanged and centralised in `ParseRules`.

Alternative considered: extend `ParseRules` to accept typed slices. Rejected — `ParseRules` is the sandbox test API and cross-cutting; changing its signature ripples widely with no benefit.

### Decision: Top-level array keys (not TOML sections)

```toml
fs      = ["ro:/usr", "rw:."]
net     = ["http:api.example.com:443"]
syscall = ["allow:ptrace"]
```

Top-level key-value pairs keep the config flat and minimal. TOML sections (`[fs]` with a nested `rules` key) were considered but are more verbose with no benefit — there are no other keys to add under each type.

### Decision: All three keys are optional

An absent key means "no rules of that type". An empty file is valid and produces an empty config. This is consistent with the existing behaviour of `rules = []`.

### Decision: Error messages reference combined rule index

`ParseTOML` reconstructs a flat prefixed slice (fs rules first, then net, then syscall) and passes it to `ParseRules`, so error messages say `rule N: ...` (indexing within the combined slice). This is acceptable; exact wording is not a public API contract.

Alternative: per-key error context (`in fs rule 2: ...`). Deferred — can be done independently.

### Decision: No backward compatibility shim

There are no existing user configs to migrate. A shim would add permanent parsing complexity for no benefit.

## Risks / Trade-offs

- [Risk] Tests that assert `"unknown resource type"` error text break, because the new format no longer routes by prefix in `ParseTOML`. → Mitigation: update those tests to assert on the actual error the new code produces or remove them if the scenario no longer applies. The `ParseRules` API still rejects unknown prefixes, so tests going through `ParseRules` directly are unaffected.
- [Risk] `RawRule` fields on parsed rules will read `fs:ro:/usr` (reconstructed prefixed form) not `ro:/usr`. This is fine — `RawRule` is used for error messages and access log entries, and the prefixed form is what callers already expect. → No mitigation needed.
- [Risk] Fuzz corpus seeds reference the old `rules = [...]` format. → Mitigation: update seed strings in `config_fuzz_test.go`.

## Migration Plan

1. Update `ParseTOML` to unmarshal `fs`, `net`, `syscall` as top-level array keys, reconstruct prefixed slices, delegate to `ParseRules`.
2. Update all TOML literal strings in tests (`config_test.go`, `integration_test.go`, `config_fuzz_test.go`).
3. Update `test/e2e/helpers_test.go` `tomlConfig()` helper to emit the new flat key format.
4. Update hardcoded TOML strings in `test/e2e/configuring_execave_test.go`.
5. Update `execave.toml.example`, `README.md`, `docs/architecture.md`.
6. Run `go test ./...` to confirm all tests pass.

No rollback required (no existing configs).

## Open Questions

None.

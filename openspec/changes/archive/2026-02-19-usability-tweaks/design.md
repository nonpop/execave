## Context

The config format is plain JSON, which doesn't support comments. Paths in rules must be written as full absolute paths. The access log in the web UI displays raw absolute paths, making it harder to scan than necessary.

Three independent changes address this:
1. TOML replaces JSON as the config format.
2. Tilde (`~`) expansion lets users write `~/project` instead of `/home/user/project` in rules.
3. The web UI shortens access log target paths relative to the config directory or home directory.

## Goals / Non-Goals

**Goals:**
- Config files support comments and trailing commas (TOML).
- `~/...` is valid in filesystem rule paths and expands to the user's home directory.
- Web UI target column shows the shortest intelligible path (relative or `~/...`).
- Rules in the log are shown verbatim from the config (`RawRule`).

**Non-Goals:**
- `~username` expansion (other users' home directories).
- Environment variable expansion in paths (future).
- Wildcards in paths.
- Programmatic config format migration tooling.
- Changing the rule string syntax itself (`fs:rw:...` unchanged).
- Path shortening outside the web UI (e.g., CLI stderr output).

## Decisions

### 1. TOML format with `BurntSushi/toml`

**Decision:** Replace `encoding/json` with `github.com/BurntSushi/toml` in `config.Load`. The config struct stays identical — only the parser changes. Rule strings are unchanged (`"fs:rw:~/project"` etc.). Default config filename changes from `execave.json` to `execave.toml`.

**Rationale:** TOML has a versioned spec (v1.0.0), native comment syntax, and broad editor support. `BurntSushi/toml` is the de facto standard Go TOML library — stable, well-maintained, v1.0.0 compliant.

**Alternatives considered:**
- *JSONC*: No formal spec; editor support is fragile; VS Code treats it specially but other tools don't.
- *JSON5*: Formal spec, but editor support worse than JSONC; adds irrelevant features (hex literals, NaN).
- *JSON + external comment stripper*: Works but adds a hand-rolled or fragile pre-processing step.

**Security impact:** TOML parsing replaces JSON parsing at the config trust boundary. The rule string format is unchanged, so all downstream validation (path normalization, permission checks, managed-path guards) is unaffected. TOML is stricter than JSON in some ways (no duplicate keys by default), which reduces misconfiguration risk. The `BurntSushi/toml` library does not execute arbitrary code during parsing.

**Breaking change:** Existing `.json` configs must be converted. The change is mechanical: rename the file, add `rules = ` before the array, remove outer `{}`, convert to TOML array syntax. No tool is provided — the format is simple enough that a comment in the error message or README suffices.

### 2. Tilde expansion in `normalizePath`

**Decision:** In `fsrules.normalizePath`, expand a leading `~/` to `os.UserHomeDir() + "/"` before the existing relative-path and `filepath.Clean` logic. A bare `~` (without slash) also expands to `os.UserHomeDir()`. `~username` (tilde followed by a non-slash character) is rejected with an explicit parse error.

```
~/project   → /home/user/project   (expanded, then cleaned)
~           → /home/user           (expanded, then cleaned)
~user/foo   → parse error          (~username not supported)
./src       → configDir/src        (unchanged)
/abs/path   → /abs/path            (unchanged)
```

**Rationale:** Expansion at parse time means `Rule.Path` is always an absolute path. The rest of the pipeline (resolver, sandbox, validation) is completely unchanged. `RawRule` preserves the original `~/...` string for display.

If `os.UserHomeDir()` fails (no `$HOME`, no passwd entry), `Parse` returns an error — fail-safe. We do not silently fall back to a relative path.

**Security impact:** Tilde expansion is equivalent to the user writing the absolute path explicitly. It does not expand the access surface beyond what the user intended. The expanded path goes through the same `filepath.Clean` + managed-path + duplicate + config-writability validation as any other path. No new trust boundary.

**`~username` not supported:** Resolving another user's home requires parsing `/etc/passwd` or calling `user.Lookup`, adding complexity for a rare case. Rejected at parse time with a clear error rather than silently treating it as a relative path.

### 3. Path shortening in the web UI

**Decision:** Add a `shortenPath(absPath, homeDir, configDir string) string` function (in the `webui` package, unexported). Apply it to `Entry.Target` when rendering both the initial HTML page and SSE entry events. Store canonical absolute paths throughout — shortening is display-only.

**Shortening algorithm (strict priority):**

```
if absPath is under configDir:
    return filepath.Rel(configDir, absPath)   // e.g., "src/main.go"

if absPath is under homeDir:
    return "~/" + rel-to-homeDir              // e.g., "~/.ssh/id_rsa"

return absPath
```

Priority order ensures the most context-specific form wins. When a path is under both configDir and homeDir, the configDir-relative form is always shorter (configDir is deeper), so priority and shortest-wins produce the same result.

**Where it lives:** `internal/webui` — it's a presentation concern. The `Server` receives `homeDir` and `configDir` at construction time (from `main`). The access log and monitor packages are untouched.

**Why store canonical and display short, not vice versa:**
- Deduplication in the access log keys on `(operation, target, result)` — absolute paths keep this unambiguous regardless of which config was active.
- A future "show full paths" toggle is trivial: skip `shortenPath`.
- The monitor and proxy produce absolute paths from strace/proxy events; transforming them before storage would require threading display config into non-display code.

**Rendering two paths (HTML template + SSE JSON):** Both code paths call `shortenPath`. The HTML template uses a template function; the SSE JSON marshals the shortened form in the entry DTO.

**Security impact:** Display-only. No effect on rule resolution, sandbox construction, or access decisions. The underlying `Entry.Target` remains the canonical path — shortening cannot mask a path that shouldn't be accessed.

## Risks / Trade-offs

**Breaking config format change** → Mitigation: The format is simple (one array of strings); conversion is mechanical. Update README and error message for `execave.toml` not found. No tooling needed.

**`os.UserHomeDir()` unavailable** → `Parse` returns an error for any `~/...` path. Fail-safe: the sandbox doesn't start with an unresolved path. No silent fallback.

**Path shortening masks the true accessed path** → The shortened path is always unambiguous within the context of `homeDir`/`configDir`. The title attribute or a "show full" toggle can expose the absolute path later if needed. The underlying log entry is unmodified.

**TOML parse errors differ from JSON parse errors** → Error messages will change slightly in wording. Not a correctness concern.

## Migration Plan

1. Add `BurntSushi/toml` dependency.
2. Update `config.Load` to parse TOML.
3. Update default config path constant in `cmd/execave/main.go` to `execave.toml`.
4. Update all test helpers to write `.toml` configs.
5. Update `README.md` and `docs/architecture.md`.
6. Update `openspec/config.yaml` context.

Rollback: revert the `config.Load` change. No data migration — config files are user-managed.

## Open Questions

None. All decisions resolved during exploration.

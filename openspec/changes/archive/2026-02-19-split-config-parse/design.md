## Context

`config.Load` reads a TOML file, parses raw rule strings via `parseRules` (which dispatches to `fsrules.Parse` and `netrules.Parse`), validates cross-rule constraints (`fsrules.Validate`, `netrules.Validate`), and assembles a `*Config`. All of this is one function that requires a file path.

The web UI config editor (planned) needs to parse and validate user-edited rule strings from memory. The same parsing and validation logic must apply — no separate code path that could drift.

## Goals / Non-Goals

**Goals:**
- Export the parse+validate logic so callers can go from `[]string` → `*Config` without file I/O.
- `Load` delegates to the new function — single code path for all config parsing.
- Same validation guarantees (duplicate detection, managed path rejection, config writability) regardless of entry point.

**Non-Goals:**
- Separating parse errors from validation errors (field-level error reporting for the UI). Can be done later by splitting further.
- Config serialization (writing Config back to TOML). That's save semantics, a separate change.
- Draft state management in the web UI. This change only provides the building block.

## Decisions

### Extract `ParseRules` as the non-I/O entry point

```go
func ParseRules(rawRules []string, configDir, configPath string, managedPaths []string) (*Config, error)
```

**Why this signature:**
- `rawRules` — the rule strings, decoupled from TOML format.
- `configDir` — needed by `fsrules.Parse` for tilde expansion and relative path resolution.
- `configPath` — needed by `fsrules.Validate` for the "config not writable" check.
- `managedPaths` — needed by `fsrules.Validate` for managed path rejection.

**Why combine parse+validate in one function:** The web UI plan says "if invalid, block Run and Save" — callers always want both steps. A single function is the simple, obvious API. If field-level errors are needed later, we can split `ParseRules` into `Parse` + `Validate` without changing the `Load` → `ParseRules` delegation.

**Alternative considered:** Exporting `parseRules` alone (just parsing, no validation). Rejected because every caller would need to remember to call both `fsrules.Validate` and `netrules.Validate` separately — easy to miss one, creating a security gap.

### `Load` becomes a thin wrapper

```go
func Load(path string, managedPaths []string) (*Config, error) {
    // read file, unmarshal TOML, extract raw.Rules
    // compute absPath, configDir
    return ParseRules(raw.Rules, configDir, absPath, managedPaths)
}
```

No behavior change. Error messages from `Load` continue to include the file path for context; `ParseRules` errors do not (they don't know the file path).

## Risks / Trade-offs

**[Risk] Error messages differ slightly between `Load` and `ParseRules`** → `Load` wraps errors with file path context (`"parse rules in %s: ..."`). `ParseRules` returns bare parsing/validation errors. This is correct — callers of `ParseRules` (web UI) should add their own context. No mitigation needed.

**[Risk] `configPath` parameter could be confusing — is it needed for parsing or validation?** → It's only used for the "config not writable" validation check. The godoc will clarify this. Considered making it optional (empty string skips the check), but that creates a security gap — callers might accidentally skip it. Keeping it required is fail-safe.

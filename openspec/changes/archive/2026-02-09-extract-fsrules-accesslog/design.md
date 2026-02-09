## Context

The codebase currently has four internal packages with these responsibilities:

- **config**: JSON loading, FS rule parsing (`parseRule`, `normalizePath`), FS-specific validation (duplicates, managed paths, config-not-writable), type definitions (`Rule`, `Permission`, `Resource`).
- **rules**: FS rule resolution (`CheckAccess`, `PermissionFor`, `findMatchingRule`, `matchesPath`), symlink resolution (`resolvePathComponents`), rule boundary detection, managed path detection.
- **monitor**: strace execution, strace output parsing, syscall-to-operation mapping, access log writing (`writeLogEntry`), deduplication (`seen` map, `alreadyLogged`), infrastructure path filtering (`isManagedPath`), symlink chain log formatting, non-existent path filtering.
- **sandbox**: bwrap argument construction, managed dirs definition (`ManagedDirs`), mount ordering, config file protection.

The upcoming network isolation feature needs `netrules` (parallel to FS rules) and a shared access log (both strace-derived FS events and proxy-derived network events). The current structure forces either duplication or tangled dependencies.

### Current dependency graph

```
cmd/execave/main.go → config, rules, sandbox, monitor
sandbox             → config, rules
monitor             → config, rules, sandbox
rules               → config
```

Monitor depends on sandbox only for `ManagedDirs`. This is the only cross-dependency between the two execution-path packages.

## Goals / Non-Goals

**Goals:**

- Extract `internal/fsrules` from `config` + `rules`: self-contained FS rule engine with parsing, validation, and resolution.
- Extract `internal/accesslog` from `monitor`: reusable log writer with formatting, deduplication, and infrastructure filtering.
- Thin `config` to JSON loading + rule routing.
- Thin `monitor` to strace integration only.
- Zero behavioral changes. All existing tests pass. No config format changes. No CLI changes.

**Non-Goals:**

- Adding network rule support (separate change).
- Changing the access log format.
- Refactoring sandbox or CLI wiring.
- Changing the strace parsing logic.

## Decisions

### Decision 1: fsrules absorbs rules entirely, takes FS-specific logic from config

**What moves where:**

From `config` → `fsrules`:
- `parseRule` (renamed from FS-specific to the package's `Parse` entrypoint)
- `normalizePath`
- `Rule`, `Permission`, `Resource` types
- `validateNoDuplicates`, `validateConfigNotWritable`, `validateNoManagedPaths`

From `rules` → `fsrules`:
- `Resolver` (entire struct and all methods)
- `CheckAccess`, `PermissionFor`, `findMatchingRule`, `matchesPath`
- `resolvePathComponents`, `isRuleBoundary`, `isUnresolvablePath`
- `Operation`, `AccessResult`, `SymlinkChain`, `SymlinkHop`
- `export_test.go` (`MatchesPath`)

The `internal/rules` package is deleted. The `internal/config` package keeps `Load`, the JSON struct, and a `Config` type that holds `[]fsrules.Rule` instead of `[]Rule`. Config's `Load` splits raw rule strings by resource prefix (`fs:` → `fsrules.Parse()`), and returns errors for unknown prefixes.

**Why not keep rules as a separate package?** The rules package exists solely for FS rule resolution and depends entirely on config types. Merging into fsrules eliminates a package boundary with no independent purpose. When netrules arrives, it will be a parallel package — `fsrules` and `netrules` with no dependency between them.

**Alternative: Keep types in config, move only parsing.** Rejected because the types (`Rule`, `Permission`, `Resource`) are FS-specific. When network rules arrive, config would need `NetRule`, `Protocol`, etc. Better to co-locate types with their domain.

### Decision 2: Config becomes a thin router

After extraction, `config.Load` does:
1. Read JSON, unmarshal `{"rules": [...]}`.
2. Resolve config dir for relative paths.
3. For each raw rule string, split on first `:` to get resource prefix.
4. Route `fs:` rules to `fsrules.Parse(rawRule, configDir)`.
5. Reject unknown prefixes (currently only `fs:` is valid — unchanged behavior).
6. Call `fsrules.Validate(rules, configPath, managedPaths)` for FS-specific cross-rule validation.
7. Return `Config{FSRules: []fsrules.Rule, ManagedPaths: []string}`.

The `Config` struct changes from `Rules []Rule` to `FSRules []fsrules.Rule`. This is an internal API change — callers in `cmd/execave/main.go`, `sandbox`, and `monitor` update accordingly.

**Why separate Parse and Validate?** Parsing is per-rule (syntax, normalization). Validation is cross-rule (duplicates, managed paths, config-not-writable). Config needs to call validation after collecting all parsed rules.

### Decision 3: accesslog extracts log writing, dedup, and filtering from monitor

**What moves to `accesslog`:**

- `OperationType` (READ, WRITE) and `ResultType` (OK, DENY, UNKNOWN) type definitions
- Rule-reason constants (`RuleNoMatch`, `RuleUnresolvedRelativePath`, `RuleSymlinkTargetUnresolvable`, `RuleSymlinkDepthExceeded`)
- `writeLogEntry` (formatting: `<OP> <TARGET> <RESULT> <RULE>`)
- `accessKey` struct, `seen` map, `alreadyLogged` deduplication logic
- `isManagedPath` infrastructure filtering
- Log file creation (`os.Create`)

**What stays in `monitor`:**

- `Monitor` struct (strace execution, bwrap args)
- `Run`, `buildStraceArgs`, `executeStrace`, `createStraceOutputFile`
- `processStraceOutput`, `processAccessEntry` (strace parsing loop, syscall dispatch)
- `handleRelativePath`, `handleSymlinkChain`, `handleDepthLimitExceeded`, `handleUncertainResult` — these orchestrate which entries to emit but call accesslog for the actual writing
- Non-existent path filtering for reads (via resolver's `PathNotFound` field)
- `straceParser`, `mapSyscallToOperation`, `classifyOpenOperation`, syscall maps
- `OperationIgnored` (strace-specific, not a log operation)

**The accesslog.Logger interface:**

```go
type Logger struct {
    writer  *bufio.Writer
    seen    map[accessKey]bool
    managed []string  // managed path prefixes for filtering
}

func (l *Logger) Log(entry Entry) error  // dedup + filter + write
```

`Entry` holds `{Operation, Path, Result, Rule}`. Monitor constructs entries and calls `Logger.Log()`. The logger handles dedup, managed path filtering, and formatting.

**Why not make Logger an interface?** Only one implementation exists. An interface would add indirection without value. If the proxy needs different behavior, it can use a different method or the proxy can construct entries differently.

**Alternative: Keep log writing in monitor, just extract types.** Rejected because the proxy also needs to write access log entries with the same format, dedup, and file. Duplication is worse than extraction.

### Decision 4: ManagedDirs stays in sandbox, accesslog receives it as a parameter

`ManagedDirs` is defined in `sandbox` because sandbox is the authority on which paths it manages (mounts `/dev`, `/proc`, `/tmp`, handles `/newroot`, `/oldroot`). Moving it to accesslog or fsrules would invert this authority.

Instead, `accesslog.New()` accepts a `managedPaths []string` parameter. The CLI passes `sandbox.ManagedDirs` when constructing the logger, same as it passes them to `config.Load` today. This breaks monitor's current direct dependency on sandbox.

### Decision 5: Symlink chain log orchestration stays in monitor

The `handleSymlinkChain`, `handleDepthLimitExceeded`, and `handleUncertainResult` methods decide *which* entries to emit (each hop as READ, then target with original operation). This is FS-specific orchestration tied to how the resolver reports symlinks. It stays in monitor and calls `Logger.Log()` for each entry.

The accesslog package does not know about symlinks. It receives flat entries.

## Risks / Trade-offs

**[Risk] Behavioral regression in rule matching or validation during move.**
Mitigation: All existing tests are migrated to the new packages. Run `go test ./...` at each step. The refactor is mechanical — functions move, import paths change, but logic is identical.

**[Risk] Config struct field rename (`Rules` → `FSRules`) breaks callers.**
Mitigation: Compile-time breakage — all callers are internal and updated in the same change. No runtime risk.

**[Risk] Monitor's access entry logic becomes harder to follow across two packages.**
Mitigation: Clear responsibility split — monitor decides *what* to log (which entries, which operation type), accesslog handles *how* to log (format, dedup, filter). The boundary is at `Logger.Log(entry)`.

**[Trade-off] Two new packages for a refactor that doesn't add features.**
Accepted: the extraction is prerequisite for network isolation. Without it, netrules and the proxy would either duplicate FS-specific code or create circular dependencies.

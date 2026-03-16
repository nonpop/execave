## Context

Execave currently requires a TOML config file for all invocations. Rules are loaded via `config.Load`, which reads a config graph (root file + extends chain), parses rules, merges, validates, and injects synthetic rules. The CLI layer (`cmd/execave/commands/`) defines `--config` as a global persistent flag and passes it to `run.LoadRuntimeConfig`.

The `config.Config` struct carries `ConfigPaths []string` for provenance tracking. Each rule has a `SourcePath` field — file path for file-sourced rules, empty string for synthetic rules. `RenderEffectiveTOML` groups rules by source and renders `<synthetic>` for empty-string sources.

## Goals / Non-Goals

**Goals:**
- Add repeatable CLI flags (`--fs`, `--net`, `--syscall`, `--env`, `--extends`) for all rule sections
- Add `--no-config` flag to skip config file loading
- CLI flags work with `run` (implicit and explicit), `monitor`, and `config show`
- CLI rules participate in existing merge/validate pipeline with no special-case validation
- CLI-sourced rules render with `<cli>` provenance in `config show`

**Non-Goals:**
- Changing the config file format
- Changing the default config path (`./execave.toml`)
- Adding rule override/priority semantics (conflicts remain errors)

## Decisions

### Decision: Virtual `<cli>` config model

CLI flags are assembled into a virtual `rawConfig` struct, as if the user wrote a TOML file. The config file (if present) is an implicit extends entry in this virtual config.

```
Virtual <cli> rawConfig:
  extends = [<--extends entries...>, <config file if not --no-config>]
  fs      = [<--fs values>]
  net     = [<--net values>]
  syscall = [<--syscall values>]
  env     = [<--env values>]
```

**Why over alternatives:**
- Reuses the entire existing pipeline (readConfigGraph → buildConfig → mergeConfigs → validate)
- No new code paths for validation or merge — CLI rules go through the same checks as file rules
- The extends ordering is natural: bases load first (depth-first), then CLI rules layer on top
- Conflicts between CLI and file rules are caught by the same duplicate-path/identity validators

**Implementation:** A new `config.LoadWithCLI(cliRules CLIRules, managedPaths []string, ...)` function constructs the virtual rawConfig and feeds it into the existing pipeline. `config.Load` remains for backwards compatibility but can delegate to `LoadWithCLI` internally.

### Decision: CLI FS rule path resolution uses cwd as configDir

File-sourced FS rules resolve relative paths against the config file's directory. CLI-sourced FS rules use the current working directory, since there is no config file to be relative to.

**Implementation:** `buildConfig` already accepts a `configDir` parameter. For the virtual `<cli>` config, pass `cwd` (from `os.Getwd()`).

### Decision: SourcePath sentinels as named constants

The existing convention uses `SourcePath = ""` for synthetic rules and checks for empty string in rendering. This change replaces that with explicit named constants in the `config` package:

```go
const (
    SourceCLI       = "<cli>"
    SourceSynthetic = "<synthetic>"
)
```

Both use angle brackets, which cannot appear in valid file paths. All existing code that compares `SourcePath` against `""` or sets it to `""` is updated to use `SourceSynthetic`. CLI-parsed rules use `SourceCLI`.

In `RenderEffectiveTOML`, `orderedSourcePaths` and `appendSection` use the constants instead of hardcoded empty-string checks. The rendering order is: file paths → `SourceCLI` → `SourceSynthetic`.

Both sentinel values are added to `Config.ConfigPaths` only when rules with that source exist, so `orderedSourcePaths` includes them in the ordering.

### Decision: --no-config is a boolean flag, mutually exclusive with --config

`--no-config` is a `BoolVar` persistent flag on the root command. Validation in the command's `PersistentPreRunE` checks:
- If `--no-config` is set and `--config` was explicitly changed from its default → error
- If neither `--no-config` is set nor `--config` is explicitly provided → use default config path (`./execave.toml`)

**Why `PersistentPreRunE`:** The mutual exclusion check must run before any subcommand handler. Cobra's persistent pre-run hooks propagate to subcommands.

### Decision: CLI rule flags are global persistent flags

`--fs`, `--net`, `--syscall`, `--env`, and `--extends` are `StringArrayVar` persistent flags on the root command (same as `--config`). This makes them available to all subcommands: `run`, implicit run, `monitor`, and `config show`.

**Why `StringArrayVar` over `StringSliceVar`:** `StringArrayVar` treats each flag occurrence as one value. `StringSliceVar` splits on commas, which could cause issues if rule values ever contain commas and is less explicit.

### Decision: SandboxConfig carries CLI rules

`run.SandboxConfig` gains a `CLIRules` field containing the raw string slices from CLI flags plus the `NoConfig` boolean. `LoadRuntimeConfig` uses these to call the appropriate `config.Load` variant.

```go
type CLIRules struct {
    FS      []string
    Net     []string
    Syscall []string
    Env     []string
    Extends []string
    NoConfig bool
}
```

### Decision: Config file protection with --no-config

When `--no-config` is used, there are no config file paths to protect from writability. The `appendForcedReadOnlyRules` function already iterates `Config.ConfigPaths` — with no config files in the list (only `<cli>`), it naturally skips the protection. Extended config files (via `--extends`) are still in `ConfigPaths` and still protected.

## Risks / Trade-offs

**[Risk] User forgets --no-config and gets "config not found" error when they intended CLI-only usage** → The error message should hint at `--no-config` when CLI rule flags are present but no config file is found. This is a UX improvement, not a correctness concern.

**[Risk] Flag pollution on help output** → Six new global flags. Acceptable given they map directly to TOML sections. Group them visually in help text if cobra supports it.

**[Trade-off] No rule override semantics** → A user cannot use CLI flags to "override" a file rule (e.g., widen `ro:/foo` to `rw:/foo`). This is intentional: conflicting rules are always errors. The user must edit the config file or use `--no-config` to change existing permissions. This keeps the security model simple and auditable.

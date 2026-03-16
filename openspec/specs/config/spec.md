# Config Capability

## Purpose

The config capability loads and parses the execave configuration file. It reads TOML, routes rules to the appropriate engine by resource prefix, and rejects unrecognized or malformed input at load time.

## Requirements

### Requirement: Config file location

`config.Load` SHALL accept an explicit file path. If the file does not exist, it SHALL return an error.

#### Scenario: Config file not found
- **WHEN** the config file does not exist at the given path
- **THEN** Load returns an error containing "config file not found"

### Requirement: Config file format

The config file SHALL be valid TOML with optional top-level array keys: `fs`, `net`, `syscall`, and `env` of strings. Rule strings within each section omit the resource-type prefix — the section determines the type. All four keys are optional; omitting a key means no rules of that type. Unknown or malformed rule bodies SHALL cause Load to return an error.

Within `fs`: `ro`, `rw`, `none` prefixes are access rules. Within `net`: `http`, `none` prefixes are access rules. Within `syscall`: `allow` is the only valid action. Within `env`: `pass` is the only valid action.

#### Scenario: Valid config with fs and net rules

- **WHEN** config contains:
  ```toml
  fs = ["ro:/usr/bin"]

  net = ["http:api.anthropic.com:443"]
  ```
- **THEN** Load returns a config with 1 FS rule and 1 net rule

#### Scenario: Empty config (no sections)

- **WHEN** config contains no `fs`, `net`, `syscall`, or `env` keys
- **THEN** Load returns a config with no FS rules and no net rules

#### Scenario: Invalid rule rejected at config load

- **WHEN** config contains:
  ```toml
  net = ["http:example.com"]
  ```
  (missing port segment)
- **THEN** Load returns an error containing "malformed rule"

#### Scenario: Config with comments

- **WHEN** config contains TOML line comments (`#`) and inline comments within the config
- **THEN** Load parses successfully, ignoring all comments

#### Scenario: Config with trailing comma

- **WHEN** config contains a `rules` array with a trailing comma after the last element
- **THEN** Load parses successfully

#### Scenario: fs:nolog rule rejected

- **WHEN** config contains:
  ```toml
  fs = ["nolog:/usr/bin"]
  ```
- **THEN** Load returns an error (unknown rule prefix)

#### Scenario: net:nolog rule rejected

- **WHEN** config contains:
  ```toml
  net = ["nolog:*.example.com:*"]
  ```
- **THEN** Load returns an error (unknown rule prefix)

#### Scenario: syscall:nolog rule rejected

- **WHEN** config contains:
  ```toml
  syscall = ["nolog:ptrace"]
  ```
- **THEN** Load returns an error (unknown action)

### Requirement: Env section in config file format

The config file SHALL accept an optional top-level `env` array of strings. Each string SHALL be parsed as an env rule. Unknown or malformed env rule bodies SHALL cause Load to return an error.

#### Scenario: Valid config with env rules

- **WHEN** config contains:
  ```toml
  env = ["pass:HOME", "pass:PATH"]
  ```
- **THEN** Load returns a config with 2 env rules

#### Scenario: Empty env section

- **WHEN** config contains:
  ```toml
  env = []
  ```
- **THEN** Load returns a config with no env rules

#### Scenario: Invalid env rule rejected at config load

- **WHEN** config contains:
  ```toml
  env = ["ro:HOME"]
  ```
- **THEN** Load returns an error containing "invalid action"

#### Scenario: Duplicate env rule rejected at config load

- **WHEN** config contains:
  ```toml
  env = ["pass:HOME", "pass:HOME"]
  ```
- **THEN** Load returns an error containing "duplicate env rule"

### Requirement: ParseTOML includes env section

`ParseTOML` SHALL unmarshal and validate the `env` key in addition to `fs`, `net`, and `syscall`.

#### Scenario: Valid env rules parsed from bytes

- **WHEN** ParseTOML is called with bytes containing:
  ```toml
  env = ["pass:HOME"]
  ```
- **THEN** it returns a Config with 1 env rule

### Requirement: Parse TOML from bytes

`config.ParseTOML` SHALL accept raw TOML bytes, a configDir, a configPath, and managedPaths, and return a validated `*Config`. It SHALL unmarshal the `rules` array and apply all validation that `Load` applies. `Load` SHALL delegate to `ParseTOML` internally, so that `Load` and `ParseTOML` produce identical results for the same input.

#### Scenario: Valid TOML parsed from bytes

- **WHEN** ParseTOML is called with bytes containing:
  ```toml
  rules = ["fs:ro:/usr/bin", "net:http:example.com:443"]
  ```
  a valid configDir, an absolute configPath, and nil managedPaths
- **THEN** it returns a Config with 1 FS rule and 1 net rule

#### Scenario: Empty TOML produces empty Config

- **WHEN** ParseTOML is called with empty bytes
- **THEN** it returns a Config with no FS rules and no net rules

#### Scenario: Invalid TOML rejected

- **WHEN** ParseTOML is called with bytes that are not valid TOML
- **THEN** it returns an error

#### Scenario: Invalid rule rejected via ParseTOML

- **WHEN** ParseTOML is called with bytes containing:
  ```toml
  rules = ["net:http:example.com"]
  ```
  (missing port segment)
- **THEN** it returns an error containing "malformed rule"

#### Scenario: ParseTOML produces identical result to Load

- **WHEN** a TOML file contains a `rules` array with `fs:` and `net:` rules
- **AND** Load is called with that file path and managedPaths
- **AND** ParseTOML is called with the file's bytes, the file's directory, the absolute file path, and the same managedPaths
- **THEN** both return equivalent Config structs (same FSRules, NetRules, and ManagedPaths)

#### Scenario: TOML with comments parsed from bytes

- **WHEN** ParseTOML is called with bytes containing TOML comments within the sections
- **THEN** it returns a Config successfully (comments are ignored)

### Requirement: Effective config rendering
The config capability SHALL provide effective merged config rendering through `execave config show`, using the same layered load, deduplication, and validation path as command execution.

#### Scenario: Show effective config from default path
- **WHEN** the user runs `execave config show`
- **THEN** execave prints TOML representing the effective merged config loaded from `./execave.toml`

#### Scenario: Show effective config from custom path
- **WHEN** the user runs `execave --config /home/user/project/execave.toml config show`
- **THEN** execave prints TOML representing the effective merged config loaded from `/home/user/project/execave.toml`

### Requirement: Effective config output format and provenance
Effective config output SHALL be TOML with typed sections (`fs`, `net`, `syscall`, `env`) and SHALL include source-path provenance as comment lines for emitted rules. CLI-sourced rules SHALL render with `# <cli>` provenance. The rendering order SHALL be: file-sourced rules in config-path order, then CLI-sourced rules, then synthetic rules.

#### Scenario: Output contains typed sections
- **WHEN** `config show` succeeds
- **THEN** stdout contains TOML arrays for configured sections (`fs`, `net`, `syscall`, and/or `env`) using rule bodies consistent with current config format

#### Scenario: Output includes source comments for each emitted rule
- **WHEN** `config show` emits a rule originating from layered config files
- **THEN** the emitted TOML includes one or more comment lines indicating source file path provenance adjacent to that rule

#### Scenario: CLI-sourced rules render with cli provenance
- **WHEN** `config show` emits a rule originating from CLI flags
- **THEN** the emitted TOML includes a `# <cli>` comment line adjacent to that rule

#### Scenario: CLI rules render after file rules
- **WHEN** `config show` renders rules from both a config file and CLI flags
- **THEN** file-sourced rules appear before CLI-sourced rules within each section

### Requirement: Config file composition via extends

The config file format SHALL support an optional top-level `extends` array of strings. Each string SHALL reference another config file to compose into the current config.

`extends` path resolution SHALL follow filesystem rule path semantics:
- absolute paths MUST be used as-is
- relative paths MUST be resolved against the directory of the file that declares the `extends` entry
- `~` prefixes MUST expand to the current user's home directory

The loader SHALL resolve `extends` recursively and MUST reject cyclic references.

#### Scenario: Root config composes rules from parent config
- **WHEN** `Load` is called on a config file that contains `extends = ["/path/base.toml"]` and both files are valid
- **THEN** the returned `Config` contains rules from both files

#### Scenario: Relative extends path resolves against declaring file directory
- **WHEN** `Load` is called on `/work/project/execave.toml` containing `extends = ["../base.toml"]`
- **THEN** the loader resolves the reference to `/work/base.toml`

#### Scenario: Tilde extends path resolves to user home
- **WHEN** `Load` is called on a config containing `extends = ["~/.config/listree/common.toml"]`
- **THEN** the loader resolves the reference under the current user's home directory

#### Scenario: Cyclic extends chain is rejected
- **WHEN** `Load` is called on a config graph where `a.toml` extends `b.toml` and `b.toml` extends `a.toml`
- **THEN** `Load` returns an error indicating an `extends` cycle

### Requirement: Layered merge and validation model

For layered config composition, validation MUST be performed in two phases:
1. Each loaded file SHALL be validated independently using the same single-file validation rules.
2. The merged rule set SHALL be formed by union of all rules, removing only exact duplicate rules, and then validated again using the same validators as a single config file.

The merged validation result SHALL be order-independent with respect to `extends` entry order.

#### Scenario: Exact duplicate rules across files are accepted
- **WHEN** two composed config files contain the exact same rule string
- **THEN** `Load` succeeds and the merged policy contains one effective copy of that rule

#### Scenario: Contradictory filesystem rules across files are rejected
- **WHEN** composed configs include `fs = ["ro:/foo"]` in one file and `fs = ["rw:/foo"]` in another
- **THEN** `Load` returns a validation error for duplicate/conflicting path policy

#### Scenario: Contradictory network rules across files are rejected
- **WHEN** composed configs include `net = ["http:example.com:443"]` in one file and `net = ["none:example.com:443"]` in another
- **THEN** `Load` returns a validation error for conflicting net rule identity

#### Scenario: Extends order does not change the outcome
- **WHEN** `Load` is called for two root configs that reference the same parent files in different `extends` order
- **THEN** both loads produce equivalent success/failure outcomes under merged validation

### Requirement: Source-aware layered validation errors

For validation failures detected after layered merge, error messages SHALL identify the conflicting rules and the source config file path for each conflicting rule.

#### Scenario: Cross-file fs conflict includes both source files
- **WHEN** layered merge detects a filesystem conflict between rules from `/path/base.toml` and `/path/execave.toml`
- **THEN** the returned error includes both file paths and both conflicting rule strings

#### Scenario: Cross-file net conflict includes both source files
- **WHEN** layered merge detects a net identity conflict between rules from two different files
- **THEN** the returned error includes both file paths and both conflicting rule strings

### Requirement: All loaded config files are protected from explicit writability

Explicit writable filesystem rules targeting any loaded config file (root or extended parent) SHALL be rejected during validation.

#### Scenario: Parent config path explicitly writable is rejected
- **WHEN** a layered config set includes a rule that grants `rw` access to an extended parent config file path
- **THEN** `Load` returns an error indicating the config file must not be writable

#### Scenario: Root config path explicitly writable is rejected in layered mode
- **WHEN** a layered config set includes a rule that grants `rw` access to the root config file path
- **THEN** `Load` returns an error indicating the config file must not be writable

### Requirement: Syscall rule validation

Syscall rule names SHALL be validated against the ruleable subset of seccomp-blocked syscalls. Defense-in-depth syscalls (those the kernel already prevents inside the sandbox via init-namespace capability checks or removal) SHALL be rejected — they cannot be meaningfully allowed. Names not in the ruleable list SHALL be rejected at config parse time. This prevents typos, rejects names for syscalls that are not blocked, and rejects defense-in-depth syscalls that offer a false impression of configurability.

Duplicate syscall names within the same rule type (allow or nolog) SHALL be rejected. `syscall:allow:X` and `syscall:nolog:X` for the same name X SHALL be permitted (different rule namespaces).

#### Scenario: Valid syscall name accepted
- **WHEN** config contains rule `"syscall:allow:ptrace"`
- **THEN** Load returns a config with 1 syscall allow rule

#### Scenario: Invalid syscall name rejected
- **WHEN** config contains rule `"syscall:allow:ptraec"`
- **THEN** Load returns an error indicating the syscall name is not a ruleable syscall name

#### Scenario: Non-blocked syscall name rejected
- **WHEN** config contains rule `"syscall:allow:read"`
- **THEN** Load returns an error indicating the syscall name is not a ruleable syscall name

#### Scenario: Defense-in-depth syscall rejected
- **WHEN** config contains rule `"syscall:allow:syslog"` (a defense-in-depth syscall)
- **THEN** Load returns an error indicating the syscall name is not a ruleable syscall name

#### Scenario: Duplicate syscall allow rules rejected
- **WHEN** config contains rules `"syscall:allow:ptrace"` and `"syscall:allow:ptrace"`
- **THEN** Load returns an error indicating a duplicate syscall rule

#### Scenario: Duplicate syscall nolog rules rejected
- **WHEN** config contains rules `"syscall:nolog:ptrace"` and `"syscall:nolog:ptrace"`
- **THEN** Load returns an error indicating a duplicate syscall rule

#### Scenario: Same name in allow and nolog permitted
- **WHEN** config contains rules `"syscall:allow:ptrace"` and `"syscall:nolog:ptrace"`
- **THEN** Load returns a config with 1 syscall allow rule and 1 syscall nolog rule

### Requirement: Load config from CLI rules

`config.LoadWithCLI` SHALL accept CLI rule slices (fs, net, syscall, env, extends) and an optional config file path, and return a merged, validated `*Config`. CLI rules SHALL be assembled into a virtual config where the config file (if present) and `--extends` entries are the virtual config's extends chain, and CLI rule slices populate the corresponding sections. The loading order SHALL be: extends entries (depth-first), then config file, then CLI rules.

#### Scenario: CLI fs rule merged with config file rules

- **WHEN** LoadWithCLI is called with config file containing `fs = ["ro:/usr"]` and CLI fs rules `["rw:/tmp/work"]`
- **THEN** the returned Config contains both fs rules

#### Scenario: CLI net rule merged with config file rules

- **WHEN** LoadWithCLI is called with config file containing `net = ["http:api.example.com:443"]` and CLI net rules `["http:cdn.example.com:443"]`
- **THEN** the returned Config contains both net rules

#### Scenario: CLI syscall rule merged with config file rules

- **WHEN** LoadWithCLI is called with config file containing `syscall = ["allow:bpf"]` and CLI syscall rules `["allow:ptrace"]`
- **THEN** the returned Config contains both syscall rules

#### Scenario: CLI env rule merged with config file rules

- **WHEN** LoadWithCLI is called with config file containing `env = ["pass:HOME"]` and CLI env rules `["pass:EDITOR"]`
- **THEN** the returned Config contains both env rules

#### Scenario: CLI extends merged with config file

- **WHEN** LoadWithCLI is called with config file path and CLI extends `["base.toml"]`
- **THEN** the returned Config contains rules from base.toml, the config file, and CLI rules

#### Scenario: Duplicate rule across CLI and config file is deduplicated

- **WHEN** LoadWithCLI is called with config file containing `fs = ["ro:/usr"]` and CLI fs rules `["ro:/usr"]`
- **THEN** the returned Config contains one fs rule for `/usr`

#### Scenario: Conflicting fs rules across CLI and config file rejected

- **WHEN** LoadWithCLI is called with config file containing `fs = ["none:/secrets"]` and CLI fs rules `["rw:/secrets"]`
- **THEN** LoadWithCLI returns a validation error indicating duplicate path

#### Scenario: Conflicting net rules across CLI and config file rejected

- **WHEN** LoadWithCLI is called with config file containing `net = ["none:evil.com:443"]` and CLI net rules `["http:evil.com:443"]`
- **THEN** LoadWithCLI returns a validation error indicating duplicate net rule identity

#### Scenario: CLI-only mode with no config file

- **WHEN** LoadWithCLI is called with no config file path and CLI fs rules `["ro:/usr"]`
- **THEN** the returned Config contains only the CLI fs rule

#### Scenario: CLI-only mode with extends

- **WHEN** LoadWithCLI is called with no config file path, CLI extends `["base.toml"]`, and CLI fs rules `["rw:/project"]`
- **THEN** the returned Config contains rules from base.toml and the CLI fs rule

#### Scenario: Invalid CLI rule syntax rejected

- **WHEN** LoadWithCLI is called with CLI fs rules `["readonly:/usr"]`
- **THEN** LoadWithCLI returns a parse error

#### Scenario: Empty CLI rules with config file is equivalent to Load

- **WHEN** LoadWithCLI is called with a config file path and no CLI rules
- **THEN** the returned Config is equivalent to calling Load with the same config file

### Requirement: CLI rule SourcePath provenance

Rules parsed from CLI flags SHALL have `SourcePath` set to the sentinel value `"<cli>"`. This value SHALL be distinct from file paths (empty string is reserved for synthetic rules).

#### Scenario: CLI-sourced fs rule has cli source path

- **WHEN** LoadWithCLI is called with CLI fs rules `["ro:/usr"]`
- **THEN** the returned fs rule has SourcePath `"<cli>"`

#### Scenario: File-sourced rule retains file source path

- **WHEN** LoadWithCLI is called with a config file at `/home/user/execave.toml` containing `fs = ["ro:/usr"]` and no CLI fs rules
- **THEN** the returned fs rule has SourcePath `/home/user/execave.toml`

### Requirement: CLI rule path resolution

CLI-sourced filesystem rules SHALL resolve relative paths against the current working directory. Tilde expansion SHALL work the same as for file-sourced rules.

#### Scenario: Relative CLI fs path resolves against cwd

- **WHEN** LoadWithCLI is called from cwd `/home/user/project` with CLI fs rules `["rw:."]`
- **THEN** the returned fs rule has Path `/home/user/project`

#### Scenario: Tilde CLI fs path expands to home directory

- **WHEN** LoadWithCLI is called with CLI fs rules `["ro:~/docs"]` and user home is `/home/user`
- **THEN** the returned fs rule has Path `/home/user/docs`

### Requirement: CLI extends path resolution

CLI-sourced extends paths SHALL resolve relative paths against the current working directory. Tilde expansion SHALL work the same as for file-sourced extends.

#### Scenario: Relative CLI extends path resolves against cwd

- **WHEN** LoadWithCLI is called from cwd `/home/user/project` with CLI extends `["../base.toml"]`
- **THEN** the loader resolves the extends path to `/home/user/base.toml`

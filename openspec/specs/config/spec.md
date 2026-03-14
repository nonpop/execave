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

The config file SHALL be valid TOML containing a `rules` array of strings. Rules are routed by resource prefix: `fs:` rules are parsed by the FS rules engine, `net:` rules are parsed by the net rules engine, `syscall:` rules are parsed by the syscall rules engine. Within each prefix, the action/permission determines whether the rule is an access rule or a log rule: `fs:ro`, `fs:rw`, `fs:none` are access rules; `fs:log`, `fs:nolog` are log rules; `net:http`, `net:none` are access rules; `net:log`, `net:nolog` are log rules; `syscall:allow` are access rules; `syscall:nolog` are log rules. Unknown prefixes or malformed rules SHALL cause Load to return an error.

#### Scenario: Valid config with fs and net rules

- **WHEN** config contains:
  ```toml
  rules = ["fs:ro:/usr/bin", "net:http:api.anthropic.com:443"]
  ```
- **THEN** Load returns a config with 1 FS rule and 1 net rule

#### Scenario: Valid config with log rules

- **WHEN** config contains:
  ```toml
  rules = ["fs:ro:/usr/bin", "fs:nolog:/usr/bin", "net:http:api.example.com:443", "net:nolog:*.example.com:*"]
  ```
- **THEN** Load returns a config with 1 FS access rule, 1 FS log rule, 1 net access rule, and 1 net log rule

#### Scenario: Empty rules array

- **WHEN** config contains `rules = []`
- **THEN** Load returns a config with no FS rules, no net rules, no FS log rules, no net log rules, no syscall allow rules, and no syscall nolog rules

#### Scenario: Unknown resource type
- **WHEN** config contains rule `"dns:allow:example.com"`
- **THEN** Load returns an error containing "unknown resource type"

#### Scenario: Invalid rule rejected at config load
- **WHEN** config contains rule `"net:http:example.com"` (missing port segment)
- **THEN** Load returns an error containing "malformed rule"

#### Scenario: Config with comments
- **WHEN** config contains TOML line comments (`#`) and inline comments
- **THEN** Load parses successfully, ignoring all comments

#### Scenario: Config with trailing comma
- **WHEN** config contains a rules array with a trailing comma after the last element
- **THEN** Load parses successfully

#### Scenario: Valid config with syscall rules
- **WHEN** config contains:
  ```toml
  rules = ["fs:ro:/usr/lib", "syscall:allow:ptrace", "syscall:nolog:bpf"]
  ```
- **THEN** Load returns a config with 1 FS rule, 1 syscall allow rule, and 1 syscall nolog rule

#### Scenario: Unknown syscall action rejected
- **WHEN** config contains rule `"syscall:deny:ptrace"`
- **THEN** Load returns an error (only `allow` and `nolog` are valid syscall actions)

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
Effective config output SHALL be TOML with typed sections (`fs`, `net`, `syscall`) and SHALL include source-path provenance as comment lines for emitted rules.

#### Scenario: Output contains typed sections
- **WHEN** `config show` succeeds
- **THEN** stdout contains TOML arrays for configured sections (`fs`, `net`, and/or `syscall`) using rule bodies consistent with current config format

#### Scenario: Output includes source comments for each emitted rule
- **WHEN** `config show` emits a rule originating from layered config files
- **THEN** the emitted TOML includes one or more comment lines indicating source file path provenance adjacent to that rule

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

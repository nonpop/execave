## MODIFIED Requirements

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

## ADDED Requirements

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

## Why

The log/nolog visibility rule system (fs:log/nolog, net:log/nolog, syscall:nolog) adds significant implementation complexity across config parsing, rule resolution, fsrules, netrules, and the text log writer, while providing limited value: users can filter the displayed log output through simpler means. Removing it reduces the attack surface, simplifies the config format, and makes the codebase easier to audit.

## What Changes

- **BREAKING** Remove `fs:log:` and `fs:nolog:` rule syntax from config
- **BREAKING** Remove `net:log:` and `net:nolog:` rule syntax from config
- **BREAKING** Remove `syscall:nolog:` rule syntax from config
- **BREAKING** Remove `--show-nolog` flag from the `monitor` command
- Remove `internal/fsrules/logrules.go` and all log rule logic from fsrules package
- Remove `internal/netrules/logrules.go` and all log rule logic from netrules package
- Remove `internal/syscallrules/logrules.go` and syscall nolog logic
- Remove `IsNolog`/`showNolog` logic from `internal/accesslog` and `internal/textlog`
- Remove nolog-related filtering from `internal/logfilter`
- Remove nolog fields from Config struct and parsing from `internal/config`

## Playbooks

### New Playbooks
<!-- none -->

### Modified Playbooks
- `monitoring-access`: Remove all use cases describing fs:nolog, net:nolog usage and the `--show-nolog` flag

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `fs-rules`: Remove log rule syntax, ParseLogRule, ValidateLogRules, LogResolver requirements and scenarios
- `net-rules`: Remove log rule syntax, ParseLogRule, ValidateLogRules, LogResolver requirements and scenarios
- `config`: Remove fs:log/nolog and net:log/nolog and syscall:nolog from the rule syntax specification
- `text-log`: Remove showNolog filter, nolog filter requirements and scenarios, --show-nolog flag reference
- `commands`: Remove `--show-nolog` flag from monitor command spec

## Impact

- Config format: **breaking change** — existing configs using log/nolog rules will fail to load
- `internal/config`: Remove LogRules fields, nolog parsing, validateSyscallRules nolog path
- `internal/fsrules`: Delete `logrules.go` and all tests referencing log rules
- `internal/netrules`: Delete `logrules.go` and all tests referencing log rules
- `internal/syscallrules`: Delete `logrules.go` and related fuzz/unit tests
- `internal/accesslog`: Remove `IsNolog` method and nolog-related logic
- `internal/textlog`: Remove `showNolog` parameter and filtering logic
- `internal/logfilter`: Remove `IsNolog` function
- `cmd/execave/commands/monitor.go`: Remove `--show-nolog` flag
- E2E tests referencing nolog use cases must be removed

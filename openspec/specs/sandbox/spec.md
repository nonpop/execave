# Sandbox Capability

## Purpose

The sandbox capability constructs bwrap arguments for secure process and network isolation. It translates filesystem and network rules into bwrap mount flags and command wrapping, enforcing a default-deny security model.

## Requirements

### Requirement: Default-deny filesystem

BuildBwrapArgs SHALL only include mount arguments for paths explicitly allowed by rules. Paths without matching rules SHALL have no mount entry.

#### Scenario: No matching rule
- **WHEN** config contains `fs:ro:/usr/bin`
- **THEN** BuildBwrapArgs includes no mount for `/opt/secret`

#### Scenario: Allowed path accessible
- **WHEN** config contains `fs:ro:/usr/bin`
- **THEN** BuildBwrapArgs includes `--ro-bind /usr/bin /usr/bin`

### Requirement: Read-only access

Rules with `ro` permission SHALL produce `--ro-bind` mount arguments, preventing write operations at the kernel level.

#### Scenario: Read allowed
- **WHEN** config contains `fs:ro:<path>`
- **THEN** BuildBwrapArgs includes `--ro-bind <path> <path>`

#### Scenario: Write denied on read-only path
- **WHEN** config contains `fs:ro:<path>`
- **THEN** BuildBwrapArgs includes `--ro-bind` (not `--bind`) for the path

### Requirement: Read-write access

Rules with `rw` permission SHALL produce `--bind` mount arguments, allowing both read and write operations.

#### Scenario: Read allowed on read-write path
- **WHEN** config contains `fs:rw:<path>`
- **THEN** BuildBwrapArgs includes `--bind <path> <path>`

#### Scenario: Write allowed on read-write path
- **WHEN** config contains `fs:rw:<path>`
- **THEN** BuildBwrapArgs includes `--bind <path> <path>`

### Requirement: No-access rule

Rules with `none` permission SHALL deny all access. Files are overlaid with `/dev/null`. Directories get a `tmpfs` with mode `0000`. A `none` directory with a child rule gets mode `0111` (execute-only for traversal) and the child is bind-mounted over it.

#### Scenario: Read denied by none rule
- **WHEN** config contains `fs:rw:<dir>` and `fs:none:<dir>/secret.txt`
- **THEN** BuildBwrapArgs includes `--bind /dev/null <dir>/secret.txt`

#### Scenario: Write denied by none rule
- **WHEN** config contains `fs:rw:<dir>` and `fs:none:<dir>/secret.txt`
- **THEN** BuildBwrapArgs includes `--bind /dev/null <dir>/secret.txt`

#### Scenario: None directory inaccessible
- **WHEN** config contains `fs:rw:<dir>` and `fs:none:<dir>/blocked`
- **AND** `<dir>/blocked` is a directory
- **THEN** BuildBwrapArgs includes `--tmpfs <dir>/blocked` and `--chmod 0000 <dir>/blocked`

#### Scenario: None directory with child rule allows child access
- **WHEN** config contains `fs:rw:<dir>`, `fs:none:<dir>/parent`, and `fs:rw:<dir>/parent/child`
- **THEN** BuildBwrapArgs includes `--tmpfs <dir>/parent` and `--chmod 0111 <dir>/parent` (execute-only for traversal)
- **AND** BuildBwrapArgs includes `--bind <dir>/parent/child <dir>/parent/child`

### Requirement: Default-deny environment

BuildBwrapArgs SHALL always include `--clearenv` so that no host environment variables are visible inside the sandbox by default. For each env rule in the config, if the variable is present in the host environment, BuildBwrapArgs SHALL append `--setenv KEY VALUE`. Variables listed in env rules but absent from the host environment are silently skipped.

#### Scenario: Default-deny: no host vars without rules

- **WHEN** config contains no `env` rules
- **THEN** BuildBwrapArgs includes `--clearenv`
- **AND** BuildBwrapArgs includes no `--setenv` flags

#### Scenario: Passed variable injected

- **WHEN** config contains `env:pass:HOME`
- **AND** host environment has `HOME=/home/user`
- **THEN** BuildBwrapArgs includes `--clearenv`
- **AND** BuildBwrapArgs includes `--setenv HOME /home/user`

#### Scenario: Multiple passed variables injected

- **WHEN** config contains `env:pass:HOME` and `env:pass:PATH`
- **AND** host environment has `HOME=/home/user` and `PATH=/usr/bin`
- **THEN** BuildBwrapArgs includes `--setenv HOME /home/user` and `--setenv PATH /usr/bin`

#### Scenario: Absent host variable not injected

- **WHEN** config contains `env:pass:MISSING_VAR`
- **AND** host environment does not contain `MISSING_VAR`
- **THEN** BuildBwrapArgs includes `--clearenv`
- **AND** BuildBwrapArgs includes no `--setenv MISSING_VAR` flag

### Requirement: Default-deny network

BuildBwrapArgs SHALL always include `--unshare-all` and never include `--share-net`. Without net rules, sandboxed processes have no NIC, no route, and no DNS.

#### Scenario: No net rules means no network
- **WHEN** config contains only fs rules
- **THEN** BuildBwrapArgs includes `--unshare-all` and does not include `--share-net`

#### Scenario: No net rules means no DNS
- **WHEN** config contains only fs rules
- **THEN** BuildBwrapArgs includes `--unshare-all`

### Requirement: Proxy-tunnel path setup

When a NetworkPath is provided, BuildBwrapArgs SHALL bind-mount the proxy UDS and execave binary into the sandbox read-only, and wrap the user command with `execave network-tunnel`.

Note: The CLI always provides a NetworkPath; testing the always-on proxy behavior requires bwrap + proxy orchestration and cannot be tested at the sandbox package level.

#### Scenario: Proxy-tunnel setup
- **WHEN** NetworkPath is provided
- **THEN** BuildBwrapArgs wraps the command with `network-tunnel` and the sandbox-internal UDS path

#### Scenario: Proxy UDS bind-mounted into sandbox
- **WHEN** NetworkPath has UDSPath `/tmp/test-proxy.sock`
- **THEN** BuildBwrapArgs includes `--ro-bind /tmp/test-proxy.sock /tmp/execave-proxy.sock`

#### Scenario: Execave binary bind-mounted read-only
- **WHEN** NetworkPath has ExecaveBinary `/usr/local/bin/execave`
- **THEN** BuildBwrapArgs includes `--ro-bind /usr/local/bin/execave /tmp/execave`

### Requirement: Processes ignoring HTTP_PROXY have no network

Even with net rules, BuildBwrapArgs SHALL include `--unshare-all` and never `--share-net`. Network isolation is enforced by the kernel, not the proxy.

#### Scenario: Direct connection fails
- **WHEN** NetworkPath is provided
- **THEN** BuildBwrapArgs includes `--unshare-all` and does not include `--share-net`

#### Scenario: UDP fails
- **WHEN** NetworkPath is provided
- **THEN** BuildBwrapArgs includes `--unshare-all`

### Requirement: CLI command execution

Without a NetworkPath, the user command appears directly after `--` in bwrap args. With a NetworkPath, the command is wrapped with `execave network-tunnel`.

#### Scenario: Command execution without net rules
- **WHEN** NetworkPath is nil
- **THEN** BuildBwrapArgs ends with `-- <command> <args...>` (no tunnel wrapping)

#### Scenario: Command execution with net rules
- **WHEN** NetworkPath is provided
- **THEN** BuildBwrapArgs ends with `-- /tmp/execave network-tunnel /tmp/execave-proxy.sock -- <command> <args...>`

### Requirement: Config file protection

When the config file path falls inside a `rw` mount, BuildBwrapArgs SHALL overlay it with `--ro-bind` to prevent modification. If the config file is not mounted or already in a `ro` mount, no overlay is added.

Note: ConfigFileDeletionPossibleButAcceptable requires bwrap to verify unlink behavior and cannot be tested at the sandbox package level.

#### Scenario: Config file in rw directory forced to ro
- **WHEN** config file is inside a directory with `fs:rw` rule
- **THEN** BuildBwrapArgs includes `--bind <dir> <dir>` followed by `--ro-bind <configPath> <configPath>`

#### Scenario: Config file protection does not block sibling access
- **WHEN** config file is inside a directory with `fs:rw` rule
- **THEN** BuildBwrapArgs includes `--bind <dir> <dir>` (parent remains writable)

#### Scenario: Config file not mounted stays unmounted
- **WHEN** config file is outside all rule paths
- **THEN** BuildBwrapArgs includes no mount for the config file path

#### Scenario: Config file already ro stays ro
- **WHEN** config file is inside a directory with `fs:ro` rule
- **THEN** BuildBwrapArgs includes `--ro-bind <dir> <dir>` with no separate overlay for the config file

### Requirement: Binary validation

ResolveBwrap and ResolveStrace SHALL resolve their respective binaries from PATH and validate them before use. ValidateBinary checks that the path entry itself (Lstat, no symlink follow) MUST be owned by root (uid 0), blocking symlink injection by non-privileged users. The resolved target (Stat, follows symlinks) MUST be owned by root and not writable by group or others (mode & 0022 == 0). Validation failure SHALL be a hard error that prevents execution. Both bwrap and strace are validated because strace runs outside the sandbox with full host access.

#### Scenario: Bwrap not found in PATH
- **WHEN** PATH contains no `bwrap` binary
- **THEN** ResolveBwrap returns an error mentioning "not found in PATH"

#### Scenario: Non-root-owned bwrap rejected
- **WHEN** PATH resolves to a `bwrap` binary not owned by root
- **THEN** ResolveBwrap returns an error mentioning "not owned by root"

#### Scenario: Non-root symlink to bwrap rejected
- **WHEN** PATH resolves to a symlink named `bwrap` not owned by root
- **THEN** ResolveBwrap returns an error mentioning "not owned by root"
- **AND** the symlink target is never executed (Lstat check blocks symlink injection)

#### Scenario: Strace not found in PATH
- **WHEN** PATH contains no `strace` binary
- **THEN** ResolveStrace returns an error mentioning "not found in PATH"

#### Scenario: Non-root-owned strace rejected
- **WHEN** PATH resolves to a `strace` binary not owned by root
- **THEN** ResolveStrace returns an error mentioning "not owned by root"

### Requirement: ELF interpreter auto-mount

binutil.InterpreterPath SHALL read the PT_INTERP program header from the bwrap binary and return the dynamic linker path. ManagedPathsWith SHALL extend ManagedDirs with the interpreter path. When Config.InterpreterPath is set, BuildBwrapArgs SHALL include a read-only bind-mount for the interpreter. The interpreter path SHALL be a managed path, preventing user rules from targeting it.

#### Scenario: Rule targeting interpreter path rejected
- **WHEN** the interpreter path is detected from a dynamically linked binary
- **AND** ManagedPathsWith includes the interpreter path in managed paths
- **AND** a rule targets the interpreter path
- **THEN** config validation rejects the rule as targeting a managed path

#### Scenario: Interpreter mounted in bwrap args
- **WHEN** Config.InterpreterPath is set to the detected interpreter path
- **THEN** BuildBwrapArgs includes `--ro-bind <interpPath> <interpPath>`

### Requirement: bwrap version check

CheckBwrapVersion SHALL run `bwrap --version`, parse the version string, and classify it against the pinned version 0.11.0.

- OK tier (`0.11.x`): return `("", nil)`.
- WARN tier (`0.12.x` through `0.99.x`): return `(warning, nil)` where warning describes the version mismatch.
- ERROR tier (`< 0.11.0` or `>= 1.0.0`): return `("", error)` where error describes the incompatibility.

#### Scenario: Exact pinned version — OK
- **WHEN** bwrap reports version `0.11.0`
- **THEN** CheckBwrapVersion returns `("", nil)`

#### Scenario: Higher patch, same minor — OK
- **WHEN** bwrap reports version `0.11.5`
- **THEN** CheckBwrapVersion returns `("", nil)`

#### Scenario: Higher minor, same 0.x major — WARN
- **WHEN** bwrap reports version `0.12.0`
- **THEN** CheckBwrapVersion returns a non-empty warning and nil error

#### Scenario: Older version — ERROR
- **WHEN** bwrap reports version `0.10.0`
- **THEN** CheckBwrapVersion returns a non-nil error

#### Scenario: Major version bump — ERROR
- **WHEN** bwrap reports version `1.0.0`
- **THEN** CheckBwrapVersion returns a non-nil error

#### Scenario: Version output unparseable — ERROR
- **WHEN** `bwrap --version` produces output with no recognisable version number
- **THEN** CheckBwrapVersion returns a non-nil error

### Requirement: strace version check

CheckStraceVersion SHALL run `strace --version`, parse the version string, and classify it against the pinned version 6.18.

- OK tier (`6.18`): return `("", nil)`.
- WARN tier (`6.19` through `6.x`): return `(warning, nil)`.
- ERROR tier (`< 6.18` or `>= 7.0`): return `("", error)`.

#### Scenario: Exact pinned version — OK
- **WHEN** strace reports version `6.18`
- **THEN** CheckStraceVersion returns `("", nil)`

#### Scenario: Higher minor, same major 6 — WARN
- **WHEN** strace reports version `6.19`
- **THEN** CheckStraceVersion returns a non-empty warning and nil error

#### Scenario: Older version — ERROR
- **WHEN** strace reports version `6.17`
- **THEN** CheckStraceVersion returns a non-nil error

#### Scenario: Major version bump — ERROR
- **WHEN** strace reports version `7.0`
- **THEN** CheckStraceVersion returns a non-nil error

#### Scenario: Version output unparseable — ERROR
- **WHEN** `strace --version` produces output with no recognisable version number
- **THEN** CheckStraceVersion returns a non-nil error

### Requirement: bwrap version compatibility enforcement

Sandbox.Run SHALL call CheckBwrapVersion after resolving the bwrap binary and SHALL enforce the result before executing any sandboxed command. A WARN result SHALL cause a warning message to be printed to stderr; execution SHALL continue. An ERROR result SHALL propagate as an error, preventing execution.

#### Scenario: Compatible bwrap version — execution proceeds
- **WHEN** bwrap is installed at a compatible version (OK or WARN tier)
- **THEN** Sandbox.Run proceeds to execute the sandboxed command

#### Scenario: Incompatible bwrap version — execution blocked
- **WHEN** bwrap is installed at an incompatible version (ERROR tier)
- **THEN** Sandbox.Run returns an error without executing the command

### Requirement: Seccomp filter integration

When seccomp is enabled (default), `Run()` SHALL create a seccomp filter pipe, add it to `cmd.ExtraFiles`, and insert `--seccomp <fd>` into the bwrap arguments before the `--` separator. The fd number SHALL be 3 (first ExtraFile). When `allowAllSyscalls` is true, no seccomp filter SHALL be applied.

#### Scenario: Seccomp enabled by default
- **WHEN** `New()` is called with `allowAllSyscalls=false`
- **AND** `Run()` is called
- **THEN** the bwrap command includes `--seccomp 3` before `--`
- **AND** `cmd.ExtraFiles` contains the seccomp filter pipe

#### Scenario: Seccomp disabled with flag
- **WHEN** `New()` is called with `allowAllSyscalls=true`
- **AND** `Run()` is called
- **THEN** the bwrap command does NOT include `--seccomp`
- **AND** `cmd.ExtraFiles` is empty

### Requirement: Seccomp arg insertion helper

The sandbox package SHALL export `InsertSeccompArg(args []string, fd int) []string` which inserts `--seccomp <fd>` before the `--` separator in bwrap args. This is used by both `sandbox.Run()` and the monitor for consistent arg manipulation.

#### Scenario: Seccomp arg inserted before separator
- **WHEN** `InsertSeccompArg(["--unshare-all", "--", "bash"], 3)` is called
- **THEN** it returns `["--unshare-all", "--seccomp", "3", "--", "bash"]`

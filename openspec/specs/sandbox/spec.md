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

Note: MonitoringWithoutNetRulesStartsProxyTunnel requires bwrap + strace + proxy orchestration and cannot be tested at the sandbox package level.

#### Scenario: Net rules trigger proxy-tunnel setup
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

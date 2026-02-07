# Sandbox Capability

## Purpose

The sandbox capability provides secure process and network isolation using bubblewrap. It enforces filesystem and network access controls based on configuration rules, implements a default-deny security model, and ensures sandboxed processes can only access explicitly permitted resources.

## Requirements

### Requirement: Default-deny filesystem

The sandbox SHALL start with an empty filesystem. Only paths explicitly allowed in the config SHALL be accessible. Essential system mounts (`/dev`, `/proc`, `/tmp`) MAY be mounted as needed for basic operation.

#### Scenario: No matching rule
- **WHEN** sandboxed process attempts to read `/opt/secret`
- **AND** no rule matches `/opt/secret`
- **THEN** access is denied with EACCES

#### Scenario: Allowed path accessible
- **WHEN** config contains `fs:ro:/usr/bin`
- **AND** sandboxed process attempts to read `/usr/bin/bash`
- **THEN** access is allowed

### Requirement: Read-only access

Rules with `fs:ro:<path>` SHALL allow read operations on `<path>` and all descendants. Write operations SHALL be denied.

#### Scenario: Read allowed
- **WHEN** config contains `fs:ro:/etc`
- **AND** sandboxed process attempts to read `/etc/passwd`
- **THEN** access is allowed

#### Scenario: Write denied on read-only path
- **WHEN** config contains `fs:ro:/etc`
- **AND** sandboxed process attempts to write `/etc/passwd`
- **THEN** access is denied with EACCES

### Requirement: Read-write access

Rules with `fs:rw:<path>` SHALL allow both read and write operations on `<path>` and all descendants.

#### Scenario: Read allowed on read-write path
- **WHEN** config contains `fs:rw:/home/user/project`
- **AND** sandboxed process attempts to read `/home/user/project/main.go`
- **THEN** access is allowed

#### Scenario: Write allowed on read-write path
- **WHEN** config contains `fs:rw:/home/user/project`
- **AND** sandboxed process attempts to write `/home/user/project/main.go`
- **THEN** access is allowed

### Requirement: No-access rule

Rules with `fs:none:<path>` SHALL deny all operations (read and write) on `<path>` and all descendants.

#### Scenario: Read denied by none rule
- **WHEN** config contains `fs:rw:/home/user/project` and `fs:none:/home/user/project/.env`
- **AND** sandboxed process attempts to read `/home/user/project/.env`
- **THEN** access is denied with EACCES

#### Scenario: Write denied by none rule
- **WHEN** config contains `fs:rw:/home/user/project` and `fs:none:/home/user/project/.env`
- **AND** sandboxed process attempts to write `/home/user/project/.env`
- **THEN** access is denied with EACCES

#### Scenario: None directory inaccessible
- **WHEN** config contains `fs:rw:/home/user/project` and `fs:none:/home/user/project/secrets`
- **AND** `/home/user/project/secrets` is a directory
- **AND** sandboxed process attempts to list `/home/user/project/secrets`
- **THEN** access is denied with EACCES
- **AND** file creation inside the directory is denied with EACCES

#### Scenario: None directory with child rule allows child access
- **WHEN** config contains `fs:rw:/home/user`, `fs:none:/home/user/project`, and `fs:rw:/home/user/project/src`
- **AND** `/home/user/project` and `/home/user/project/src` are directories
- **AND** sandboxed process attempts to read a file in `/home/user/project/src`
- **THEN** access to `/home/user/project/src` is allowed (child rule overrides)
- **AND** listing `/home/user/project` is denied with EACCES (parent is execute-only for traversal)

### Requirement: Symlink resolution

Access through a symlink SHALL require `ro` or `rw` permission on the symlink path, and the appropriate permission for the requested operation on the resolved target path.

#### Scenario: Symlink with accessible path and allowed target
- **WHEN** config contains `fs:rw:/home/user/project` and `fs:ro:/etc/passwd`
- **AND** `/home/user/project/passwd-link` is a symlink to `/etc/passwd`
- **AND** sandboxed process attempts to read via the symlink
- **THEN** access is allowed (both symlink path and target are accessible)

#### Scenario: Symlink with inaccessible path
- **WHEN** config contains `fs:ro:/etc/passwd`
- **AND** `/tmp/passwd-link` is a symlink to `/etc/passwd`
- **AND** no rule allows `/tmp` or `/tmp/passwd-link`
- **AND** sandboxed process attempts to read via the symlink
- **THEN** access is denied (symlink path is not mounted in sandbox)

#### Scenario: Symlink with accessible path but denied target
- **WHEN** config contains `fs:rw:/home/user/project`
- **AND** `/home/user/project/shadow-link` is a symlink to `/etc/shadow`
- **AND** no rule allows `/etc/shadow`
- **AND** sandboxed process attempts to read via the symlink
- **THEN** access is denied with ENOENT (target `/etc/shadow` is not mounted in sandbox)

### Requirement: Default-deny network

The sandbox SHALL isolate the network namespace unconditionally (no `--share-net`). Without net rules, sandboxed processes SHALL have no network access — no NIC, no route, no DNS.

#### Scenario: No net rules means no network
- **WHEN** config contains only fs rules (no `net:` rules)
- **AND** sandboxed process attempts to connect to `api.anthropic.com:443`
- **THEN** connection fails (no network interface available)

#### Scenario: No net rules means no DNS
- **WHEN** config contains only fs rules (no `net:` rules)
- **AND** sandboxed process attempts DNS resolution
- **THEN** resolution fails (no network interface available)

### Requirement: Proxy-tunnel path setup

When net rules are present in the config or monitoring is enabled, the sandbox SHALL:
1. Create a temporary directory for the proxy UDS
2. Start the proxy on the host, listening on the UDS
3. Bind-mount the UDS read-only into the sandbox at a fixed path
4. Bind-mount the execave binary read-only into the sandbox
5. Wrap the user command with `execave network-tunnel`

#### Scenario: Net rules trigger proxy-tunnel setup
- **WHEN** config contains `net:https:api.anthropic.com:443`
- **AND** sandboxed process uses `HTTP_PROXY` to connect to `api.anthropic.com:443`
- **THEN** connection succeeds through the proxy-tunnel path

#### Scenario: Proxy UDS bind-mounted into sandbox
- **WHEN** config contains net rules
- **THEN** the proxy UDS is accessible inside the sandbox as a filesystem object

#### Scenario: Execave binary bind-mounted read-only
- **WHEN** config contains net rules
- **THEN** the execave binary inside the sandbox is read-only (cannot be overwritten by sandboxed processes)

#### Scenario: Monitoring without net rules starts proxy-tunnel
- **WHEN** monitoring is enabled
- **AND** config contains no `net:` rules
- **THEN** the proxy-tunnel path is started with an empty rule set (deny-all)
- **AND** HTTP-proxy-aware programs' network access attempts are logged

### Requirement: Proxy lifecycle management

The sandbox SHALL start the proxy before the sandboxed process begins and stop the proxy after the sandboxed process exits. The temporary directory and UDS SHALL be cleaned up on exit.

#### Scenario: Proxy started before sandbox
- **WHEN** config contains net rules
- **THEN** proxy is accepting connections before the sandboxed process starts

#### Scenario: Cleanup on exit
- **WHEN** sandboxed process exits
- **THEN** proxy is stopped
- **AND** temporary directory and UDS are removed

### Requirement: Processes ignoring HTTP_PROXY have no network

Sandboxed processes that ignore `HTTP_PROXY` and attempt direct TCP connections SHALL fail because the sandbox has no NIC and no route. This is enforced by the kernel's network namespace isolation, not by the proxy.

#### Scenario: Direct connection fails
- **WHEN** config contains `net:https:api.anthropic.com:443`
- **AND** sandboxed process ignores `HTTP_PROXY` and attempts a direct TCP connection to `api.anthropic.com:443`
- **THEN** connection fails (no NIC, no route)

#### Scenario: UDP fails
- **WHEN** config contains net rules
- **AND** sandboxed process attempts to send a UDP packet
- **THEN** packet send fails (no network interface)

### Requirement: CLI command execution

The system SHALL execute the command specified after `--` in the sandboxed environment. When net rules are present, the command is wrapped with `execave network-tunnel` which sets up the proxy bridge and then runs the user command as a subprocess. The user command's exit code SHALL be propagated as execave's exit code.

#### Scenario: Command execution without net rules
- **WHEN** user runs `execave -- python script.py`
- **AND** config contains no net rules
- **THEN** `python script.py` runs directly inside the sandbox

#### Scenario: Command execution with net rules
- **WHEN** user runs `execave -- python script.py`
- **AND** config contains net rules
- **THEN** `python script.py` runs inside the sandbox as a subprocess of the tunnel
- **AND** proxy environment variables are set

#### Scenario: Exit code propagation with tunnel
- **WHEN** config contains net rules
- **AND** sandboxed command exits with code 42
- **THEN** execave exits with code 42

### Requirement: Config file protection

The sandbox SHALL prevent sandboxed processes from modifying the config file. Explicitly listing the config file as writable is rejected at config validation time (see config spec). If the config file path would be writable inside the sandbox (due to a rule granting rw access to a parent directory), the system SHALL ensure the config file is read-only inside the sandbox. If the config file is not mounted in the sandbox, it SHALL remain unmounted.

When access is reduced, the system SHALL print an info message to stderr.

#### Scenario: Config file in rw directory forced to ro
- **WHEN** config file is at `/home/user/project/execave.json`
- **AND** config contains `fs:rw:/home/user/project`
- **THEN** config file is mounted read-only inside sandbox
- **AND** system prints info message: `execave: config file forced read-only`

#### Scenario: Config file protection does not block sibling access
- **WHEN** config file is at `/home/user/project/execave.json`
- **AND** config contains `fs:rw:/home/user/project`
- **AND** `/home/user/project/data.txt` exists
- **THEN** sandboxed process can read `/home/user/project/data.txt`
- **AND** sandboxed process can write `/home/user/project/data.txt`

#### Scenario: Config file not mounted stays unmounted
- **WHEN** config file is at `/etc/execave/config.json`
- **AND** no rule matches `/etc/execave`
- **THEN** config file is not accessible inside sandbox

#### Scenario: Config file already ro stays ro
- **WHEN** config file is at `/home/user/project/execave.json`
- **AND** config contains `fs:ro:/home/user/project`
- **THEN** config file is mounted read-only inside sandbox
- **AND** no info message is printed (access not reduced)

#### Scenario: Config file deletion possible but acceptable
- **WHEN** config file is at `/home/user/project/execave.json`
- **AND** config contains `fs:rw:/home/user/project`
- **AND** sandboxed process attempts to unlink the config file
- **THEN** unlink may succeed (the parent directory is writable)

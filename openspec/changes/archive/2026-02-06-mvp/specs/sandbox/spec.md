## ADDED Requirements

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

### Requirement: Most specific rule wins

When multiple rules match a path, the most specific rule (longest matching path prefix) SHALL take precedence.

#### Scenario: Specific ro overrides general rw
- **WHEN** config contains `fs:rw:/home/user/project` and `fs:ro:/home/user/project/.git`
- **AND** sandboxed process attempts to write `/home/user/project/.git/config`
- **THEN** access is denied with EACCES (ro rule is more specific)

#### Scenario: Specific rw overrides general ro
- **WHEN** config contains `fs:ro:/home/user` and `fs:rw:/home/user/project`
- **AND** sandboxed process attempts to write `/home/user/project/file.txt`
- **THEN** access is allowed (rw rule is more specific)

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

### Requirement: CLI command execution

The system SHALL execute the command specified after `--` in the sandboxed environment. The command's exit code SHALL be propagated as execave's exit code.

#### Scenario: Command execution
- **WHEN** user runs `execave -- python script.py`
- **THEN** `python script.py` runs inside the sandbox

#### Scenario: Exit code propagation
- **WHEN** sandboxed command exits with code 42
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

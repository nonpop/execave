# Sandboxing Filesystem — Running commands with filesystem isolation

## Purpose

The user runs commands inside the sandbox with filesystem access controlled by rules. Rules grant read-only, read-write, or no-access permissions on specific paths. Unmatched paths are inaccessible (default-deny). More specific rules override less specific ones.

## Use Cases

### Use Case: Run command with read-only system access

The user grants read-only access to system paths so the sandboxed command can read system libraries and binaries but cannot modify them.

- **GIVEN** a config with rules `fs:ro:/usr/bin` and `fs:ro:/usr/lib`
- **WHEN** the user runs `execave -- ls /usr/bin`
- **THEN** the command succeeds and lists the contents of `/usr/bin`
- **AND** writing to any path under `/usr/bin` or `/usr/lib` is denied

### Use Case: Run command with read-write project access

The user grants read-write access to a project directory so the sandboxed command can create and modify files.

- **GIVEN** a config with rule `fs:rw:/home/user/project`
- **WHEN** the user runs `execave -- touch /home/user/project/output.txt`
- **THEN** the command succeeds and the file is created
- **AND** reading files in `/home/user/project` is also allowed

### Use Case: Protect sensitive files with no-access rules

The user blocks access to sensitive files within an otherwise accessible directory using a `none` rule.

- **GIVEN** a config with rules `fs:rw:/home/user/project` and `fs:none:/home/user/project/.env`
- **WHEN** the user runs a command that attempts to read `/home/user/project/.env`
- **THEN** the read is denied
- **AND** reading and writing other files in `/home/user/project` still works

### Use Case: Override parent rule with more specific child rule

The user protects a subdirectory with a more restrictive rule than its parent. The most specific rule wins.

- **GIVEN** a config with rules `fs:rw:/home/user/project` and `fs:ro:/home/user/project/.git`
- **WHEN** the user runs a command that attempts to write `/home/user/project/.git/config`
- **THEN** the write is denied (read-only rule is more specific)
- **AND** reading from `/home/user/project/.git/config` succeeds
- **AND** writing to `/home/user/project/src/main.go` succeeds (parent rw rule applies)

### Use Case: Access files through symlinks with allowed target

The user accesses a file through a symlink. Both the symlink path and the resolved target must be permitted by the rules.

- **GIVEN** a config with rules `fs:rw:/home/user/project` and `fs:ro:/etc/passwd`
- **AND** `/home/user/project/passwd-link` is a symlink to `/etc/passwd`
- **WHEN** the user runs a command that reads `/home/user/project/passwd-link`
- **THEN** the read succeeds (both the symlink path and the target are accessible)

### Use Case: Symlink to inaccessible target denied

The user has a symlink inside an accessible directory that points to a path outside any rule. Access through the symlink is denied.

- **GIVEN** a config with rule `fs:rw:/home/user/project`
- **AND** `/home/user/project/shadow-link` is a symlink to `/etc/shadow`
- **AND** no rule allows `/etc/shadow`
- **WHEN** the user runs a command that reads `/home/user/project/shadow-link`
- **THEN** the read is denied (target is not mounted in the sandbox)

### Use Case: Default-deny for unmatched paths

Paths not matched by any rule are inaccessible. The sandbox starts with an empty filesystem and only mounts explicitly allowed paths.

- **GIVEN** a config with rule `fs:ro:/usr/bin`
- **WHEN** the user runs a command that attempts to read `/opt/secret`
- **THEN** the read is denied (no rule matches `/opt/secret`)

### Use Case: None-directory with accessible child path

The user blocks a directory with `none` but grants access to a specific subdirectory within it. The child rule overrides the parent `none` rule.

- **GIVEN** a config with rules `fs:rw:/home/user`, `fs:none:/home/user/project`, and `fs:rw:/home/user/project/src`
- **WHEN** the user runs a command that reads a file in `/home/user/project/src`
- **THEN** the read succeeds (child rw rule overrides parent none rule)
- **AND** listing `/home/user/project` is denied (the directory itself is not readable, only traversable)

### Use Case: Relative paths in rules resolved relative to config directory

The user uses relative paths in config rules. These are resolved relative to the config file's directory, not the current working directory.

- **GIVEN** a config file at `/home/user/myproject/execave.json` with rule `fs:rw:./src`
- **WHEN** the user runs `execave --config /home/user/myproject/execave.json -- ls src`
- **THEN** the command can access files in `/home/user/myproject/src`

### Use Case: Sandboxed process receives terminal resize signal

On modern kernels where TIOCSTI is disabled, the sandbox skips `--new-session` so that SIGWINCH is delivered to the sandboxed process when the terminal is resized.

- **GIVEN** the kernel disables TIOCSTI (`/proc/sys/dev/tty/legacy_tiocsti` is `0`)
- **WHEN** the user runs a command that traps SIGWINCH inside the sandbox, and the terminal is resized
- **THEN** the command receives the SIGWINCH signal

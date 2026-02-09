# FS Rules Capability

## Purpose

The fs-rules capability handles parsing, validation, and resolution of filesystem access rules. It defines rule syntax, path normalization, cross-rule validation, and rule matching semantics. This is the core rule engine that determines which paths are accessible and with what permissions.

## Requirements

### Requirement: Rule syntax validation

The system SHALL validate each rule matches the pattern `fs:<permission>:<path>` where permission is one of `ro`, `rw`, `none`. Invalid rules SHALL cause the application to exit with an error before running the command.

#### Scenario: Invalid permission type
- **WHEN** config contains rule `fs:readonly:/path`
- **THEN** system exits with error indicating invalid permission type

#### Scenario: Malformed rule
- **WHEN** config contains rule `fs:ro` (missing path)
- **THEN** system exits with error indicating malformed rule

### Requirement: Path normalization

The system SHALL normalize paths in rules by resolving `..` and `.` components and removing trailing slashes. Relative paths SHALL be resolved relative to the config file's directory, not the current working directory.

#### Scenario: Path with relative components
- **WHEN** config contains rule `fs:ro:/home/user/../user/project/./src`
- **THEN** sandboxed process can read files in `/home/user/project/src`

#### Scenario: Trailing slash removal
- **WHEN** config contains rule `fs:rw:/home/user/project/`
- **THEN** sandboxed process can read and write files in `/home/user/project`

#### Scenario: Relative path resolution
- **WHEN** config file is at `/home/user/myproject/execave.json`
- **AND** config contains rule `fs:rw:./src`
- **THEN** sandboxed process can read and write files in `/home/user/myproject/src`

#### Scenario: Relative path with parent traversal
- **WHEN** config file is at `/home/user/myproject/execave.json`
- **AND** config contains rule `fs:ro:../shared`
- **THEN** sandboxed process can read files in `/home/user/shared`

### Requirement: Duplicate paths rejected

The system SHALL reject configs where multiple rules specify the same normalized path. Duplicate paths indicate config errors and must be resolved by the user.

#### Scenario: Duplicate paths with different permissions
- **WHEN** config contains both `fs:ro:/home/user` and `fs:rw:/home/user`
- **THEN** system exits with error indicating duplicate path `/home/user`

#### Scenario: Identical duplicate rules
- **WHEN** config contains `fs:ro:/usr/bin` twice
- **THEN** system exits with error indicating duplicate path `/usr/bin`

### Requirement: Config file cannot be explicitly writable

The system SHALL reject configs where a rule explicitly lists the config file path with `rw` permission. This prevents sandboxed processes from modifying the config to escalate privileges in future runs.

#### Scenario: Config file explicitly writable
- **WHEN** config file is at `/home/user/project/execave.json`
- **AND** config contains rule `fs:rw:/home/user/project/execave.json`
- **THEN** system exits with error indicating config file must not be writable

### Requirement: Managed paths cannot be targeted by rules

The system SHALL reject configs where a rule targets a managed path (`/dev`, `/proc`, `/tmp`) or any descendant of a managed path. These paths are mounted automatically by the sandbox and user rules would conflict with or duplicate the automatic mounts.

#### Scenario: Rule targets managed path exactly
- **WHEN** config contains rule `fs:ro:/dev`
- **THEN** system exits with error indicating the rule targets a managed path

#### Scenario: Rule targets descendant of managed path
- **WHEN** config contains rule `fs:rw:/proc/self/status`
- **THEN** system exits with error indicating the rule targets a managed path

#### Scenario: Path with managed prefix in name is allowed
- **WHEN** config contains rule `fs:ro:/home/user/dev`
- **THEN** system accepts the config (path is not under `/dev`)

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

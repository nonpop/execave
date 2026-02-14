# FS Rules Capability

## Purpose

The fs-rules capability handles parsing, validation, and resolution of filesystem access rules. `Parse` validates rule syntax and normalizes paths. `Validate` performs cross-rule checks (duplicates, config protection, managed paths). `NewResolver` + `CheckAccess` determines whether a given path and operation are allowed. The resource prefix (`fs:`) is stripped by the config layer before parsing.

## Requirements

### Requirement: Rule syntax validation

`Parse` SHALL validate each rule body matches the pattern `<permission>:<path>` where permission is one of `ro`, `rw`, `none`. Invalid rule bodies SHALL cause `Parse` to return an error.

#### Scenario: Invalid permission type
- **WHEN** `Parse` is called with rule body `"readonly:/path"` and configDir `"/"`
- **THEN** it returns an error containing `"invalid permission type"`

#### Scenario: Malformed rule
- **WHEN** `Parse` is called with rule body `"ro"` (missing path) and configDir `"/"`
- **THEN** it returns an error containing `"malformed rule"`

### Requirement: Path normalization

`Parse` SHALL normalize paths by resolving `..` and `.` components and removing trailing slashes. Relative paths SHALL be resolved relative to the configDir parameter.

#### Scenario: Path with relative components
- **WHEN** `Parse` is called with rule body `"ro:/home/user/../user/project/./src"` and configDir `"/"`
- **THEN** the returned rule has Path `"/home/user/project/src"`

#### Scenario: Trailing slash removal
- **WHEN** `Parse` is called with rule body `"rw:/home/user/project/"` and configDir `"/"`
- **THEN** the returned rule has Path `"/home/user/project"`

#### Scenario: Relative path resolution
- **WHEN** `Parse` is called with rule body `"rw:./src"` and configDir `"/home/user/myproject"`
- **THEN** the returned rule has Path `"/home/user/myproject/src"`

#### Scenario: Relative path with parent traversal
- **WHEN** `Parse` is called with rule body `"ro:../shared"` and configDir `"/home/user/myproject"`
- **THEN** the returned rule has Path `"/home/user/shared"`

### Requirement: Duplicate paths rejected

`Validate` SHALL reject rule sets where multiple rules specify the same normalized path. Duplicate paths indicate config errors and must be resolved by the user.

#### Scenario: Duplicate paths with different permissions
- **WHEN** `Validate` is called with rules `ro:/home/user` and `rw:/home/user`
- **THEN** it returns an error containing `"duplicate path"` and `"/home/user"`

#### Scenario: Identical duplicate rules
- **WHEN** `Validate` is called with rule `ro:/usr/bin` appearing twice
- **THEN** it returns an error containing `"duplicate path"` and `"/usr/bin"`

### Requirement: Config file cannot be explicitly writable

`Validate` SHALL reject rule sets where a rule explicitly lists the config file path with `rw` permission. This prevents sandboxed processes from modifying the config to escalate privileges in future runs.

#### Scenario: Config file explicitly writable
- **WHEN** `Validate` is called with rule `rw:/home/user/project/execave.json` and configPath `"/home/user/project/execave.json"`
- **THEN** it returns an error containing `"config file must not be writable"`

### Requirement: Managed paths cannot be targeted by rules

`Validate` SHALL reject rule sets where a rule targets a managed path or any descendant of a managed path. These paths are mounted automatically by the sandbox and user rules would conflict with or duplicate the automatic mounts.

#### Scenario: Rule targets managed path exactly
- **WHEN** `Validate` is called with rule `ro:/dev` and managedPaths `["/dev", "/proc", "/tmp"]`
- **THEN** it returns an error containing `"managed path"` and `"/dev"`

#### Scenario: Rule targets descendant of managed path
- **WHEN** `Validate` is called with rule `rw:/proc/self/status` and managedPaths `["/dev", "/proc", "/tmp"]`
- **THEN** it returns an error containing `"managed path"` and `"/proc"`

#### Scenario: Path with managed prefix in name is allowed
- **WHEN** `Validate` is called with rule `ro:/home/user/dev` and managedPaths `["/dev", "/proc", "/tmp"]`
- **THEN** it returns no error

### Requirement: Most specific rule wins

When `CheckAccess` is called and multiple rules match a path, the most specific rule (longest matching path prefix) SHALL take precedence.

#### Scenario: Specific ro overrides general rw
- **WHEN** a resolver is created with rules `rw:/home/user/project` and `ro:/home/user/project/.git`
- **AND** `CheckAccess` is called with path `"/home/user/project/.git/config"` and operation write
- **THEN** the result is not allowed (ro rule is more specific)

#### Scenario: Specific rw overrides general ro
- **WHEN** a resolver is created with rules `ro:/home/user` and `rw:/home/user/project`
- **AND** `CheckAccess` is called with path `"/home/user/project/file.txt"` and operation write
- **THEN** the result is allowed (rw rule is more specific)

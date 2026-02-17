## ADDED Requirements

### Requirement: Tilde expansion in paths

`Parse` SHALL expand a leading `~/` or a bare `~` in the path component to the current user's home directory (as returned by `os.UserHomeDir()`), before relative-path resolution and normalization. If `os.UserHomeDir()` returns an error, `Parse` SHALL return an error. `~username` (tilde followed by a non-slash character) SHALL be rejected with a parse error.

#### Scenario: Tilde-slash path expanded to absolute
- **WHEN** `Parse` is called with rule body `"rw:~/project"` and configDir `"/home/user"`
- **AND** the user's home directory is `/home/user`
- **THEN** the returned rule has Path `"/home/user/project"`

#### Scenario: Bare tilde expanded to home directory
- **WHEN** `Parse` is called with rule body `"ro:~"` and configDir `"/"`
- **AND** the user's home directory is `/home/user`
- **THEN** the returned rule has Path `"/home/user"`

#### Scenario: Tilde path cleaned after expansion
- **WHEN** `Parse` is called with rule body `"rw:~/project/../other"` and configDir `"/"`
- **AND** the user's home directory is `/home/user`
- **THEN** the returned rule has Path `"/home/user/other"`

#### Scenario: Tilde-username rejected
- **WHEN** `Parse` is called with rule body `"ro:~otheruser/data"` and configDir `"/home/user"`
- **THEN** it returns an error containing `"~username"` or `"not supported"`

### Requirement: Tilde-expanded paths participate in validation

`Validate` SHALL detect duplicates and other violations using the expanded path from tilde expansion, not the original rule text. Rules that expand to the same absolute path SHALL be rejected as duplicates.

#### Scenario: Tilde and absolute path duplicate detected
- **WHEN** `Validate` is called with rules `ro:~` and `ro:/home/user`
- **AND** the user's home directory is `/home/user`
- **THEN** it returns an error containing `"duplicate path"` and `"/home/user"`

#### Scenario: Tilde path and equivalent relative path duplicate detected
- **WHEN** `Validate` is called with rules `rw:~/project` and `rw:project`
- **AND** the user's home directory is `/home/user`
- **AND** configDir is `/home/user`
- **THEN** it returns an error containing `"duplicate path"` and `"/home/user/project"`

#### Scenario: Tilde path targeting config file rejected
- **WHEN** `Validate` is called with rule `rw:~/project/execave.toml`
- **AND** the user's home directory is `/home/user`
- **AND** configPath is `/home/user/project/execave.toml`
- **THEN** it returns an error containing `"config file must not be writable"`

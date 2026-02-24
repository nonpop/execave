## ADDED Requirements

### Requirement: Log rule syntax validation

`ParseLogRule` SHALL validate each rule body matches the pattern `<visibility>:<path>` where visibility is one of `log`, `nolog`. Invalid rule bodies SHALL cause `ParseLogRule` to return an error. The path component SHALL be normalized identically to access rules: tilde expansion, relative path resolution against configDir, and filepath.Clean.

#### Scenario: Valid nolog rule

- **WHEN** `ParseLogRule` is called with rule body `"nolog:/home/user/project"` and configDir `"/"`
- **THEN** it returns a LogRule with Visible=false and Path `"/home/user/project"`

#### Scenario: Valid log rule

- **WHEN** `ParseLogRule` is called with rule body `"log:/home/user/project"` and configDir `"/"`
- **THEN** it returns a LogRule with Visible=true and Path `"/home/user/project"`

#### Scenario: Invalid visibility type

- **WHEN** `ParseLogRule` is called with rule body `"hide:/path"` and configDir `"/"`
- **THEN** it returns an error containing `"invalid visibility type"`

#### Scenario: Malformed log rule

- **WHEN** `ParseLogRule` is called with rule body `"nolog"` (missing path) and configDir `"/"`
- **THEN** it returns an error containing `"malformed rule"`

#### Scenario: Tilde expansion in log rule path

- **WHEN** `ParseLogRule` is called with rule body `"nolog:~/project"` and configDir `"/home/user"`
- **AND** the user's home directory is `/home/user`
- **THEN** the returned LogRule has Path `"/home/user/project"`

#### Scenario: Relative path resolution in log rule

- **WHEN** `ParseLogRule` is called with rule body `"nolog:data"` and configDir `"/home/user/myproject"`
- **THEN** the returned LogRule has Path `"/home/user/myproject/data"`

### Requirement: Log rule validation

`ValidateLogRules` SHALL reject log rule sets where multiple rules specify the same normalized path. Duplicate paths indicate config errors and must be resolved by the user.

#### Scenario: Duplicate log rule paths rejected

- **WHEN** `ValidateLogRules` is called with rules `nolog:/home/user` and `log:/home/user`
- **THEN** it returns an error containing `"duplicate path"` and `"/home/user"`

#### Scenario: Identical duplicate log rules rejected

- **WHEN** `ValidateLogRules` is called with rule `nolog:/usr/bin` appearing twice
- **THEN** it returns an error containing `"duplicate path"` and `"/usr/bin"`

#### Scenario: Same path in access and log rules allowed

- **WHEN** access rules contain `ro:/usr/lib` and log rules contain `nolog:/usr/lib`
- **THEN** validation succeeds (access and log are different namespaces)

### Requirement: Log rule resolution

`LogResolver.Visible` SHALL determine whether an entry for a given path should be displayed by finding the log rule with the longest matching path prefix. If the matching rule has visibility `nolog`, the entry is not visible. If the matching rule has visibility `log`, the entry is visible. If no log rule matches, the entry is visible (default: show).

#### Scenario: Nolog hides entries under matching path

- **WHEN** a LogResolver is created with rule `nolog:/home/user/project`
- **AND** `Visible` is called with path `"/home/user/project/cache/data"`
- **THEN** the result is false

#### Scenario: Log overrides nolog for more specific path

- **WHEN** a LogResolver is created with rules `nolog:/home/user/project` and `log:/home/user/project/secret`
- **AND** `Visible` is called with path `"/home/user/project/secret/key.pem"`
- **THEN** the result is true

#### Scenario: No matching log rule defaults to visible

- **WHEN** a LogResolver is created with rule `nolog:/home/user/project`
- **AND** `Visible` is called with path `"/usr/lib/libc.so"`
- **THEN** the result is true

#### Scenario: Exact path match

- **WHEN** a LogResolver is created with rule `nolog:/home/user/project`
- **AND** `Visible` is called with path `"/home/user/project"`
- **THEN** the result is false

#### Scenario: Nested nolog overrides log

- **WHEN** a LogResolver is created with rules `nolog:/home/user`, `log:/home/user/project`, and `nolog:/home/user/project/vendor`
- **AND** `Visible` is called with path `"/home/user/project/vendor/lib.go"`
- **THEN** the result is false

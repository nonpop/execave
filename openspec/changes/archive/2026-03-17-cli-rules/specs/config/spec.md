## ADDED Requirements

### Requirement: Load config from CLI rules

`config.LoadWithCLI` SHALL accept CLI rule slices (fs, net, syscall, env, extends) and an optional config file path, and return a merged, validated `*Config`. CLI rules SHALL be assembled into a virtual config where the config file (if present) and `--extends` entries are the virtual config's extends chain, and CLI rule slices populate the corresponding sections. The loading order SHALL be: extends entries (depth-first), then config file, then CLI rules.

#### Scenario: CLI fs rule merged with config file rules

- **WHEN** LoadWithCLI is called with config file containing `fs = ["ro:/usr"]` and CLI fs rules `["rw:/tmp/work"]`
- **THEN** the returned Config contains both fs rules

#### Scenario: CLI net rule merged with config file rules

- **WHEN** LoadWithCLI is called with config file containing `net = ["http:api.example.com:443"]` and CLI net rules `["http:cdn.example.com:443"]`
- **THEN** the returned Config contains both net rules

#### Scenario: CLI syscall rule merged with config file rules

- **WHEN** LoadWithCLI is called with config file containing `syscall = ["allow:bpf"]` and CLI syscall rules `["allow:ptrace"]`
- **THEN** the returned Config contains both syscall rules

#### Scenario: CLI env rule merged with config file rules

- **WHEN** LoadWithCLI is called with config file containing `env = ["pass:HOME"]` and CLI env rules `["pass:EDITOR"]`
- **THEN** the returned Config contains both env rules

#### Scenario: CLI extends merged with config file

- **WHEN** LoadWithCLI is called with config file path and CLI extends `["base.toml"]`
- **THEN** the returned Config contains rules from base.toml, the config file, and CLI rules

#### Scenario: Duplicate rule across CLI and config file is deduplicated

- **WHEN** LoadWithCLI is called with config file containing `fs = ["ro:/usr"]` and CLI fs rules `["ro:/usr"]`
- **THEN** the returned Config contains one fs rule for `/usr`

#### Scenario: Conflicting fs rules across CLI and config file rejected

- **WHEN** LoadWithCLI is called with config file containing `fs = ["none:/secrets"]` and CLI fs rules `["rw:/secrets"]`
- **THEN** LoadWithCLI returns a validation error indicating duplicate path

#### Scenario: Conflicting net rules across CLI and config file rejected

- **WHEN** LoadWithCLI is called with config file containing `net = ["none:evil.com:443"]` and CLI net rules `["http:evil.com:443"]`
- **THEN** LoadWithCLI returns a validation error indicating duplicate net rule identity

#### Scenario: CLI-only mode with no config file

- **WHEN** LoadWithCLI is called with no config file path and CLI fs rules `["ro:/usr"]`
- **THEN** the returned Config contains only the CLI fs rule

#### Scenario: CLI-only mode with extends

- **WHEN** LoadWithCLI is called with no config file path, CLI extends `["base.toml"]`, and CLI fs rules `["rw:/project"]`
- **THEN** the returned Config contains rules from base.toml and the CLI fs rule

#### Scenario: Invalid CLI rule syntax rejected

- **WHEN** LoadWithCLI is called with CLI fs rules `["readonly:/usr"]`
- **THEN** LoadWithCLI returns a parse error

#### Scenario: Empty CLI rules with config file is equivalent to Load

- **WHEN** LoadWithCLI is called with a config file path and no CLI rules
- **THEN** the returned Config is equivalent to calling Load with the same config file

### Requirement: CLI rule SourcePath provenance

Rules parsed from CLI flags SHALL have `SourcePath` set to the sentinel value `"<cli>"`. This value SHALL be distinct from file paths (empty string is reserved for synthetic rules).

#### Scenario: CLI-sourced fs rule has cli source path

- **WHEN** LoadWithCLI is called with CLI fs rules `["ro:/usr"]`
- **THEN** the returned fs rule has SourcePath `"<cli>"`

#### Scenario: File-sourced rule retains file source path

- **WHEN** LoadWithCLI is called with a config file at `/home/user/execave.toml` containing `fs = ["ro:/usr"]` and no CLI fs rules
- **THEN** the returned fs rule has SourcePath `/home/user/execave.toml`

### Requirement: CLI rule path resolution

CLI-sourced filesystem rules SHALL resolve relative paths against the current working directory. Tilde expansion SHALL work the same as for file-sourced rules.

#### Scenario: Relative CLI fs path resolves against cwd

- **WHEN** LoadWithCLI is called from cwd `/home/user/project` with CLI fs rules `["rw:."]`
- **THEN** the returned fs rule has Path `/home/user/project`

#### Scenario: Tilde CLI fs path expands to home directory

- **WHEN** LoadWithCLI is called with CLI fs rules `["ro:~/docs"]` and user home is `/home/user`
- **THEN** the returned fs rule has Path `/home/user/docs`

### Requirement: CLI extends path resolution

CLI-sourced extends paths SHALL resolve relative paths against the current working directory. Tilde expansion SHALL work the same as for file-sourced extends.

#### Scenario: Relative CLI extends path resolves against cwd

- **WHEN** LoadWithCLI is called from cwd `/home/user/project` with CLI extends `["../base.toml"]`
- **THEN** the loader resolves the extends path to `/home/user/base.toml`

## MODIFIED Requirements

### Requirement: Effective config output format and provenance

Effective config output SHALL be TOML with typed sections (`fs`, `net`, `syscall`, `env`) and SHALL include source-path provenance as comment lines for emitted rules. CLI-sourced rules SHALL render with `# <cli>` provenance. The rendering order SHALL be: file-sourced rules in config-path order, then CLI-sourced rules, then synthetic rules.

#### Scenario: Output contains typed sections
- **WHEN** `config show` succeeds
- **THEN** stdout contains TOML arrays for configured sections (`fs`, `net`, `syscall`, and/or `env`) using rule bodies consistent with current config format

#### Scenario: Output includes source comments for each emitted rule
- **WHEN** `config show` emits a rule originating from layered config files
- **THEN** the emitted TOML includes one or more comment lines indicating source file path provenance adjacent to that rule

#### Scenario: CLI-sourced rules render with cli provenance
- **WHEN** `config show` emits a rule originating from CLI flags
- **THEN** the emitted TOML includes a `# <cli>` comment line adjacent to that rule

#### Scenario: CLI rules render after file rules
- **WHEN** `config show` renders rules from both a config file and CLI flags
- **THEN** file-sourced rules appear before CLI-sourced rules within each section

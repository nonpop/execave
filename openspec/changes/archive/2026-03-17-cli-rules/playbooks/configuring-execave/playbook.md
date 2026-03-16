## ADDED Use Cases

### Use Case: Add filesystem rule via CLI flag

The user adds a filesystem access rule from the command line to augment the config file.

- **GIVEN** a config file `execave.toml` with `fs = ["ro:/usr"]`
- **WHEN** the user runs `execave --fs rw:/tmp/scratch -- ls /tmp/scratch`
- **THEN** the sandbox has both `ro:/usr` from the config and `rw:/tmp/scratch` from the CLI flag
- **AND** the command can list `/tmp/scratch`

### Use Case: Add network rule via CLI flag

The user adds a network access rule from the command line.

- **GIVEN** a config file `execave.toml` with `fs = ["ro:/usr", "ro:/lib", "ro:/lib64", "ro:/etc"]`
- **WHEN** the user runs `execave --net http:example.com:443 -- curl https://example.com`
- **THEN** the sandbox allows HTTPS to example.com on port 443
- **AND** the curl command succeeds

### Use Case: Add syscall rule via CLI flag

The user allows a blocked syscall from the command line.

- **GIVEN** a config file `execave.toml` with `fs = ["ro:/usr", "ro:/lib", "ro:/lib64", "ro:/etc"]`
- **WHEN** the user runs `execave --syscall allow:bpf -- <command using bpf>`
- **THEN** the bpf syscall is removed from the seccomp deny-list

### Use Case: Add env rule via CLI flag

The user passes a host environment variable into the sandbox from the command line.

- **GIVEN** a config file `execave.toml` with `fs = ["ro:/usr"]`
- **AND** the host has `MY_VAR=hello` set
- **WHEN** the user runs `execave --env pass:MY_VAR -- env`
- **THEN** the sandbox has `MY_VAR=hello` in its environment

### Use Case: Add extends via CLI flag

The user composes a base config from the command line instead of declaring it in the config file.

- **GIVEN** a config file `execave.toml` with `fs = ["rw:~/project"]`
- **AND** a base config `base.toml` with `fs = ["ro:/usr", "ro:/lib", "ro:/lib64"]`
- **WHEN** the user runs `execave --extends base.toml -- ls`
- **THEN** the sandbox has rules from both `base.toml` and `execave.toml`

### Use Case: Multiple CLI flags of the same type

The user specifies multiple rules of the same type by repeating the flag.

- **GIVEN** a config file `execave.toml` with `fs = ["ro:/usr"]`
- **WHEN** the user runs `execave --fs ro:/lib --fs ro:/lib64 --fs ro:/etc -- ls /etc`
- **THEN** the sandbox has all four filesystem rules (one from config, three from CLI)

### Use Case: Run without config file using --no-config

The user runs execave with no config file at all, specifying all rules on the command line.

- **GIVEN** no config file exists
- **WHEN** the user runs `execave --no-config --fs ro:/usr --fs ro:/lib --fs ro:/lib64 -- ls /usr`
- **THEN** the command runs in a sandbox with only the CLI-specified rules
- **AND** no config file is loaded

### Use Case: --no-config with --extends composes from CLI

The user builds a config entirely from CLI flags and extends references.

- **GIVEN** a base config `base.toml` with `fs = ["ro:/usr", "ro:/lib", "ro:/lib64"]`
- **WHEN** the user runs `execave --no-config --extends base.toml --fs rw:~/project -- make build`
- **THEN** the sandbox has rules from `base.toml` plus the CLI filesystem rule
- **AND** no default config file is loaded

### Use Case: --config and --no-config together is an error

The user accidentally specifies both flags. The system rejects the invocation.

- **GIVEN** a config file `execave.toml` exists
- **WHEN** the user runs `execave --config execave.toml --no-config --fs ro:/usr -- ls`
- **THEN** execave exits with an error indicating `--config` and `--no-config` are mutually exclusive

### Use Case: CLI rule conflicts with config file rule

The user specifies a CLI rule that targets the same path as a config file rule with a different permission. The system rejects the conflicting rules.

- **GIVEN** a config file `execave.toml` with `fs = ["none:/secrets"]`
- **WHEN** the user runs `execave --fs rw:/secrets -- ls /secrets`
- **THEN** execave exits with an error indicating duplicate/conflicting path `/secrets`

### Use Case: CLI net rule conflicts with config file net rule

The user specifies a CLI network rule that targets the same identity as a config file rule with a different action. The system rejects the conflict.

- **GIVEN** a config file `execave.toml` with `net = ["none:evil.com:443"]`
- **WHEN** the user runs `execave --net http:evil.com:443 -- curl https://evil.com`
- **THEN** execave exits with an error indicating duplicate/conflicting net rule identity

### Use Case: Duplicate CLI rule and config rule is deduplicated

The user specifies a CLI rule identical to one in the config file. The duplicate is silently deduplicated.

- **GIVEN** a config file `execave.toml` with `fs = ["ro:/usr"]`
- **WHEN** the user runs `execave --fs ro:/usr -- ls /usr`
- **THEN** the sandbox runs with one effective `ro:/usr` rule (deduplicated)

### Use Case: Config show displays CLI rules with provenance

The user inspects the effective config including CLI-sourced rules.

- **GIVEN** a config file `execave.toml` with `fs = ["ro:/usr"]`
- **WHEN** the user runs `execave --fs rw:/tmp/work config show`
- **THEN** the output includes `rw:/tmp/work` with `<cli>` provenance
- **AND** the output includes `ro:/usr` with the config file path as provenance

### Use Case: Config show with --no-config

The user inspects the effective config when running without a config file.

- **GIVEN** no config file
- **WHEN** the user runs `execave --no-config --fs ro:/usr --net http:example.com:443 config show`
- **THEN** the output shows both rules with `<cli>` provenance
- **AND** no config file path appears in the output

### Use Case: CLI flags work with monitor command

The user adds rules via CLI flags when using the monitor subcommand.

- **GIVEN** a config file `execave.toml` with `fs = ["ro:/usr"]`
- **WHEN** the user runs `execave --fs ro:/etc monitor -- ls /etc`
- **THEN** monitoring runs with both the config file rule and the CLI rule applied

### Use Case: CLI flags with relative filesystem path resolve from cwd

The user specifies a relative path in a CLI filesystem rule. It resolves against the current working directory.

- **GIVEN** the user's current directory is `/home/user/project`
- **WHEN** the user runs `execave --no-config --fs rw:. -- ls`
- **THEN** the sandbox mounts `/home/user/project` as read-write

### Use Case: CLI flags with tilde filesystem path expand to home

The user specifies a tilde path in a CLI filesystem rule. It expands to the home directory.

- **GIVEN** the user's home directory is `/home/user`
- **WHEN** the user runs `execave --no-config --fs ro:~/documents -- ls ~/documents`
- **THEN** the sandbox mounts `/home/user/documents` as read-only

### Use Case: Invalid CLI rule syntax rejected

The user provides a malformed rule string via CLI flag. The system rejects it with a clear error.

- **GIVEN** no config file
- **WHEN** the user runs `execave --no-config --fs readonly:/usr -- ls`
- **THEN** execave exits with an error indicating invalid rule syntax
- **AND** the command is never executed

## MODIFIED Use Cases

### Use Case: Missing config file shows error

The user runs execave without a config file at the expected path and without `--no-config`. The system exits with a clear error message.

- **GIVEN** no `./execave.toml` file exists in the current directory
- **AND** the user does not pass `--no-config`
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating the config file was not found

### Use Case: Show effective config as TOML

The user inspects the final merged config to validate layered config composition before running commands. The output includes provenance for all rule sources, including CLI flags.

- **GIVEN** a valid layered config rooted at `./execave.toml`
- **WHEN** the user runs `execave config show`
- **THEN** execave prints TOML with `fs`, `net`, `syscall`, and `env` sections representing effective merged rules
- **AND** emitted rules include source provenance as TOML comments (file paths for file-sourced rules, `<cli>` for CLI-sourced rules)

### Use Case: Show effective config includes env rules

The user inspects the effective config and sees the `env` section with source provenance comments, including any CLI-added env rules.

- **GIVEN** a config with:
  ```toml
  env = ["pass:HOME", "pass:PATH"]
  ```
- **WHEN** the user runs `execave --env pass:EDITOR config show`
- **THEN** the output includes an `env` section listing all three pass rules
- **AND** `pass:HOME` and `pass:PATH` include the config file path as provenance
- **AND** `pass:EDITOR` includes `<cli>` as provenance

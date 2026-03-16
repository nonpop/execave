# Configuring Execave — Setting up and validating configuration

## Purpose

The user creates and manages the execave configuration file. The system validates all rules before running any command, catching syntax errors, conflicts, and security violations at config load time rather than at runtime.

## Use Cases

### Use Case: Default config location (`./execave.toml`)

The user places the config file in the current working directory with the default name. Execave finds it automatically without any flags.

- **GIVEN** a file `./execave.toml` with valid rules
- **WHEN** the user runs `execave -- ls`
- **THEN** the system reads configuration from `./execave.toml`
- **AND** the command runs in the sandbox with the configured rules

### Use Case: Custom config path via `--config`

The user stores the config file at a non-default location and points execave to it with the global `--config` flag.

- **GIVEN** a valid config file at `/home/user/configs/execave.toml`
- **WHEN** the user runs `execave --config /home/user/configs/execave.toml run -- ls`
- **THEN** the system reads configuration from `/home/user/configs/execave.toml`

### Use Case: Missing config file shows error

The user runs execave without a config file at the expected path and without `--no-config`. The system exits with a clear error message.

- **GIVEN** no `./execave.toml` file exists in the current directory
- **AND** the user does not pass `--no-config`
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating the config file was not found

### Use Case: Invalid rule syntax rejected before execution

The user has a config with a malformed rule. The system catches the error at config load time and exits before running any command.

- **GIVEN** a config with:
  ```toml
  fs = ["readonly:/home/user"]
  ```
  (invalid permission type)
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating the invalid rule syntax
- **AND** the command is never executed

### Use Case: Duplicate filesystem paths rejected

The user has a config where two rules target the same normalized path. The system rejects the config because duplicate paths indicate a configuration error.

- **GIVEN** a config with:
  ```toml
  fs = ["ro:/home/user", "rw:/home/user"]
  ```
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating duplicate path `/home/user`

### Use Case: Duplicate network rule identity rejected

The user has a config where two net rules share the same target and port pattern. The system rejects the config because the conflicting actions cannot be resolved.

- **GIVEN** a config with:
  ```toml
  net = ["http:example.com:443", "none:example.com:443"]
  ```
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating duplicate net rule identity

### Use Case: Mixed port patterns on same target rejected

The user has a config where the same target has both a wildcard port rule and a specific port rule. The system rejects this because the interaction between wildcard and specific ports is ambiguous.

- **GIVEN** a config with:
  ```toml
  net = ["http:example.com:*", "none:example.com:443"]
  ```
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating mixed port patterns on the same target

### Use Case: Config file with comments

The user adds comments to the TOML config file to document the purpose of each rule. The system accepts the config and applies all rules normally.

- **GIVEN** a config file `execave.toml` containing:
  ```toml
  # Sandbox for my coding agent
  # Project directory: full access
  fs = [
      "rw:/home/user/project",  # workspace
      "ro:/usr",                 # system libraries
  ]
  ```
- **WHEN** the user runs `execave -- ls`
- **THEN** the system reads the config, ignoring comments
- **AND** the command runs in the sandbox with the configured rules

### Use Case: Tilde expansion in filesystem rules

The user writes `~/...` paths in rules instead of full absolute paths. The system expands `~` to the user's home directory at config load time.

- **GIVEN** a config file with:
  ```toml
  fs = ["rw:~/project"]
  ```
- **AND** the user's home directory is `/home/user`
- **WHEN** the user runs `execave -- ls`
- **THEN** the system expands `~` to `/home/user` and mounts `/home/user/project` read-write in the sandbox

### Use Case: Tilde in config validation errors

The user writes a tilde path that conflicts with another rule. The error message includes the original tilde path for clarity.

- **GIVEN** a config file with:
  ```toml
  fs = ["rw:~/project", "ro:~/project"]
  ```
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating duplicate path `/home/user/project`

### Use Case: Config file explicitly writable rejected

The user has a config where a rule explicitly grants read-write access to the config file itself. The system rejects this to prevent sandboxed processes from modifying the config and escalating privileges in future runs.

- **GIVEN** a config file at `/home/user/project/execave.toml` with:
  ```toml
  fs = ["rw:/home/user/project/execave.toml"]
  ```
- **WHEN** the user runs `execave --config /home/user/project/execave.toml -- ls`
- **THEN** the system exits with an error indicating the config file must not be explicitly writable

### Use Case: Managed paths in rules rejected

The user has a config with a rule targeting a managed path or its descendant. The system rejects it because these paths are mounted automatically by the sandbox and user rules would conflict. Managed paths include `/dev`, `/proc`, `/tmp`, and the auto-detected ELF interpreter (dynamic linker).

- **GIVEN** a config with:
  ```toml
  fs = ["ro:/proc/self/status"]
  ```
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating the rule targets a managed path

### Use Case: Selectively allow a blocked syscall

The user wants to allow a specific syscall that is blocked by default. The syscall is specified in the `syscall` key of the config.

- **GIVEN** a config with:
  ```toml
  fs = ["ro:/usr", "ro:/lib", "ro:/lib64", "ro:/etc/ld.so.cache"]

  syscall = ["allow:bpf"]
  ```
- **WHEN** the user runs `execave -- <command using bpf>`
- **THEN** the syscall is passed through to the kernel (which may return its own error) rather than being blocked by seccomp

### Use Case: Invalid syscall name rejected at config parse

The user has a misspelled or non-existent syscall name in the `syscall` key. The system rejects it at config load time.

- **GIVEN** a config with:
  ```toml
  syscall = ["allow:ptraec"]
  ```
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating the syscall name is not ruleable

### Use Case: Explicit run command and implicit run are equivalent
The user can invoke sandboxed execution explicitly with `run` or implicitly by providing a command without a subcommand.

- **GIVEN** a file `./execave.toml` with valid rules
- **WHEN** the user runs `execave run -- ls`
- **THEN** the command runs in the sandbox with the configured rules
- **AND** running `execave -- ls` produces equivalent sandbox behavior

### Use Case: Pass env vars via env section

The user adds an `env` section to the config to pass specific host environment variables into the sandbox.

- **GIVEN** a config with:
  ```toml
  env = ["pass:HOME", "pass:PATH"]
  ```
- **WHEN** the user runs `execave -- ls`
- **THEN** the command runs successfully with HOME and PATH set from the host environment

### Use Case: Invalid env rule action rejected

The user has a config with an unrecognized action in the `env` section. The system rejects it at config load time before running any command.

- **GIVEN** a config with:
  ```toml
  env = ["ro:HOME"]
  ```
  (invalid action — only `pass` is valid for env rules)
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating the invalid rule syntax
- **AND** the command is never executed

### Use Case: Duplicate env pass rule rejected

The user has a config where the same environment variable appears twice in the `env` section. The system rejects the config as a configuration error.

- **GIVEN** a config with:
  ```toml
  env = ["pass:HOME", "pass:HOME"]
  ```
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating a duplicate env rule for `HOME`

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

### Use Case: Show effective config as TOML

The user inspects the final merged config to validate layered config composition before running commands. The output includes provenance for all rule sources, including CLI flags.

- **GIVEN** a valid layered config rooted at `./execave.toml`
- **WHEN** the user runs `execave config show`
- **THEN** execave prints TOML with `fs`, `net`, `syscall`, and `env` sections representing effective merged rules
- **AND** emitted rules include source provenance as TOML comments (file paths for file-sourced rules, `<cli>` for CLI-sourced rules)

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

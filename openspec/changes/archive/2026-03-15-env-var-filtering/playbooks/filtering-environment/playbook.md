# Filtering Environment — Controlling which host env vars are visible to sandboxed processes

## Purpose

The user controls which host environment variables are passed into the sandbox. By default no host env vars pass through; explicit `pass` rules in the `env` config section opt specific vars in. This prevents sandboxed processes from reading secrets (API keys, tokens, credentials) present in the host environment.

## ADDED Use Cases

### Use Case: Default-deny: no host env vars pass through without rules

Without any `env` rules in the config, no host environment variables are visible inside the sandbox. A sandboxed command that reads a host env var will see it as unset.

- **GIVEN** a config with no `env` rules
- **AND** the host environment has a variable `MY_VAR=hello`
- **WHEN** the user runs `execave -- sh -c 'echo ${MY_VAR:-unset}'`
- **THEN** the output is `unset` (the variable is not present in the sandbox)

### Use Case: Allow specific env var

The user grants the sandbox access to a specific environment variable by adding a `pass` rule to the `env` section. The variable's current value from the host environment is passed through.

- **GIVEN** a config with:
  ```toml
  env = ["pass:HOME"]
  ```
- **AND** the host environment has `HOME=/home/user`
- **WHEN** the user runs `execave -- sh -c 'echo $HOME'`
- **THEN** the output is `/home/user`

### Use Case: Allow multiple env vars

The user allows several environment variables needed by the sandboxed command. Only those listed are visible; all others remain absent.

- **GIVEN** a config with:
  ```toml
  env = ["pass:HOME", "pass:PATH", "pass:TERM"]
  ```
- **WHEN** the user runs `execave -- env`
- **THEN** the output includes `HOME`, `PATH`, and `TERM` with their host values
- **AND** other host environment variables are absent from the output

### Use Case: No-sandbox mode passes all env vars through

In `--no-sandbox` mode the sandbox boundary is not enforced. Environment variables pass through unfiltered, consistent with the unenforced model for filesystem and network.

- **GIVEN** a config with no `env` rules
- **AND** the host environment has `MY_VAR=hello`
- **WHEN** the user runs `execave --no-sandbox --monitor -- sh -c 'echo $MY_VAR'`
- **THEN** the output is `hello` (env vars pass through in no-sandbox mode)

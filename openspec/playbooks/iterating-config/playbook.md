# Iterating Config — Editing and testing sandbox configs via the CLI

## Purpose

The user edits their TOML config file in an external editor and runs execave with monitoring to observe the access log, adjusting rules between runs. This is the interactive config editing loop.

## Use Cases

### Use Case: Edit config and re-run with monitor

The user edits their TOML config file in an external editor and runs execave with monitoring to observe the access log, adjusting rules between runs.

- **GIVEN** a config file containing rules `fs:ro:/usr/lib` and `fs:rw:/tmp`
- **AND** the user has started `execave --monitor -- ls /usr/lib`
- **WHEN** the process exits and the text log is printed to stderr
- **THEN** the user reviews denied entries in the text log
- **AND** edits the config file in their editor to adjust rules
- **AND** re-runs `execave --monitor -- ls /usr/lib` to verify

### Use Case: Invalid config rejected on start

The user sees a validation error when attempting to run with a config that contains invalid TOML or invalid rules.

- **GIVEN** a config file containing `rules = ["badprefix:something"]`
- **WHEN** the user runs `execave --monitor -- ls /usr/lib`
- **THEN** execave exits with an error containing "unknown resource type"
- **AND** no sandbox is started

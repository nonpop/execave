# Inspecting Effective Config — Viewing the resolved configuration

## Purpose

The user inspects the effective configuration after all layers are resolved. This helps validate that config composition, extends, and overrides produce the intended rules before running commands.

## Use Cases

### Use Case: Print effective layered config
The user asks execave to render the final config after resolving `extends`, deduplicating exact duplicate rules, and preserving effective rule semantics.

- **GIVEN** a root config that extends one or more parent config files
- **WHEN** the user runs `execave config show`
- **THEN** execave prints the effective merged config as TOML to stdout
- **AND** the output reflects the same effective rules used for `run` and `monitor`

### Use Case: See rule provenance in effective config output
The user wants to understand where each emitted rule came from in a layered setup.

- **GIVEN** an effective config that includes rules from multiple source files
- **WHEN** the user runs `execave --config /home/user/project/execave.toml config show`
- **THEN** each emitted rule is preceded by TOML comment lines indicating source file path(s)
- **AND** the comments do not change enforcement behavior; they are display-only metadata

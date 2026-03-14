## ADDED Use Cases

### Use Case: Compose project config from shared base files

The user keeps shared sandbox policy in separate files and composes them into a project config.

- **GIVEN** `/etc/listree.toml` contains:
  ```toml
  fs = ["ro:/home/user/shared/base.txt"]
  ```
- **AND** `/home/user/project/execave.toml` contains:
  ```toml
  extends = ["/etc/listree.toml"]
  fs = ["rw:."]
  ```
- **WHEN** the user runs `execave --config /home/user/project/execave.toml -- cat /home/user/shared/base.txt`
- **THEN** the command succeeds
- **AND** stdout contains the content of `/home/user/shared/base.txt`

### Use Case: Extends paths resolve with absolute, relative, and tilde forms

The user references parent configs with multiple path forms in one config file.

- **GIVEN** `/etc/listree.toml` contains `fs = ["ro:/home/user/data/from-absolute.txt"]`
- **AND** `/home/user/project/agent.toml` contains `fs = ["ro:/home/user/data/from-relative.txt"]`
- **AND** `~/.config/listree/common.toml` contains `fs = ["ro:/home/user/data/from-tilde.txt"]`
- **AND** `/home/user/project/execave.toml` contains:
  ```toml
  extends = ["/etc/listree.toml", "./agent.toml", "~/.config/listree/common.toml"]
  fs = ["rw:."]
  ```
- **WHEN** the user runs `execave --config /home/user/project/execave.toml -- sh -c 'cat /home/user/data/from-absolute.txt /home/user/data/from-relative.txt /home/user/data/from-tilde.txt'`
- **THEN** the command succeeds
- **AND** stdout contains content from all three files

### Use Case: Cross-file conflicting rules are rejected with source file paths

The user composes configs that contain contradictory rules for the same target.

- **GIVEN** `/etc/listree.toml` contains `fs = ["ro:/foo"]`
- **AND** `/home/user/project/execave.toml` contains:
  ```toml
  extends = ["/etc/listree.toml"]
  fs = ["rw:/foo"]
  ```
- **WHEN** the user runs `execave --config /home/user/project/execave.toml -- true`
- **THEN** the system exits with a validation error
- **AND** the error identifies both conflicting rules and both source files

### Use Case: Cyclic extends chain is rejected

The user accidentally creates a cycle between config files.

- **GIVEN** `/home/user/a.toml` contains `extends = ["/home/user/b.toml"]`
- **AND** `/home/user/b.toml` contains `extends = ["/home/user/a.toml"]`
- **WHEN** the user runs `execave --config /home/user/a.toml -- true`
- **THEN** the system exits with an error indicating a cycle in `extends`
- **AND** no sandboxed command is started

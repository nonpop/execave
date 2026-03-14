## ADDED Use Cases

### Use Case: Update a shared base config and re-run a project config

The user edits a shared parent config and verifies that project behavior changes on the next run.

- **GIVEN** `/home/user/base.toml` contains `fs = ["none:/home/user/shared"]`
- **AND** `/home/user/project/execave.toml` contains:
  ```toml
  extends = ["../base.toml"]
  fs = ["rw:."]
  ```
- **WHEN** the user runs `execave --config /home/user/project/execave.toml -- cat /home/user/shared/data.txt`, then edits `/home/user/base.toml` to `fs = ["ro:/home/user/shared"]`, and runs the same command again
- **THEN** the first run exits with a read-denied error for `/home/user/shared/data.txt`
- **AND** the second run succeeds and prints the file content

### Use Case: Resolve layered conflict by following source-aware error details

The user gets a merge validation error and uses the reported file paths to fix it.

- **GIVEN** a project config extends multiple files with contradictory rules for the same path or network identity
- **WHEN** the user runs `execave --config /home/user/project/execave.toml -- true`
- **THEN** the system exits with an error naming the conflicting rules and their source files
- **AND** after the user edits one source file to remove the contradiction, the next run succeeds

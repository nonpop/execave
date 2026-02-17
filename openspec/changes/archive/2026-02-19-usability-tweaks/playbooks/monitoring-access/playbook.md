## MODIFIED Use Cases

### Use Case: View access log in web UI

The user opens the web UI in a browser to view access log entries in a structured table with operation type, target, result, and matched rule columns. Filesystem target paths are displayed in shortened form: relative to config directory when possible, or with `~/` prefix, whichever is shorter.

- **GIVEN** a config at `/home/user/project/execave.toml` with rules `fs:ro:/usr/lib` and `fs:rw:~/project`
- **WHEN** the user runs `execave --monitor=9876 -- ls /usr/lib`
- **THEN** `execave: monitor at http://127.0.0.1:9876` is printed to stderr
- **AND** opening `http://127.0.0.1:9876` in a browser displays a table with `READ` entries
- **AND** paths under the config directory are shortened to relative form (e.g., `src/main.go` instead of `/home/user/project/src/main.go`)
- **AND** paths under the home directory but outside the config directory are shortened with `~` (e.g., `~/.ssh/id_rsa` instead of `/home/user/.ssh/id_rsa`)
- **AND** paths outside the home directory are shown as absolute (e.g., `/usr/lib/libc.so`)
- **AND** rules are shown verbatim as written in the config (e.g., `fs:rw:~/project`)

### Use Case: Verify filesystem enforcement decisions are accurately logged

The user wants to confirm that allowed operations show OK and denied operations show DENY in the monitor, matching actual sandbox behavior. Target paths are displayed in shortened form.

- **GIVEN** a config at `/home/user/project/execave.toml` with rules `fs:ro:~/project/allowed.txt` and `fs:none:~/project/denied.txt`
- **WHEN** the user attempts to access both files with `execave --monitor -- sh -c "cat allowed.txt || true; cat denied.txt || true"`
- **THEN** the allowed file shows `READ allowed.txt OK fs:ro:~/project/allowed.txt`
- **AND** the denied file shows `READ denied.txt DENY fs:none:~/project/denied.txt`

## ADDED Use Cases

### Use Case: Default view shows only denied and unknown entries

The user opens the web UI and sees only DENY and UNKNOWN entries by default. OK entries are hidden until the user opts in.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:/home/user/project`
- **WHEN** the user runs `execave --monitor=9876 -- ls /usr/lib /home/user/project`
- **THEN** the web UI displays only `DENY` and `UNKNOWN` entries
- **AND** `OK` entries for reads under `/usr/lib` and `/home/user/project` are not shown
- **AND** a "Denied only" checkbox is checked by default

### Use Case: Toggle to show all entries

The user unchecks the "denied only" toggle to see all entries including allowed accesses.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:/home/user/project`
- **WHEN** the user runs `execave --monitor=9876 -- ls /usr/lib`
- **AND** opens the web UI and unchecks the "Denied only" checkbox
- **THEN** the web UI displays all entries including `OK` entries for reads under `/usr/lib`

### Use Case: Suppress expected denies with fs:nolog

The user adds an `fs:nolog` rule to suppress known harmless deny entries from a path.

- **GIVEN** a config with rules `fs:ro:/home/user/project` and `fs:nolog:/home/user/project/cache`
- **AND** the sandboxed app always tries to write to `/home/user/project/cache/data` on startup (which is denied by the ro rule, but the app tolerates the failure)
- **WHEN** the user runs `execave --monitor=9876 -- myapp`
- **THEN** the web UI does not display the `WRITE /home/user/project/cache/data DENY` entry
- **AND** other entries under `/home/user/project` are still displayed

### Use Case: Override nolog with fs:log for a subtree

The user nologs a broad directory but overrides with `fs:log` for a specific child path they still want to monitor.

- **GIVEN** a config with rules `fs:ro:/home/user/project`, `fs:nolog:/home/user/project`, and `fs:log:/home/user/project/secret`
- **WHEN** the user runs `execave --monitor=9876 -- sh -c "cat /home/user/project/data.txt; cat /home/user/project/secret/key.pem"`
- **THEN** the web UI does not display entries for `/home/user/project/data.txt` (suppressed by nolog)
- **AND** the web UI displays entries for `/home/user/project/secret/key.pem` (overridden by the more specific log rule)

### Use Case: Suppress expected network denies with net:nolog

The user adds a `net:nolog` rule to suppress known harmless network deny entries.

- **GIVEN** a config with rules `net:https:api.example.com:443` and `net:nolog:telemetry.example.com:443`
- **AND** the sandboxed app always tries to reach `telemetry.example.com:443` on startup (denied, but the app continues fine)
- **WHEN** the user runs `execave --monitor=9876 -- myapp`
- **THEN** the web UI does not display the `HTTPS telemetry.example.com:443 DENY` entry
- **AND** other network entries are still displayed

### Use Case: Override net:nolog with net:log for specific endpoint

The user nologs a wildcard domain but overrides with `net:log` for a specific subdomain.

- **GIVEN** a config with rules `net:https:*.example.com:443`, `net:nolog:*.example.com:443`, and `net:log:api.example.com:443`
- **WHEN** the user runs `execave --monitor=9876 -- sh -c "curl https://cdn.example.com/ || true; curl https://api.example.com/ || true"`
- **THEN** the web UI does not display entries for `cdn.example.com:443` (suppressed by nolog)
- **AND** the web UI displays entries for `api.example.com:443` (overridden by the more specific log rule)

### Use Case: Toggle to show nolog-suppressed entries

The user unchecks the "apply nolog rules" toggle to temporarily see all entries including those suppressed by nolog rules.

- **GIVEN** a config with rules `fs:ro:/home/user/project` and `fs:nolog:/home/user/project`
- **WHEN** the user runs `execave --monitor=9876 -- ls /home/user/project`
- **AND** opens the web UI and unchecks the "Apply nolog rules" checkbox
- **THEN** the web UI displays all entries for `/home/user/project`, including those that were suppressed

### Use Case: Both filters are independent

Both the "denied only" toggle and "apply nolog rules" toggle operate independently. An entry must pass both filters to be displayed.

- **GIVEN** a config with rules `fs:ro:/usr/lib`, `fs:rw:/home/user/project`, and `fs:nolog:/usr/lib`
- **WHEN** the user runs `execave --monitor=9876 -- ls /usr/lib /home/user/project`
- **AND** unchecks "Denied only" but leaves "Apply nolog rules" checked
- **THEN** the web UI displays OK entries for `/home/user/project` (passes both filters)
- **AND** does not display OK entries for `/usr/lib` (passes mode filter but blocked by nolog)

### Use Case: Log rule specificity matches access rule semantics for fs

Filesystem log rules use longest-prefix-match, same as access rules. The most specific log/nolog rule for a path wins.

- **GIVEN** a config with rules `fs:ro:/home/user`, `fs:nolog:/home/user`, `fs:log:/home/user/project`, and `fs:nolog:/home/user/project/vendor`
- **WHEN** the user runs `execave --monitor=9876 -- sh -c "cat /home/user/.bashrc; cat /home/user/project/main.go; cat /home/user/project/vendor/lib.go"`
- **THEN** entries for `/home/user/.bashrc` are suppressed (matches `fs:nolog:/home/user`)
- **AND** entries for `/home/user/project/main.go` are displayed (matches `fs:log:/home/user/project`)
- **AND** entries for `/home/user/project/vendor/lib.go` are suppressed (matches `fs:nolog:/home/user/project/vendor`)

### Use Case: Log rule specificity matches access rule semantics for net

Network log rules use the same specificity ranking as access rules. Exact domain beats wildcard; longer CIDR prefix beats shorter.

- **GIVEN** a config with rules `net:https:*.example.com:443`, `net:nolog:*.example.com:443`, and `net:log:api.example.com:443`
- **WHEN** the user runs `execave --monitor=9876 -- sh -c "curl https://cdn.example.com/ || true; curl https://api.example.com/ || true"`
- **THEN** entries for `cdn.example.com:443` are suppressed (matches wildcard nolog)
- **AND** entries for `api.example.com:443` are displayed (exact match log overrides wildcard nolog)

## MODIFIED Use Cases

### Use Case: View access log in web UI

The user opens the web UI in a browser to view access log entries in a structured table with operation type, target, result, and matched rule columns. Filesystem target paths are displayed in shortened form: relative to config directory when possible, or with `~/` prefix, whichever is shorter. By default, only DENY and UNKNOWN entries are shown; the user can toggle to show all entries.

- **GIVEN** a config at `/home/user/project/execave.toml` with rules `fs:ro:/usr/lib` and `fs:rw:~/project`
- **WHEN** the user runs `execave --monitor=9876 -- ls /usr/lib`
- **THEN** `execave: monitor at http://127.0.0.1:9876` is printed to stderr
- **AND** opening `http://127.0.0.1:9876` in a browser displays a table with only `DENY` and `UNKNOWN` entries by default
- **AND** a "Denied only" checkbox is checked by default; unchecking it reveals all entries including `OK`
- **AND** paths under the config directory are shortened to relative form (e.g., `src/main.go` instead of `/home/user/project/src/main.go`)
- **AND** paths under the home directory but outside the config directory are shortened with `~` (e.g., `~/.ssh/id_rsa` instead of `/home/user/.ssh/id_rsa`)
- **AND** paths outside the home directory are shown as absolute (e.g., `/usr/lib/libc.so`)
- **AND** rules are shown verbatim as written in the config (e.g., `fs:rw:~/project`)

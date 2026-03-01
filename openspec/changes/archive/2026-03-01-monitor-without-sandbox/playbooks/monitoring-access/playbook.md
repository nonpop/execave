## ADDED Use Cases

### Use Case: Observe native filesystem accesses to diagnose sandbox failures

The user runs a command with `--no-sandbox --monitor` to observe all filesystem accesses the program makes on the real host filesystem, without bwrap isolation. This is useful for diagnosing why a program fails inside the sandbox — the access log shows every path the program probes, including ancestor directories or fallback paths that might be missing in the sandboxed view.

- **GIVEN** a config with filesystem rules (e.g., `fs:ro:/usr/lib`, `fs:rw:~/project`)
- **WHEN** the user runs `execave --no-sandbox --monitor -- myapp`
- **THEN** `myapp` runs natively on the host filesystem (no bwrap, no filesystem isolation)
- **AND** the access log is printed to stderr after the process exits (same as `--monitor` without `--no-sandbox`)
- **AND** log entries show all filesystem accesses with result `UNENFORCED`, making it immediately clear that no sandboxing was active
- **AND** the user can see accesses to ancestor directories, fallback library paths, and other paths that are not present in the sandboxed view

### Use Case: Write native access log to file in real time

The user runs with `--no-sandbox --monitor=<path>` to stream the native access log to a file while the program runs, useful for long-running programs.

- **GIVEN** a config with filesystem rules
- **WHEN** the user runs `execave --no-sandbox --monitor=native.log -- myapp`
- **AND** runs `tail -f native.log` in another terminal
- **THEN** `myapp` runs natively on the host filesystem
- **AND** new log entries appear in the tail output while the command is still running

### Use Case: Observe native network accesses without isolation

The user runs with `--no-sandbox --monitor` and the config has net rules. The network proxy starts and HTTP_PROXY/HTTPS_PROXY are set, so proxy-aware HTTP traffic goes through the proxy and is logged against net rules, but there is no network namespace isolation. Connections are never blocked — rules are evaluated for logging only.

- **GIVEN** a config with no net rules (empty rules)
- **WHEN** the user runs `execave --no-sandbox --monitor --show-allowed -- curl http://<local-server>/`
- **THEN** `curl` is proxy-aware and sends its request through the proxy (HTTP_PROXY is set)
- **AND** the request reaches the server and succeeds (not blocked with 403 despite no matching rule)
- **AND** the text log displays an entry with operation `HTTP`, target `<local-server>`, result `UNENFORCED`
- **AND** the host network interfaces remain accessible (no `--unshare-net`)

### Use Case: Error when --no-sandbox is used without --monitor

The user attempts to run with `--no-sandbox` but forgets to specify `--monitor`. execave exits with a clear error message.

- **GIVEN** a valid config
- **WHEN** the user runs `execave --no-sandbox -- myapp` (without `--monitor`)
- **THEN** execave exits with an error message indicating that `--monitor` is required when `--no-sandbox` is used
- **AND** `myapp` is not executed

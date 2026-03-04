# Execave

Filesystem and network sandbox for Linux using bubblewrap.

⚠️ Personal project, not a security expert. Uses established tools but may have configuration bugs. See `docs/security-model.md`.

## Quick Start

```bash
# Dependencies (Debian/Ubuntu)
sudo apt install bubblewrap strace

# Install
go install ./cmd/execave

# Run
execave --config execave.toml.example -- ls -la

# If execave command not found, add Go's bin directory to PATH:
export PATH="$PATH:$(go env GOPATH)/bin"
```

## Configuration

**Filesystem rules:** `<permission>:<path>` where permission is `ro`, `rw`, or `none`. More specific paths win. Paths may use `~/...` (expanded to the current user's home directory) or be relative to the config file location.

**Network rules:** `<protocol>:<target>:<port>` where protocol is `http` or `none`. Target can be a domain, IP, or CIDR. Port is a number or `*` wildcard.

**Log visibility rules:** Control which entries appear in the monitor output. `log:<path>` / `nolog:<path>` show/hide filesystem entries within the `fs` section; `log:<target>:<port>` / `nolog:<target>:<port>` show/hide network entries within the `net` section. Uses the same longest-prefix-match (fs) and target-specificity (net) resolution as access rules. Entries hidden by nolog rules are still enforced — this only affects display.

```toml
fs = [
  "ro:/usr",
  "ro:/lib",
  "ro:/lib64",
  "ro:/etc/ld.so.cache",

  "rw:~/project",   # tilde expands to home directory
  "none:.",

  "nolog:/etc/fonts",            # hide known-harmless denied reads in monitor
]

net = [
  "http:api.example.com:443",
  "http:*.internal.corp:*",
  "none:evil.example.com:443",

  "nolog:telemetry.example.com:*",
]
```

**Automatic mounts** (not in config): `/dev`, `/proc`, `/tmp`

**Network is isolated.** Only connections matching net rules are allowed; without net rules the proxy is deny-all. Apps that ignore `HTTP_PROXY`/`HTTPS_PROXY` have no network access regardless (no NIC inside the sandbox).

**Intra-sandbox servers:** execave injects `HTTP_PROXY` into the sandboxed process's environment. HTTP clients route all connections—including to `localhost`—through the host-side proxy, which cannot reach servers inside the sandbox's network namespace. To connect to an intra-sandbox server, bypass the proxy: set `NO_PROXY=localhost,127.0.0.1`.

**Minimum paths vary by command.** Start with `/usr`, `/lib`, `/lib64`, `/etc/ld.so.cache` and use `--monitor` to narrow down what's actually needed.

**Note on `fs:none`:** Directories are replaced with an empty tmpfs (in-memory). More specific rules can override this—`fs:rw` under `fs:none` writes to the real filesystem. Writes to the tmpfs itself are ephemeral. Files use `/dev/null` and return permission denied.

See `execave.toml.example` for a comprehensive config that supports most standard tools.

### Building your config with --monitor

You're not expected to know every path a command needs upfront. Use `--monitor` to trace filesystem and network access. Two output modes are available:

```bash
execave --monitor -- your-command            # text log to stderr (buffered until exit)
execave --monitor=access.log -- your-command # text log to file (real-time, tailable)
```

Both modes write one entry per line:

| Operation | Target | Result | Rule |
|-----------|--------|--------|------|
| READ | /usr/lib/libc.so.6 | OK | ro:/usr |
| WRITE | /home/user/output.txt | DENY | ro:/home/user |
| READ | /etc/passwd | DENY | no-matching-rule |
| HTTP | api.example.com:443 | OK | http:api.example.com:443 |
| HTTP | evil.example.com:80 | DENY | no-matching-rule |

The file mode (`--monitor=<path>`) writes entries in real-time as syscalls happen (tailable with `tail -f`). The stderr mode (`--monitor` or `--monitor=-`) buffers until the process exits, then writes to stderr.

**Filter flags** control which entries appear in the output:
- `--show-allowed`: include OK (allowed) entries. Default: denied only.
- `--show-nolog`: include entries matching `nolog` rules. Default: hidden.

**Workflow:** Start with `execave.toml.example`, run with `--monitor`, check for DENY entries (filesystem paths are shown in shortened form relative to the config directory or home), edit the config, grant only what's necessary, repeat.

## Seccomp

A BPF deny-list blocks dangerous syscalls by default. With `--monitor`, blocked attempts appear as `SYSCALL` entries in the access log.

To allow a specific syscall, add `syscall:allow:<name>` to your config. To hide a syscall from the monitor log, add `syscall:nolog:<name>`.

**Note:** When `--monitor` is active, strace uses ptrace to trace the sandboxed process. Since Linux allows only one ptracer per process, `syscall:allow:ptrace` will not make ptrace usable inside the sandbox.

**Blocked syscalls:**

`ptrace`, `bpf`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`, `kexec_load`, `kexec_file_load`, `mount`, `umount2`, `unshare`, `setns`, `pivot_root`, `chroot`, `open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `keyctl`, `add_key`, `request_key`, `reboot`, `init_module`, `finit_module`, `delete_module`, `acct`, `swapon`, `swapoff`, `settimeofday`, `adjtimex`, `clock_adjtime`, `syslog`, `nfsservctl`

## Requirements

- Linux, Go 1.25+, `bubblewrap` 0.11.x, `strace` 6.18 (for `--monitor`)

Execave pins to specific known-good versions of `bwrap` and `strace` and checks the installed versions at startup. Older versions or major-version bumps cause execave to exit with an error; newer minor versions within the same major series print a warning but continue.

## Documentation

- `docs/architecture.md` - System design
- `docs/security-model.md` - Threat model and limitations

## License

MIT

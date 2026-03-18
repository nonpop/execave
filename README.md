# Execave

Filesystem and network sandbox for Linux using bubblewrap.

> [!WARNING]
> Personal project, not a security expert. Uses established tools but may have configuration bugs. See `docs/security-model.md`.

> [!IMPORTANT]
> I won't accept PRs or respond to issue reports unless they are about security bugs.

## Quick Start

```bash
# Dependencies (Debian/Ubuntu)
sudo apt install bubblewrap strace

# Install
go install ./cmd/execave

# Run (with config file)
execave --config execave.toml.example run -- ls -la

# Run with inline rules (no config file)
execave --no-config --fs ro:/usr --fs ro:/lib --fs ro:/lib64 -- ls -la

# If execave command not found, add Go's bin directory to PATH:
export PATH="$PATH:$(go env GOPATH)/bin"
```

## Configuration

**Filesystem rules:** `<permission>:<path>` where permission is `ro`, `rw`, or `none`. More specific paths win. Paths may use `~/...` (expanded to the current user's home directory) or be relative to the config file location.

**Network rules:** `<protocol>:<target>:<port>` where protocol is `http` or `none`. Target can be a domain, IP, or CIDR. Port is a number or `*` wildcard.

**Environment rules:** `pass:<NAME>` forwards the named host environment variable into the sandbox. Without env rules, no host env vars enter the sandbox (default-deny).

```toml
fs = [
  # Executables and shared libraries
  "ro:/usr",
  "ro:/lib",
  "ro:/lib64",

  # Dynamic linker configuration
  "ro:/etc/ld.so.cache",

  # DNS resolution and TLS certificates
  "ro:/etc/hosts",
  "ro:/etc/resolv.conf",
  "ro:/etc/ssl/certs",

  # Project directory (read-write)
  "rw:.",
]

env = [
  "pass:HOME",
  "pass:PATH",
]

net = [
  # "http:example.com:443",
  # "http:*.example.com:*",
]

syscall = [
  # "allow:ptrace",
]
```

**Automatic mounts** (not in config): `/dev`, `/proc`, `/tmp`

**Network is isolated.** Only connections matching net rules are allowed; without net rules the proxy is deny-all. Apps that ignore `HTTP_PROXY`/`HTTPS_PROXY` have no network access regardless (no NIC inside the sandbox).

**Intra-sandbox servers:** execave injects `HTTP_PROXY`/`HTTPS_PROXY` into the sandboxed process's environment. HTTP clients route all connections—including to `localhost`—through the host-side proxy, which cannot reach servers inside the sandbox's network namespace. To connect to an intra-sandbox server, bypass the proxy by setting `NO_PROXY=localhost,127.0.0.1` inside the sandbox (e.g. in the command itself or via env rules). Note: any host-side `NO_PROXY`/`no_proxy` values are stripped and do not carry into the sandbox.

**Minimum paths vary by command.** Start with `/usr`, `/lib`, `/lib64`, `/etc/ld.so.cache` and use `monitor` to narrow down what's actually needed.

**Note on `fs` `none`:** Directories are replaced with an empty tmpfs (in-memory). More specific rules can override this—a `fs` `rw` rule under a `none` path writes to the real filesystem. Writes to the tmpfs itself are ephemeral. Files use `/dev/null` and return permission denied.

See `execave.toml.example` for a comprehensive config that supports most standard tools.

### Inline rules via CLI flags

Rules can be specified directly on the command line without a config file. Each flag is repeatable:

```bash
# Override or supplement a config file
execave --fs ro:/extra/path --net http:api.example.com:443 -- python script.py

# No config file at all — only CLI rules apply
execave --no-config --fs ro:/usr --fs ro:/lib --fs ro:/lib64 --env pass:HOME -- ls -la
```

Available flags (all work with `run`, `monitor`, and `config show`):

| Flag | Example |
|------|---------|
| `--fs <rule>` | `--fs ro:/usr` |
| `--net <rule>` | `--net http:api.example.com:443` |
| `--syscall <rule>` | `--syscall allow:ptrace` |
| `--env <rule>` | `--env pass:HOME` |
| `--extends <path>` | `--extends ~/shared/base.toml` |

Think of the CLI flags as constructing a virtual config file that implicitly extends the file-based config (if any) and becomes the root config. Paths in CLI rules are resolved relative to the current working directory (unlike config-file rules, which resolve relative to the config file).

### Layered configs via extends

Configs can load additional files with `extends = ["../base/execave.toml", "~/shared/execave.toml"]`. Each path is expanded (absolute paths stay absolute, relative paths resolve next to the extending file, and `~` expands to the invoking user’s home directory).

The `--extends` CLI flag loads base files the same way, resolving paths relative to the current working directory.

### Building your config with monitor

You're not expected to know every path a command needs upfront. Use `monitor` to trace filesystem and network access. Two output modes are available:

```bash
execave monitor -- your-command                       # text log to stderr (buffered until exit)
execave monitor --output-path access.log -- your-command   # text log to file (real-time, tailable)
```

Both modes write one entry per line:

| Operation | Target | Result | Rule |
|-----------|--------|--------|------|
| READ | /usr/lib/libc.so.6 | OK | ro:/usr |
| WRITE | /home/user/output.txt | DENY | ro:/home/user |
| READ | /etc/passwd | DENY | no-matching-rule |
| HTTP | api.example.com:443 | OK | http:api.example.com:443 |
| HTTP | evil.example.com:80 | DENY | no-matching-rule |

The file mode (`monitor --output-path <path>`) writes entries in real-time as syscalls happen (tailable with `tail -f`). The stderr mode (default) buffers until the process exits, then writes to stderr.

**Filter flags** on `monitor` control which entries appear in the output:
- `--show-allowed`: include OK (allowed) entries. Default: denied only.
- `--no-sandbox`: run without the bubblewrap sandbox (filesystem and network rules are not enforced). Useful for tracing a command before writing any rules, but provides no isolation.

**Workflow:** Start with `execave.toml.example`, run with `monitor`, check for DENY entries (filesystem paths are shown in shortened form relative to the config directory or home), edit the config, grant only what's necessary, repeat.

### Inspect effective layered config

Use `config show` to inspect the merged effective config that `run` and `monitor` enforce:

```bash
execave config show
execave --config /path/to/execave.toml config show
execave --no-config --fs ro:/usr --fs ro:/lib config show
```

The output is TOML with `fs`, `net`, `syscall`, and `env` sections plus `# <source>` comments showing which file (or `<cli>`) each rule came from.

## Seccomp

A BPF deny-list blocks dangerous syscalls by default. With `monitor`, blocked attempts appear as `SYSCALL` entries in the access log.

To allow a specific syscall, add `allow:<name>` to the `syscall` section of your config.

**Note:** When `monitor` is active, strace uses ptrace to trace the sandboxed process. Since Linux allows only one ptracer per process, `allow:ptrace` will not make ptrace usable inside the sandbox.

**Blocked syscalls:**

`ptrace`, `bpf`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`, `kexec_load`, `kexec_file_load`, `mount`, `umount2`, `unshare`, `setns`, `pivot_root`, `chroot`, `open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `keyctl`, `add_key`, `request_key`, `reboot`, `init_module`, `finit_module`, `delete_module`, `acct`, `swapon`, `swapoff`, `settimeofday`, `adjtimex`, `clock_adjtime`, `syslog`, `nfsservctl`

## Requirements

- Linux, Go 1.25+, `bubblewrap` 0.11.x, `strace` 6.19 (for `monitor`)

Execave pins to specific known-good versions of `bwrap` and `strace` and checks the installed versions at startup. Older versions or major-version bumps cause execave to exit with an error; newer minor versions within the same major series print a warning but continue.

## Reporting bugs

If you encounter a security-related bug or misfeature, please open an issue. For any other bugs, including crashes, you may open issues/PRs but I cannot guarantee I have time to respond in any way.

## Documentation

- `docs/architecture.md` - System design
- `docs/security-model.md` - Threat model and limitations

## License

MIT

# Usability Feature Ideas

Elaborations on six candidate features for improving the execave config authoring and
day-to-day usage experience. Grounded in the current architecture as of 2026-03.

---

## 1. Auto-config generation from a monitor run

**Problem.** Authoring a config from scratch means guessing rules, running the sandbox,
reading the access log, adding the missing rules, and repeating. Even with `monitor`
mode the iteration loop requires manually translating `DENY` log lines into rule strings.

**Idea.** Add a `--generate-config` flag to the monitor subcommand (or a new subcommand
`execave generate`). After the command exits, collect all `accesslog.Entry` values with
`ResultOK` or `ResultDeny`, group by operation type and target, and emit a minimal TOML
config that would allow everything observed:

- `READ` and `WRITE` entries → `fs` rules (`ro:` / `rw:` respectively).
- `HTTP` entries → `net` rules.
- `SYSCALL` entries → `syscall` rules.

The generated config should include `extends` pointing to a sensible base profile so
the output is diff-friendly and can be committed as-is or refined.

**Architecture notes.**
- `accesslog.Logger` currently writes formatted text. The cleanest hook is to expose
  `Logger.Entries() []Entry` (or accept a callback/sink) so the generator can consume
  the same entries without re-parsing the text output.
- `fsrules.Rule.Canonical()` already produces the `permission:path` form that belongs
  in the TOML `fs` array.
- Because monitor mode sets `unenforced: true`, every observed access is logged
  regardless of current rules—so the generated config is guaranteed to cover the run.

**Open questions.** How aggressively should paths be generalized? (e.g. `~/.config/git`
vs. `~/.config`). A simple first version emits exact observed paths; a smarter version
could optionally coalesce paths sharing a common prefix.

---

## 2. Config rule suggestions on denial

**Problem.** `DENY` lines in the access log tell the user *what* was denied but not
*how* to fix it. The user must know the rule syntax and mentally construct the fix.

**Idea.** After a monitor or run session (or inline in the `--output-path` log), append
a "Suggestions" section listing the exact rule string to add for each denied access:

```
Suggestions:
  # fs:   add  ro:~/.config/git/config
  # net:  add  allow:api.example.com:443
```

The mapping is straightforward:
- `DENY READ <path>` → `ro:<path>` (promote to `rw` if a `WRITE` also exists).
- `DENY WRITE <path>` → `rw:<path>`.
- `DENY HTTP <host:port>` → `allow:<host:port>`.
- `DENY SYSCALL <name>` → `allow:<name>`.

**Architecture notes.**
- This sits naturally in `accesslog` or in the CLI layer that owns the output path.
  Given that `accesslog.Logger` already owns deduplication, adding a `Suggestions()
  []string` method keeps the logic co-located with the entries.
- `fsrules.Rule.Canonical()` and the equivalent for `netrules` / `syscallrules` provide
  the formatting.
- The suggestion block can be written to the same `--output-path` file after the
  command exits, clearly delimited (e.g. `# --- Suggestions ---`) so it is both
  human-readable and easy to grep.

**Security note.** Suggestions are advisory only; they surface what was observed, not
what is safe. The user must still review them before adding to a config.

---

## 3. Lightweight denial notifications in `run` mode

**Problem.** In `run` mode (no `--monitor` flag), filesystem denials are completely
silent from execave's perspective—bwrap simply makes the paths invisible. Network
denials return HTTP 403 via the proxy but execave logs nothing. Users diagnosing "why
isn't my agent doing anything?" have no signal without switching to `monitor` mode,
which carries strace overhead.

**Idea.** Add an optional lightweight denial-logging path in `run` mode that writes
denied accesses to stderr (or a file) without full strace coverage:

- **Network denials** are already detected in `proxy.go`; the proxy already knows when
  it rejects a CONNECT or HTTP request. Routing those rejections to an `accesslog.Logger`
  (with `ResultDeny`) requires a small addition to the proxy's handler.
- **Filesystem denials** are harder because bwrap enforces them in the kernel and
  execave gets no callback. Two lightweight options:
  1. Mount a small FUSE or overlay shim on watched directories that records denials
     without full strace. (High complexity.)
  2. Document that filesystem denial visibility requires `--monitor` and only implement
     network denial logging for now.

**Architecture notes.**
- `run.SandboxConfig` already holds a `*MonitorConfig`. A new `DenialLogPath string`
  field (or reuse `MonitorConfig` with a minimal mode) could gate the lightweight path.
- `accesslog.Logger` accepts an `io.Writer`; passing `os.Stderr` or a log file costs
  nothing new.
- This feature must not slow down the non-monitor hot path. The proxy goroutine already
  exists, so adding a log call there has negligible overhead.

---

## 8. `config test` — dry-run permission queries

**Problem.** After editing a config the user has no way to check "would path X be
readable?" or "would host Y be reachable?" without launching a full sandbox.

**Idea.** A `config test` subcommand (or `--test` flags on `config show`) that accepts
a list of targets and reports the effective permission for each:

```
$ execave config test --config execave.json \
    --fs ro:/home/user/.config/git/config \
    --net api.example.com:443
fs   ro:/home/user/.config/git/config  -> ALLOW (rule: ro:~/.config)
net  api.example.com:443               -> DENY   (no matching rule)
```

**Architecture notes.**
- `fsrules.Resolver.Resolve(path)` and the equivalent `netrules` resolver already
  encapsulate the permission lookup logic. `config test` is essentially a thin CLI
  wrapper that loads the config via `run.LoadRuntimeConfig`, instantiates the resolvers,
  and calls `Resolve` for each provided target.
- No sandbox, no bwrap, no strace—purely in-process rule evaluation.
- The `config render` subcommand (via `config.RenderEffectiveTOML`) shows the merged
  rules; `config test` complements it by answering point queries rather than showing
  the full rule set.

**Extension.** Accept a list of paths/hosts from stdin (one per line) for bulk testing
in scripts.

---

## 9. Machine-readable (JSON) access log

**Problem.** Agent frameworks and CI pipelines that wrap execave want to programmatically
detect and react to denials—e.g., surface them as structured events, fail a build on
unexpected denials, or feed them back into a rule-generation pipeline. Parsing the
current text format is fragile.

**Idea.** Add a `--log-format json` flag (or `--json-log-path`) that writes one JSON
object per line to a file (or stderr):

```json
{"result":"DENY","operation":"READ","target":"/home/user/.ssh/id_rsa","rule":"no-matching-rule","ts":"2026-03-15T10:00:00Z"}
```

**Architecture notes.**
- `accesslog.Entry` already contains all necessary fields (`Operation`, `Target`,
  `Result`, `Rule`). Adding a `Time time.Time` field (populated at log time) gives
  consumers an ordering handle.
- `accesslog.Logger` currently formats via `formatEntry`. Adding a JSON writer variant
  is a small change: either a `Logger` option (`Format: "json"`) or a second writer
  accepted alongside the text writer.
- The JSON log can be written to a separate path from the human-readable log so both
  are available simultaneously—useful when a human is watching a terminal and a script
  is watching a file.
- Keeping the schema minimal and stable matters: agent frameworks will pin to it.

---

## 10. Sandbox introspection from inside

**Problem.** A sandboxed process (especially an AI agent or a tool that probes its
environment) cannot know what it is allowed to do without attempting the operation and
observing the failure. This leads to spurious errors, retry loops, and confused agents.

**Idea.** Let the sandboxed process query its own effective permissions without
performing the operation. Two approaches, in increasing complexity:

### Option A: Static permissions manifest (simple)

Before launching the sandbox, serialize the effective config (fs rules, net rules) to
a JSON or TOML file and bind-mount it read-only at a well-known path inside the
sandbox, e.g. `/run/execave/permissions.json`. The process (or its framework) can read
this file to discover what is allowed.

- Minimal overhead: one file write per `execave run` invocation.
- No new IPC. The sandboxed process reads a regular file.
- `config.RenderEffectiveTOML` already produces the merged config; a JSON variant of
  the same data is straightforward.
- Limitation: the manifest reflects rules, not actual filesystem state (a path may be
  allowed by rules but not exist).

### Option B: Query socket (dynamic)

Expose a Unix domain socket at a path inside the sandbox (e.g. `/run/execave/query.sock`,
with the path advertised via `EXECAVE_QUERY_SOCK`). The sandboxed process sends
`{"op":"fs","path":"/some/path"}` and receives `{"result":"ro"}` or `{"result":"deny"}`.

- Allows runtime queries including symlink resolution against the actual filesystem.
- Requires a goroutine in the host process to serve the socket—architecturally similar
  to the tunnel mechanism already used for network proxying.
- Security: the socket is inside the sandbox boundary (bwrap bind-mount), so only the
  sandboxed process can reach it. The host-side handler must not expose anything beyond
  what the config permits.

**Recommendation.** Start with Option A (static manifest) as it has near-zero risk and
covers the most common case (agent frameworks that read capabilities at startup). Option B
adds value for dynamic use cases but requires careful design of the query API and
socket lifetime.

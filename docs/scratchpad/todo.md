# execave TODOs

- go through TODOs in code & other files

- monitor to execave-access.log by default, and allow stderr/out with
- maybe need to allow http:*:*

- validate config command, show effective config command, config layering
  - Means: CLI commands to check config validity, display final effective config after processing, and support layering multiple config files with overrides.
  - Assessment: Important. Validate + show-effective are high-value for a security tool. Config layering adds complexity and attack surface (which layer wins? can a child widen parent permissions?) — defer until there's a concrete use case.

- --no-sandbox should have a way of logging only those entries which would be denied
  - Means: In --no-sandbox mode, all accesses are logged as "unenforced." This would filter to show only what would have been denied if the sandbox were active.
  - Assessment: Important. This is the core UX loop for building a config: run without sandbox, see what would break, add rules, repeat. Without this filter the user drowns in noise.

- bells don't get through the sandbox?
  - Means: Terminal bell characters (BEL) may not propagate through bwrap's --new-session or pty handling.
  - Assessment: Nice to have / minor. UX papercut, not a security issue. May be inherent to --new-session and unfixable without removing that flag.

- actually do log noncustomizable syscalls, too. But when added to config, error with "kernel won't allow in sandboxes". Allow in syscall:nolog, though.
  - Means: The 13 defense-in-depth syscalls are currently invisible in logs. Log them when hit, error if user tries syscall:allow rules for them, allow syscall:nolog to suppress.
  - Assessment: Important. Visibility helps users understand why programs fail. Error-on-config-rule prevents false confidence. syscall:nolog is consistent with existing patterns.

## easy, probably

- config sections [fs], [net], ...
  - Means: Move from flat rules = [...] to sectioned fs = [...], net = [...], syscall = [...].
  - Assessment: Already done (commit ec9f387). Remove from TODO. Note: canonical openspec spec and actual execave.toml haven't been updated yet.

- rules for disabling commands: `cmd:deny:gh` looks up gh -> /usr/bin/gh and adds `fs:deny:/usr/bin/gh`
  - Means: Convenience rule type that resolves a binary name via $PATH and creates an fs:none rule for it.
  - Assessment: Questionable. PATH-dependency makes config environment-specific. Binary could exist at multiple paths or be invoked via symlinks. Gives false sense of security — fs:none:/usr/bin/gh is clear enough on its own.

- env var expansion in rules
  - Means: Allow $HOME or ${HOME} in rule paths, e.g. rw:$HOME/project. Expand once at parse time.
  - Assessment: Nice to have. Makes configs portable. Low risk if expanded at parse time. Undefined vars should error, not silently expand to empty.

- should use absolute path for bwrap?
  - Means: Currently uses exec.LookPath("bwrap") (PATH lookup) then validates. The question is whether to hardcode /usr/bin/bwrap.
  - Assessment: Probably not worth changing. PATH lookup + validation (root-owned, not world-writable) is already secure. Hardcoding breaks distros that install bwrap elsewhere.

- add commands? run, monitor
  - Means: Add explicit execave run and execave monitor subcommands instead of overloading the root command with --monitor and --no-sandbox flags.
  - Assessment: Nice to have. Would clarify CLI UX. Breaking change — worth doing if pre-1.0.

- check public apis are minimal
  - Means: Audit exported symbols across internal/ packages to ensure nothing is exported unnecessarily.
  - Assessment: Nice to have. Go's internal/ already prevents external use, so blast radius is limited. Minimal exports ease refactoring.

- extract strace parser
  - Means: The strace output parser (5 regexes, straceParser struct, parseResult) is embedded as unexported code in monitor.go. Extract to its own package.
  - Assessment: Nice to have. Good for testability and separation of concerns. The parser is non-trivial and would benefit from independent unit tests.

- stat, exec etc, maybe useful after all
  - Means: stat/lstat/access/faccessat and execve are currently OperationIgnored or handled specially. Reconsider whether logging them is useful.
  - Assessment: Questionable. stat/access are extremely high-frequency — logging them creates massive noise. execve tracking is genuinely useful for security auditing. Yes for exec, no for stat/access.

- nicer symlink resolve logging (A -> B -> C [DENY])
  - Means: Currently symlink resolution logs each hop separately. Show full chain in one log line instead.
  - Assessment: Nice to have. Better UX for debugging config. SymlinkChain already tracks hops — this is a display concern in textlog.

- log stderr stuff to file
  - Means: Capture stderr output (from bwrap, strace, or sandboxed process) to a log file for post-mortem debugging.
  - Assessment: Nice to have. Useful for debugging failures where stderr is lost or interleaved. Low complexity.

- vendoring (maybe not needed, go.sum suffices?)
  - Means: Whether to go mod vendor to check in all deps, or rely on go.sum for reproducibility.
  - Assessment: Probably not needed. go.sum + module proxy provides reproducible builds. Vendoring adds repo bloat. Only worth it for offline builds or in-tree dep auditing.

## medium, probably

- clean up test helpers & duplicate tests
  - Means: The test helper DSL and package-level test helpers have accumulated duplication.
  - Assessment: Nice to have. Standard maintenance, reduces friction for writing new tests.

- add pre & post conditions
  - Means: Formalize preconditions and postconditions in code with panic checks. CLAUDE.md mandates this but it may not be consistently applied.
  - Assessment: Important. Consistent with the project's security-critical nature. Panic on violated invariants prevents silent misbehavior.

- heuristic for determining strace output compatibility?
  - Means: Auto-detect whether the installed strace version produces output the parser can handle, rather than hard-failing or silently misinterpreting.
  - Assessment: Important. A compatibility check at startup (e.g. trace a known syscall and verify parse success) would prevent silent security failures where access checks are skipped because the parser couldn't understand the output.

## hard, probably

- put monitor inside sandbox
  - Means: Currently the monitor (strace) runs outside the sandbox as trusted code. This proposes moving it inside to reduce trusted surface area.
  - Assessment: Questionable / likely harmful. Architecture explicitly positions the monitor as trusted. Moving it inside lets an untrusted process interfere with its own monitoring. Strace needs ptrace capability which conflicts with seccomp. Architecturally unsound unless addressing a very specific threat model.

- EXPERIMENT with converting specs directly to e2e tests:
  - Means: Auto-generate or directly express e2e tests from spec files using a DSL like configContains/read/accessAllowed.
  - Assessment: Interesting but speculative. Could reduce spec-test drift, but the gap between declarative specs and executable tests is large. Existing scenario DSL is already readable. Worth experimenting, not committing to.

    configContains("fs:rw:/home/user/project")
    read("/home/user/project/main.go")
    accesAllowed()

## ???

- bwrap:
  --argv0 VALUE ?
  --uid UID, --gid GID?
  --hostname HOSTNAME?
  - Means: Whether to expose these bwrap features: fake process name, fake user/group IDs inside sandbox, fake hostname.
  - Assessment: --hostname is nice to have (reduces info leakage). --uid/--gid is questionable (could cause confusion). --argv0 is probably not needed (very niche, no clear use case for a security sandbox).

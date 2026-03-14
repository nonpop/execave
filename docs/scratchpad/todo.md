# execave TODOs

- nit lint

- env/set:VAR=VAL rules?
- trim openspec config.yaml

- flags to add temporary rules, like `--rule fs:ro:/foo/bar` (or `--fs ro:/foo/bar` maybe rather)
  - maybe need to allow http:*:*
- monitor to execave-access.log by default, and allow stderr/out with
  - would stdout be better than stderr for log?

- go through nolints & nosec & gosec. Tweak lint settings?
- Maybe use 'tcp' vs 'http' in net rules? Or 'tunnel' vs 'forward'?
- maybe log could log in rule format?
  - fs/ro:/foo/bar DENY no-matching-rule
  - fs/rw:/baz DENY fs:ro:/baz

- sequences like `^[[?1049;2$y` sometimes appear

- --no-sandbox should have a way of logging only those entries which would be denied
  - Means: In --no-sandbox mode, all accesses are logged as "unenforced." This would filter to show only what would have been denied if the sandbox were active.
  - Assessment: Important. This is the core UX loop for building a config: run without sandbox, see what would break, add rules, repeat. Without this filter the user drowns in noise.

- actually do log noncustomizable syscalls, too. But when added to config, error with "kernel won't allow in sandboxes". Allow in syscall:nolog, though.
  - Means: The 13 defense-in-depth syscalls are currently invisible in logs. Log them when hit, error if user tries syscall:allow rules for them, allow syscall:nolog to suppress.
  - Assessment: Important. Visibility helps users understand why programs fail. Error-on-config-rule prevents false confidence. syscall:nolog is consistent with existing patterns.

## easy, probably

- env var expansion in rules
  - Means: Allow $HOME or ${HOME} in rule paths, e.g. rw:$HOME/project. Expand once at parse time.
  - Assessment: Nice to have. Makes configs portable. Low risk if expanded at parse time. Undefined vars should error, not silently expand to empty.

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
    - Actually it means those fmt.Fprintf(stderr, ...)
  - Assessment: Nice to have. Useful for debugging failures where stderr is lost or interleaved. Low complexity.

## medium, probably

- add pre & post conditions
  - Means: Formalize preconditions and postconditions in code with panic checks. CLAUDE.md mandates this but it may not be consistently applied.
  - Assessment: Important. Consistent with the project's security-critical nature. Panic on violated invariants prevents silent misbehavior.

## hard, probably

- put monitor inside sandbox
  - Means: Currently the monitor (strace) runs outside the sandbox as trusted code. This proposes moving it inside to reduce trusted surface area.
  - Assessment: Questionable / likely harmful. Architecture explicitly positions the monitor as trusted. Moving it inside lets an untrusted process interfere with its own monitoring. Strace needs ptrace capability which conflicts with seccomp. Architecturally unsound unless addressing a very specific threat model.

# execave TODOs

- validate config command, show effective config command, config layering
- --no-sandbox should have a way of logging only those entries which would be denied
- bells don't get through the sandbox?
- actually do log noncustomizable syscalls, too. But when added to config, error with "kernel won't allow in sandboxes". Allow in syscall:nolog, though.

## easy, probably

- config sections [fs], [net], ...
- rules for disabling commands: `cmd:deny:gh` looks up gh -> /usr/bin/gh and adds `fs:deny:/usr/bin/gh`
- env var expansion in rules
- should use absolute path for bwrap?
- add commands? run, monitor
- check public apis are minimal
- extract strace parser
- stat, exec etc, maybe useful after all
- nicer symlink resolve logging (A -> B -> C [DENY])
- log stderr stuff to file
- vendoring (maybe not needed, go.sum suffices?)

## medium, probably

- clean up test helpers & duplicate tests
- require fixed bwrap/strace versions?
- add pre & post conditions
- heuristic for determining strace output compatibility?

## hard, probably

- put monitor inside sandbox
- EXPERIMENT with converting specs directly to e2e tests:

    configContains("fs:rw:/home/user/project")
    read("/home/user/project/main.go")
    accesAllowed()

## ???

- bwrap:
  --argv0 VALUE ?
  --uid UID, --gid GID?
  --hostname HOSTNAME?


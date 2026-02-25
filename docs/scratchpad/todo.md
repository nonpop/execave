# execave TODOs

- clearScreen needs fixing. Can detect TUI?

- maybe use a simple "mini-react" library?
- UI should indicate which config version is currently running

## easy, probably

- maybe just enable a small set of basic dirs like /lib64
- env var expansion in rules
- --monitor for stdout/err, --monitor=<path> for file log
- should use absolute path for bwrap?
- add commands? run, monitor
- check public apis are minimal
- extract strace parser
- stat, exec etc, maybe useful after all
- nicer symlink resolve logging (A -> B -> C [DENY])
- log stderr stuff to file
- vendoring (maybe not needed, go.sum suffices?)

## medium, probably

- simplify webui (no SSR, all data reading via SSE)
- clean up test helpers & duplicate tests
- bin64 trick
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


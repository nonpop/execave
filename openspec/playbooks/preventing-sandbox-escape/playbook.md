# Preventing Sandbox Escape — Security-relevant adversarial scenarios

## Purpose

The sandbox must withstand adversarial commands that attempt to escape isolation, access denied resources, or exfiltrate data. These use cases verify that security boundaries hold under attack.

## Use Cases

### Use Case: Symlink escape: link inside mount points outside rules

An adversary creates a symlink inside an accessible directory that points to a path outside the allowed rules, attempting to escape the sandbox. The access is denied because the symlink target is not mounted in the sandbox.

- **GIVEN** a config with rule `fs:rw:/home/user/project`
- **AND** `/home/user/project/escape-link` is a symlink to `/etc/shadow`
- **AND** no rule allows `/etc/shadow`
- **WHEN** the user runs `execave -- cat /home/user/project/escape-link`
- **THEN** the read is denied (the symlink target is not mounted in the sandbox)

### Use Case: Symlink chain broken at denied intermediate hop

An adversary creates a chain of symlinks where an intermediate hop passes through a denied directory. The resolution chain stops at the denied hop and subsequent hops are never followed.

- **GIVEN** a config with rule `fs:ro:/home/user/project`
- **AND** `/home/user/project/hop1` is a symlink to `/tmp/hop2` (outside rules)
- **AND** `/tmp/hop2` is a symlink to `/home/user/project/secret.txt`
- **WHEN** the user runs `execave --monitor -- cat /home/user/project/hop1`
- **THEN** the read fails at the intermediate hop (`/tmp/hop2` is not accessible via rules)
- **AND** the access log shows the denied hop but no entry for `/home/user/project/secret.txt`

### Use Case: Config file modification prevented (rw parent dir)

An adversary's command runs inside a sandbox where the config file's parent directory is writable. The sandbox forces the config file to read-only, preventing the command from modifying it to escalate privileges in future runs.

- **GIVEN** a config file at `/home/user/project/execave.json` with rule `fs:rw:/home/user/project`
- **WHEN** the user runs `execave -- sh -c 'echo {} > /home/user/project/execave.json'`
- **THEN** the write to the config file is denied (config file is forced read-only inside the sandbox)
- **AND** writing to other files in `/home/user/project` still succeeds

### Use Case: Data exfiltration via network denied

An adversary's command attempts to exfiltrate data by making network requests to an unauthorized endpoint. The proxy denies all requests that do not match the allowlist.

- **GIVEN** a config with rules `fs:ro:/home/user/data` and `net:http:api.example.com:443`
- **WHEN** the user runs a command that reads `/home/user/data/secrets.txt` and attempts to POST it to `https://evil.com/exfil`
- **THEN** the request to `evil.com` is denied with `403 Forbidden`
- **AND** the data does not leave the sandbox

### Use Case: Symlink loop hits depth limit

An adversary creates a symlink loop (A points to B, B points to A) to cause infinite resolution. The monitor enforces a depth limit of 40 links (matching the Linux kernel's `MAXSYMLINKS`) and denies the access.

- **GIVEN** a config with rule `fs:ro:/home/user/project`
- **AND** `/home/user/project/loop-a` is a symlink to `/home/user/project/loop-b`
- **AND** `/home/user/project/loop-b` is a symlink to `/home/user/project/loop-a`
- **WHEN** the user runs `execave --monitor -- cat /home/user/project/loop-a`
- **THEN** the read fails
- **AND** the access log shows the access denied with reason `symlink-depth-limit-exceeded`

### Use Case: PATH injection via fake bwrap binary

An adversary plants a fake `bwrap` binary in a directory earlier in PATH. The binary validation rejects it because the file is not owned by root, preventing execution of an attacker-controlled binary in place of the real sandbox.

- **GIVEN** a fake `bwrap` binary owned by a non-root user exists in a directory
- **AND** that directory is first in PATH (before the real bwrap)
- **WHEN** the user runs `execave -- true`
- **THEN** execave refuses to start and reports that the bwrap binary is not owned by root

### Use Case: Env var secret not visible inside sandbox

A secret present in the host environment is not visible to the sandboxed process when no `env` rules allow it. Even if the process has network access to an allowed endpoint, it cannot read the secret from its environment.

- **GIVEN** a config with rules `fs:ro:/usr` and `net:http:api.example.com:443` and no `env` rules
- **AND** the host environment has `SECRET_KEY=supersecret`
- **WHEN** the user runs `execave -- sh -c 'echo ${SECRET_KEY:-not-present}'`
- **THEN** the output is `not-present` (SECRET_KEY is absent from the sandbox environment)

### Use Case: PATH injection via fake strace binary

An adversary plants a fake `strace` binary in a directory earlier in PATH. Since strace runs outside the sandbox with full host access, the same binary validation is applied. The fake strace is rejected because the file is not owned by root.

- **GIVEN** a fake `strace` binary owned by a non-root user exists in a directory
- **AND** that directory is first in PATH (before the real strace)
- **WHEN** the user runs `execave --monitor -- true`
- **THEN** execave refuses to start and reports that the strace binary is not owned by root

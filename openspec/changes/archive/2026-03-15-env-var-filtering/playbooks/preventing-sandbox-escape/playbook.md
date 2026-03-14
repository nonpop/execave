## ADDED Use Cases

### Use Case: Env var secret not visible inside sandbox

A secret present in the host environment is not visible to the sandboxed process when no `env` rules allow it. Even if the process has network access to an allowed endpoint, it cannot read the secret from its environment.

- **GIVEN** a config with rules `fs:ro:/usr` and `net:http:api.example.com:443` and no `env` rules
- **AND** the host environment has `SECRET_KEY=supersecret`
- **WHEN** the user runs `execave -- sh -c 'echo ${SECRET_KEY:-not-present}'`
- **THEN** the output is `not-present` (SECRET_KEY is absent from the sandbox environment)

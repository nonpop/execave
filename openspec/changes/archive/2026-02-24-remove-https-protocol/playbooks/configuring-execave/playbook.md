## MODIFIED Use Cases

### Use Case: Duplicate network rule identity rejected

The user has a config where two net rules share the same target and port pattern. The system rejects the config because the conflicting actions cannot be resolved.

- **GIVEN** a config with rules `net:http:example.com:443` and `net:none:example.com:443`
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating duplicate net rule identity

### Use Case: Mixed port patterns on same target rejected

The user has a config where the same target has both a wildcard port rule and a specific port rule. The system rejects this because the interaction between wildcard and specific ports is ambiguous.

- **GIVEN** a config with rules `net:http:example.com:*` and `net:none:example.com:443`
- **WHEN** the user runs `execave -- ls`
- **THEN** the system exits with an error indicating mixed port patterns on the same target

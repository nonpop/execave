## MODIFIED Requirements

### Requirement: Sandbox setup filtering

Internal sandbox setup operations SHOULD NOT appear in the access log. Only filesystem operations initiated by the sandboxed command SHOULD be logged. When the proxy-tunnel path is active (net rules present or monitoring enabled), the tunnel process adds one additional execve call to the setup phase (3 total instead of 2). The monitor SHALL detect setup phase completion based on the expected number of execve calls: 2 without proxy-tunnel, 3 with proxy-tunnel.

#### Scenario: Sandbox setup paths not logged without net rules
- **WHEN** monitoring is enabled
- **AND** config contains no net rules
- **AND** sandbox setup creates internal paths (e.g., `/newroot`, `/oldroot`)
- **THEN** log does NOT contain entries for sandbox setup paths

#### Scenario: Sandbox setup paths not logged with net rules
- **WHEN** monitoring is enabled
- **AND** config contains net rules
- **AND** sandbox setup creates internal paths including tunnel setup
- **THEN** log does NOT contain entries for sandbox or tunnel setup paths

#### Scenario: Tunnel execve not counted as user activity
- **WHEN** monitoring is enabled
- **AND** config contains net rules
- **AND** the tunnel process starts (execve)
- **THEN** the tunnel's execve is counted toward the expected 3 setup execves and its operations are NOT logged to the access log

#### Scenario: Sandbox setup paths not logged with monitoring and no net rules
- **WHEN** monitoring is enabled
- **AND** config contains no net rules
- **AND** proxy-tunnel is started for network logging
- **THEN** log does NOT contain entries for sandbox or tunnel setup paths
- **AND** setup phase expects 3 execves (same as with net rules)

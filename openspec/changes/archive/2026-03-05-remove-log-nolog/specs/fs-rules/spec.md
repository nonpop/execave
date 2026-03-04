## REMOVED Requirements

### Requirement: Log rule syntax validation
**Reason**: log/nolog visibility rules removed as unnecessary complexity.
**Migration**: Remove `fs:log:` and `fs:nolog:` rules from config. These rules now cause a parse error.

### Requirement: Log rule validation
**Reason**: log/nolog visibility rules removed.
**Migration**: Remove `fs:log:` and `fs:nolog:` rules from config.

### Requirement: Log rule resolution
**Reason**: log/nolog visibility rules removed.
**Migration**: Use external log filtering (e.g., `grep`) instead.

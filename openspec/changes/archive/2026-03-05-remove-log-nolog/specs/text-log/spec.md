## REMOVED Requirements

### Requirement: Nolog filter
**Reason**: log/nolog visibility rules removed as unnecessary complexity.
**Migration**: Use external log filtering (e.g., `grep -v`) on text log output instead.

### Requirement: Independent filter axes
**Reason**: With nolog filter removed, only the denied-only filter (`showAllowed`) remains. The concept of independent filter axes no longer applies.
**Migration**: No replacement needed; only the `--show-allowed` filter axis remains.

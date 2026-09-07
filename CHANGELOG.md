# Changelog

## 1.0.1 - 2026-09-07

### Fixed

- Validate every address in stateful IPv4 pools and require one authorized prefix to cover
  DHCP/ARP MAC pools, consistently at planning and execution time.
- Reject unsupported network protocols (including IPv6) in stateless PCAP replay planning and
  packet compilation. Include ARP IPv4 endpoints in capture safety analysis.
- Keep ASTF flows replenished within the active-connection limit throughout the requested run.
- Separate TCP connections that reuse endpoint tuples; preserve independent session identity and
  workload occurrence weights, while rejecting repeated SYNs as ambiguous captures.

## 1.0.0 - 2026-09-05

### Added

- Durable, declarative Jobs with safety policy, logical-port leases, cancellation, recovery, and
  content-addressed publication bundles.
- TestControl adapters for HTTP, CLI, in-process callers, and MCP.
- Stateless L2/L3 traffic, full RFC2544 suite implementation, stateless/stateful PCAP replay, UDP
  capture workloads, and bounded DNS/DHCP/ARP storms.
- Transactional SQLite schema migration with online pre-upgrade backup and fail-closed readiness.
- Auditable Artifact retention/cleanup, structured JSON logs, authenticated Prometheus metrics,
  native TLS/mTLS configuration, and online file-token rotation.
- Stable Catalog and immutable Test Plan document identifiers, plus read-only compatibility for
  pre-release alpha resources and persisted Plans.
- Apache License 2.0 distribution terms, matching the upstream Cisco TRex project.

### Compatibility

- HTTP remains `/v1`; executable Job documents remain `trex.example.io/v1`.
- SQLite schema is v1 and Artifact manifests are v2.
- Catalog resources identify as `trex.example.io/catalog/v1`; immutable Plans identify as
  `trex.example.io/test-plan/v1`.
- Pre-release Catalog resources (`trex.example.io/v2alpha1`) and persisted Plans
  (`trex.example.io/plan/v2alpha1`) remain readable throughout 1.x and are not rewritten in place.

### Known limitations

- The current X550/TRex v3.08 laboratory path still needs traceable IEEE 1588 timestamp calibration
  before strict RFC2544 latency evidence can be published as complete.
- A complete strict RFC2544 publication run remains a long-running laboratory action; simulated or
  fast-mode results are never publishable as standards-conformant evidence.

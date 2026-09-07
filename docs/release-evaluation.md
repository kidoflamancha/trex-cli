# Release evaluation: trex-cli 1.0.1

Date: 2026-09-07

## Release decision

The trex-cli software is ready for a 1.0.1 release when the reproducible gate below passes. The
release provides a stable, declarative TestControl interface for arbitrary supported DUTs; device
configuration remains an administrator-owned LabPath/fixture concern and is not embedded in the
TRex control plane.

This decision does not claim that the current laboratory has produced a complete standards-grade
RFC2544 evidence set. IEEE 1588 calibration and the final long-running strict suite remain explicit
laboratory actions. Fast mode, simulated results, and uncalibrated latency are never promoted to
publishable RFC2544 evidence.

## Stable interfaces

- HTTP control plane: `/v1`
- executable Jobs: `trex.example.io/v1`
- Catalog resources: `trex.example.io/catalog/v1`
- immutable Test Plans: `trex.example.io/test-plan/v1`
- SQLite schema: 1
- Artifact manifest: 2
- distribution license: Apache-2.0

Pre-release Catalog and Plan identifiers remain read-compatible as documented in
`docs/compatibility.md`. New documents only emit stable identifiers.

## TestControl task matrix

| Agent task | Public operation | Automated evidence | Hardware evidence status |
|---|---|---|---|
| Discover and describe resources | `search_catalog`, `describe_resource` | in-process, HTTP, CLI and MCP contract tests | Catalog inputs used by real runs |
| Plan and run L2/L3 traffic | `plan_test`, `start_test`, `get_test` | immutable-plan, idempotency, lifecycle and STL adapter tests | real bidirectional smoke completed with zero loss |
| Plan a complete RFC2544 suite | RFC2544 intent through the same operations | all four methods, report bundle, validity and publication tests | Throughput verified; final calibrated strict suite pending |
| Publish and replay a PCAP | CaptureResource plus stateless replay intent | catalog, rewrite, timing, safety and execution tests | real STL replay completed |
| Replay captured TCP/HTTP sessions | stateful replay intent | flow extraction, deduplication, capacity, ASTF and result tests | real ASTF smoke completed |
| Replay every eligible UDP flow | UDP workload intent | weighted extraction, completeness, direction and STL tests | real bidirectional STL smoke completed |
| Run bounded DNS/DHCP/ARP storms | typed storm intents | protocol encoding, double safety validation and result tests | bounded real runs completed; ARP limitations disclosed |
| Observe and cancel safely | `get_test`, `control_test` | bounded wait, revision, cancellation, recovery and lease tests | ports returned to AVAILABLE after real runs |
| Reject unsafe or unauthorized work | all adapters | role, address, rate, duration, broadcast and malformed-input tests | safety limits used during laboratory runs |

The adapters expose typed task intents rather than TRex objects, Python profiles, arbitrary YAML,
Scapy expressions, FlowStats, or device-specific switch commands. A caller therefore uses the same
workflow for any DUT represented by an administrator-approved LabPath and external DutControl
fixture.

## RFC2544 publication boundary

The software can plan and execute Throughput, Latency, Frame Loss and Back-to-Back, preserve DUT and
topology context, and publish JSON, CSV, NDJSON, Markdown, environment, manifest and checksum
artifacts. Publication fails closed when strict validity requirements are not met.

For the current X550/TRex v3.08 path, a final standards-grade report additionally requires:

1. traceable IEEE 1588 timestamp capability and uncertainty calibration;
2. a versioned DUT configuration artifact and configuration digest;
3. the complete strict suite, expected to exceed 12 hours, with no exclusive-port counter fallback;
4. offline verification of the generated manifest and checksums.

Until those steps finish, the implementation is releasable but the laboratory result must be
labelled engineering evidence rather than a complete RFC2544 publication.

## Reproducible release gate

Run from a clean checkout with Python 3.12:

```bash
python -m trex_cli.release_validation --root .
ruff check src tests
mypy --strict src/trex_cli
pytest
python -m pip wheel --no-deps --no-build-isolation --wheel-dir dist .
```

Install the resulting wheel in a fresh virtual environment, then require successful
`trex-cli --help`, `trex-agent --help`, and release-resource validation. Preserve the wheel SHA-256
alongside the release record. CI performs the same gate and uploads the wheel and checksum.

### Candidate verification record

The 2026-09-07 local candidate passed resource validation (seven deployment assets), Ruff, strict
mypy over 30 source files, and 193 pytest cases. A clean virtual environment installed the wheel
with dependencies, exercised both console entry points, reported package version `1.0.1`, and
re-ran release validation successfully. The candidate wheel is
`trex_cli-1.0.1-py3-none-any.whl`, SHA-256
`5848f522ec0dc67ecaed8d25dd0ece0a554fdcf041b529010822544589b275df`. This local run used Python
3.14; the repository CI remains the authoritative Python 3.12 gate before publishing the artifact.

## Residual risks and non-blocking actions

- IEEE 1588 and the final strict RFC2544 run block a standards-grade hardware report, not the 1.0
  software release.
- X550/FDIR FlowStats behavior at high small-frame rates remains environment-sensitive; strict
  publication rejects fallback counters.
- TRex STL and ASTF deployments require different client environments, hidden behind their
  adapters but still documented operational prerequisites.
- DUT configuration and restoration remain external laboratory responsibilities. The report binds
  their artifact and digest so evidence cannot silently cross device configurations.

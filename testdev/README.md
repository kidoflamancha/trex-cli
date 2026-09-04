# Public test-device fixtures

This directory contains sanitized laboratory templates, bounded smoke-test definitions, deployment
notes, and diagnostic helpers. Addresses and MAC prefixes use documentation or benchmark ranges;
they are not a working deployment configuration.

Keep environment-specific material outside public Git:

- `testdev/testdev.md`: private topology, access procedures, device state, and run log;
- `testdev/private/` and `testdev/*.local.yaml`: real overrides and credentials;
- `testdev/pcap/`: original packet captures;
- `testdev/.state/`: databases, immutable plans, artifacts, and other runtime state.

Before running a fixture, copy it to an ignored local override, replace the documentation values,
and verify the SafetyPolicy against an isolated lab. Public test evidence should contain only the
minimum result summary and content digests needed for reproducibility.

# trex-cli

Declarative control plane for Cisco TRex tests. It provides a durable Job framework with both a
deterministic simulated engine and a remote TRex v3.08 STL adapter. The remote adapter currently
supports `StatelessTraffic`, including MAC, IPv4 address, UDP/TCP port, and same-prefix IPv6 address
variations with checksum repair. The same L2/L3 packet-template compiler is used by RFC2544
Throughput, Latency, Frame Loss, and RFC 9004 Back-to-Back trials, so RFC2544 can exercise VLAN, IPv4/IPv6, UDP/TCP/ICMP and payload templates
without exposing TRex profiles. Bare Ethernet is supported for ordinary `StatelessTraffic` through
exclusive-port counters; RFC2544 requires IPv4 or IPv6 so its strict flow statistics stay isolated.
Fast mode
is explicitly reported as an engineering estimate, while strict mode retains the standard frame
set and confirmation timings. Real strict runs above the configured bootstrap ceiling require
fresh, per-environment calibration for all standard frame sizes, using marker-isolated flow stats;
exclusive port-counter fallback is recorded for audit but cannot satisfy that gate.

This independent project is licensed under the Apache License 2.0. Cisco and TRex are trademarks
of their respective owners; this project is not affiliated with or endorsed by Cisco.

## Development

```bash
/usr/local/bin/python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
export TREX_OPERATOR_TOKEN=operator-secret
export TREX_READER_TOKEN=reader-secret
.venv/bin/trex-agent --config config.example.yaml
```

In another shell:

```bash
export TREX_AGENT_TOKEN=operator-secret
.venv/bin/trex-cli --agent-url http://127.0.0.1:8080 run examples/stateless.yaml
```

The release gate uses the locked Python 3.12 environment, validates all source-controlled schemas
and YAML resources, runs static and contract checks, builds a wheel, and installs that wheel into a
fresh virtual environment before exercising both console entry points:

```bash
python -m trex_cli.release_validation --root .
ruff check src tests
mypy --strict src/trex_cli
pytest
python -m pip wheel --no-deps --no-build-isolation --wheel-dir dist .
```

The same sequence runs in `.github/workflows/ci.yml`. The clean-wheel smoke installs the wheel by
itself, allowing its package metadata to resolve runtime dependencies rather than inheriting the
development environment.

Database schema upgrades are automatic, transactional, and preceded by an online SQLite backup.
Migration failure leaves `/healthz` alive but `/readyz` unavailable and blocks work endpoints. See
[the operations guide](docs/operations.md) for backup/restore, Artifact cleanup, JSON logs, the
authenticated `/metrics` endpoint, and initial alert recommendations.

Optional native TLS/mTLS, file-backed online token rotation, systemd/Nginx templates, and the
1.x compatibility contract are covered by [the operations guide](docs/operations.md) and
[the compatibility policy](docs/compatibility.md).

## Intent-based CLI

New callers should use a `TrafficProfile` from `traffic-profiles/` together with an administrator
owned `LabPath` from `lab-paths/`. Profiles declare packets, named one-way flows and typed
parameters; paths supply real ports and addresses. The TestPlan Module resolves both into an
immutable executable plan without exposing TRex VM or arbitrary Job field paths.

The `TestControl` Interface provides catalog search/describe, typed traffic and RFC2544 planning,
idempotent start, bounded observation, and cancellation through in-process, HTTP, CLI, and minimal
MCP adapters. Named resources resolve to the highest revision only while planning; persisted Plans
record both `name@revision` and the content digest. Authenticated intent CLI commands use the Agent
catalog and Plan store. Without a token, plan commands retain the local migration path; raw Job
commands remain available as the advanced compatibility interface.

Version 1.0 emits Catalog resources as `trex.example.io/catalog/v1` and immutable Plans as
`trex.example.io/test-plan/v1`. The Agent advertises stable and legacy-read capabilities through
authenticated `GET /version`.

```bash
# Planning is local in the first migration slice and does not require Agent credentials.
trex-cli traffic plan \
  --profile ipv4-udp \
  --path cc-switch \
  --param frame-size=256 \
  --rate 1gbps \
  --duration 30s

# Start an existing plan. Repeating this command uses the plan id as its idempotency key.
trex-cli plan start plan_<id>

# Human convenience path: plan, display, confirm, start, and watch.
trex-cli traffic run \
  --profile ipv4-udp \
  --path cc-switch \
  --rate 1000pps \
  --duration 10s

# The same packet Profile can be benchmarked; the method owns RFC2544 frame sizes.
trex-cli benchmark rfc2544 plan \
  --profile ipv4-udp \
  --path cc-switch \
  --mode fast \
  --frame-size 64 \
  --frame-size 512

# Compose an ordered engineering suite. Omitting --test preserves the Throughput-only default.
trex-cli benchmark rfc2544 run \
  --profile ipv4-udp \
  --path cc-switch \
  --mode fast \
  --frame-size 64 \
  --test throughput \
  --test frame-loss

# Explicit simultaneous bidirectional benchmark; no packet is auto-reversed.
trex-cli benchmark rfc2544 plan \
  --profile bidirectional-imix \
  --path cc-switch \
  --direction-mode bidirectional-simultaneous \
  --forward client-to-server \
  --reverse server-to-client \
  --mode fast \
  --frame-size 512
```

`--rate` always means per-egress load. Frame sizes are Ethernet wire sizes including FCS; the Plan
also shows the generated size without FCS and the L1 accounting size including preamble and IFG.
When a profile contains multiple flows, all flows run by default. Repeat `--flow <name>` to select
a subset. Each Flow is one-way and uses its own packet template; explicit reverse flows are never
derived by swapping headers. Flows from the same egress share its requested rate by weight, and a
Flow's frame-size distribution divides that share again. See
`traffic-profiles/bidirectional-imix.yaml` for a bidirectional example.

The RFC2544 suite composes `throughput`, `latency`, `frame-loss`, and `back-to-back` as independent
methods in one durable Job. Tests execute in the order supplied by repeatable `--test`; result JSON places each
method under `summary.tests.<name>`, while progress includes the current `test` and `testIndex`.
Frame Loss starts at the allowed L1 ceiling and descends in intervals no larger than 10 percentage
points until two successive valid trials have zero loss. Strict trials use 60 seconds per point;
fast trials use 3 seconds and are explicitly labelled as an engineering curve. A strict run capped
below 100% by SafetyPolicy is reported as a partial-range result, not full-range conformance.

A publishable strict suite requires all four methods in that order, both latency destination
scenarios, a current IEEE 1588 timestamp calibration with a correction for every frame size, and a
Back-to-Back upper bound covering at least 30 seconds at theoretical line rate. The `LabPath`
optionally carries a generic `reportContext` with DUT identity, configuration digest and artifact, topology,
medium, protocol, stream type, and isolation statement. Missing evidence fails closed to
`publicationStatus: PARTIAL`; simulation can never produce `COMPLETE`. A result bundle contains
`publication.json`, `measurements.csv`, raw `trials.ndjson`, submitted/resolved specs,
`environment.json`, `report.md`, `result.json`, a checksum list, and a revisioned manifest.

Back-to-Back settings are exposed as `--back-to-back-repetitions`,
`--back-to-back-minimum-step-frames`, `--back-to-back-maximum-burst-seconds`, and
`--back-to-back-buffer-depletion-seconds`, in addition to the required maximum frame bound. Frames
whose measured throughput equals theoretical line rate are explicitly recorded as not applicable,
as required by the RFC 9004 applicability condition.

See [`docs/rfc2544-publication.md`](docs/rfc2544-publication.md) for the complete environment,
calibration, command, duration, and artifact checklist.

RFC2544 methods support `unidirectional`, `bidirectional-simultaneous`, and
`unidirectional-each`. Two-direction modes require explicit mirrored `--forward` and `--reverse`
Flows. Simultaneous mode uses the lower common zero-loss point; each mode reports both independent
searches and a conservative lower summary. Fast mode remains an engineering estimate and is never
labelled as strict RFC2544 Throughput.

## Legacy full-Job profiles

The first profile adapter treated a complete Job in `profiles/<name>.yaml` as a profile. It is never edited
by a run. `plan` applies typed YAML overrides, validates the complete resolved Job, and stores an
immutable JSON plan under `.trex-plans/`; `run <plan-id>` submits exactly that stored document.

```bash
# Local inspection and planning do not need an Agent token.
trex-cli profile list
trex-cli profile show cc-switch
trex-cli plan stateless --profile cc-switch \
  --set packet.frameSize=256 \
  --set packet.ipv4.src=198.18.0.10

# Submit the immutable plan; raw YAML remains the advanced compatibility path.
trex-cli run plan_de2b9e7fda5c966fc1cbc886
trex-cli run examples/stateless.yaml
```

This is a compatibility interface. New automation must not depend on dotted `--set` paths. Use
`--profile-dir` and `--plans-dir` to place legacy baselines and generated plans elsewhere.
Overrides are relative to `spec` by default (for example `packet.frameSize=256`); use an inline
YAML mapping to replace a structured field, such as
`--set 'packet.ethernet.src={start: "00:00:00:00:00:01", end: "00:00:00:00:00:fe", mode: increment}'`.

The example Agent uses plaintext HTTP and reports `transportSecurity: insecure-http`.

For an isolated TRex test environment, install `.[dev,trex]` and start with the sanitized fixtures
described in [`testdev/README.md`](testdev/README.md). Keep the real topology, access procedure,
credentials and packet captures in ignored local files. The example safety policy is deliberately
bounded and must be reviewed for the target lab.

MAC addresses are fail-closed independently from IP CIDRs. Configure `allowedMacPrefixes` under
`safety`; a variation's complete range must fit one configured prefix. The current TRex VM compiler
varies the low 32 bits, so a MAC range must remain inside one 16-bit prefix. Set
`allowArbitraryUnicastMac: true` only for a lab that intentionally permits every unicast MAC.

Stateless PCAP replay currently accepts IPv4 and IPv4 ARP packets. Captures containing IPv6 or
other unsupported network protocols may be analyzed, but replay is rejected until their addresses
can be fully validated. Older preserved ARP Plans without ARP endpoint facts must be recreated.

PCAP replay uses immutable Capture Resources. Stateless replay sends rewritten Ethernet frames
through STL; stateful replay extracts reconstructible TCP/HTTP application exchanges and lets ASTF
regenerate the TCP transport behavior. A single-session Plan selects one exchange. A Capture
Workload selects every reconstructible TCP session. A UDP Datagram Workload selects every bounded
unicast IPv4 UDP flow and runs its directional datagrams on the two STL ports. Both workload forms
merge identical templates and use their occurrence counts as weights. They do not claim to restore
the original capture-wide timeline, transport state, retransmissions, or network jitter.

```bash
trex-cli pcap publish session.pcap --name regression/http-session
trex-cli pcap show regression/http-session
trex-cli pcap stateful-run \
  --capture regression/http-session --session session_<id> \
  --path cc-switch --client client --server server \
  --cps 10 --max-active 100 --duration 10s \
  --client-ip-start 198.18.0.1 --client-ip-end 198.18.0.4 \
  --server-ip-start 198.19.0.1 --server-ip-end 198.19.0.4 --yes

trex-cli pcap workload-run \
  --capture regression/http-session --path cc-switch \
  --client client --server server \
  --cps 30 --max-active 100 --duration 10s \
  --client-ip-start 198.18.0.1 --client-ip-end 198.18.0.4 \
  --server-ip-start 198.19.0.1 --server-ip-end 198.19.0.8 --yes

trex-cli pcap udp-workload-run \
  --capture regression/dns-workload --path cc-switch \
  --initiator client --responder server \
  --fps 30 --duration 10s --yes
```

STL and ASTF are mutually exclusive TRex server modes on the same physical ports. ASTF address
pools must each contain more addresses than the selected data-path thread count. Every generated
profile has a finite duration; cancellation has bounded stop/cleanup calls and quarantines logical
ports if remote idleness cannot be confirmed. Workload analysis is fail-closed: captures whose TCP
session analysis was truncated, or which contain more than 256 unique reconstructible templates,
cannot use `all-reconstructible`. UDP workload analysis likewise rejects omitted, malformed,
broadcast or multicast UDP, more than 4,096 flows, more than 256 unique templates, or more than 512
template datagrams. UDP `fps` means source flow instances per second; the Plan records derived PPS
and L1 bit rate and checks both against the SafetyPolicy before a Job can start.

DNS Query Storm is a first-class `PacketStorm`, not a raw TrafficProfile. It accepts only typed A
or AAAA questions, normalizes the DNS name, varies the client UDP source port and transaction ID,
and derives PPS and L1 bit rate before execution. The current STL observation proves query delivery
through the DUT with hardware FlowStats; it deliberately reports response observation as unavailable
and does not claim resolver success, response latency, or DNS service performance.

```bash
trex-cli traffic storm dns run \
  --path cc-switch --client client --server server \
  --name www.example.test --type A \
  --source-port-start 40000 --source-port-end 40003 \
  --pps 100 --duration 3s --yes
```

Packet Storm requires an isolated LabPath. Duration, PPS, derived L1 bit rate, source-port
cardinality, MAC prefixes, and IPv4 CIDRs are checked while planning and again when the Job starts.

DHCP Discover Storm is the broadcast variant. It emits only minimal DHCPDISCOVER messages from a
bounded client MAC identity pool, with matching Ethernet source and BOOTP `chaddr` plus a varying
32-bit transaction ID. It requires both `safety.allowBroadcastStorms: true` and a LabPath with
`safety.broadcastDomain: true`. Current results prove Discover delivery through the DUT; Offers,
leases, response latency, and DHCP server performance remain unavailable and are never asserted.

```bash
trex-cli traffic storm dhcp run \
  --path cc-switch --client client --server server \
  --clients 4 --pps 100 --duration 3s --yes
```

ARP Request Storm emits a closed 64-byte broadcast template toward one target IPv4. A bounded
Sender Identity Pool advances Ethernet source MAC, ARP sender MAC, and ARP sender IPv4 in lockstep.
It uses the same broadcast safety gates as DHCP. On the verified X550/TRex v3.08 environment,
hardware packet-group FlowStats rejects ARP's L2 header type, so the result reports only Request
Transmission Observation from the owned egress port. Request delivery, Replies, resolution success,
loss, and response latency are explicitly unavailable and are never inferred from aggregate RX
counters.

```bash
trex-cli traffic storm arp run \
  --path cc-switch --sender client --target server \
  --senders 4 --pps 100 --duration 3s --yes
```

To recreate the exact verified environment, install `requirements.lock` first and then install the
project without resolving dependencies:

```bash
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install -e . --no-deps
```

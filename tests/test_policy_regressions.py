import json
from io import BytesIO
from pathlib import Path

import dpkt  # type: ignore[import-untyped]
import pytest

from trex_cli.errors import TrexCliError
from trex_cli.test_plan import TestPlanError as PlanError
from trex_cli.test_plan import TestPlanModule as Plans

from .conftest import build_jobs, make_config
from .test_test_control import _http_session_pcap, _write_resources


@pytest.mark.parametrize("workload", [False, True])
async def test_stateful_pool_holes_rejected_by_plan_and_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    workload: bool,
) -> None:
    profiles, paths, plans_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    plans = Plans(profiles, paths, plans_root, tmp_path / "captures", config.safety)
    capture = plans.publish_capture(name="session", source=BytesIO(_http_session_pcap()))
    kwargs = dict(
        capture_name=capture.ref,
        path_name="cc-switch",
        client_role="client",
        server_role="server",
        cps=1,
        max_active_connections=3,
        duration="1s",
        client_ipv4_start="198.18.0.1",
        client_ipv4_end="198.18.0.3",
    )
    if workload:

        def plan():
            return plans.plan_capture_workload(**kwargs)
    else:
        session = capture.document.analysis.stateful.sessions[0].id

        def plan():
            return plans.plan_stateful_replay(session_id=session, **kwargs)

    document = plan().document
    config.safety.allowed_cidrs = ["198.18.0.1/32", "198.18.0.3/32", "198.19.0.0/24"]
    with pytest.raises(PlanError, match="outside allowedCidrs"):
        plan()
    jobs = await build_jobs(config)
    try:
        with pytest.raises(TrexCliError, match="outside allowedCidrs"):
            jobs._validate_policy(document)
    finally:
        await jobs.stop()


@pytest.mark.parametrize("mode", ["rewrite", "preserve"])
def test_ipv6_capture_can_be_analyzed_but_not_planned_for_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    profiles, paths, plans_root = _write_resources(tmp_path)
    config = make_config(tmp_path, monkeypatch)
    plans = Plans(profiles, paths, plans_root, tmp_path / "captures", config.safety)
    output = BytesIO()
    packet = dpkt.ethernet.Ethernet(
        src=bytes.fromhex("000000000001"),
        dst=bytes.fromhex("000000000002"),
        type=dpkt.ethernet.ETH_TYPE_IP6,
        data=dpkt.ip6.IP6(
            src=bytes.fromhex("20010db8000000000000000000000001"),
            dst=bytes.fromhex("20010db8000000000000000000000002"),
        ),
    )
    dpkt.pcap.Writer(output).writepkt(bytes(packet), 1)
    output.seek(0)
    resource = plans.publish_capture(name="ipv6", source=output)
    assert resource.document.analysis.protocols["unsupported-network"] == 1
    with pytest.raises(PlanError, match="cannot safely authorize"):
        plans.plan_pcap_replay(
            capture_name=resource.ref,
            path_name="cc-switch",
            source_role="client",
            destination_role="server",
            address_mode=mode,
        )


@pytest.mark.parametrize("protocol", ["dhcp", "arp"])
async def test_storm_mac_pool_holes_rejected_by_plan_and_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    protocol: str,
) -> None:
    profiles, paths, plans_root = _write_resources(tmp_path)
    path_file = paths / "cc-switch@2.yaml"
    raw = json.loads(path_file.read_text())
    raw["safety"]["broadcastDomain"] = True
    path_file.write_text(json.dumps(raw))
    config = make_config(tmp_path, monkeypatch)
    config.safety.allow_broadcast_storms = True
    plans = Plans(profiles, paths, plans_root, tmp_path / "captures", config.safety)

    def plan():
        if protocol == "dhcp":
            return plans.plan_dhcp_storm(
                path_name="cc-switch",
                client_role="client",
                server_role="server",
                clients=3,
                pps=1,
                duration="1s",
            )
        return plans.plan_arp_storm(
            path_name="cc-switch",
            sender_role="client",
            target_role="server",
            senders=3,
            pps=1,
            duration="1s",
        )

    document = plan().document
    config.safety.allowed_mac_prefixes = ["00:00:00:00:00:01", "00:00:00:00:00:03"]
    with pytest.raises(PlanError, match="outside allowedMacPrefixes"):
        plan()
    jobs = await build_jobs(config)
    try:
        with pytest.raises(TrexCliError, match="outside allowedMacPrefixes"):
            jobs._validate_policy(document)
    finally:
        await jobs.stop()

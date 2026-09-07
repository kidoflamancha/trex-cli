from __future__ import annotations

import struct
from pathlib import Path

import dpkt  # type: ignore[import-untyped]
import pytest

from trex_cli.models import PcapReplayDocument
from trex_cli.pcap_replay import compile_replay


@pytest.mark.parametrize("preserve", [False, True])
def test_ipv6_is_rejected_even_for_legacy_plans(tmp_path: Path, preserve: bool) -> None:
    from trex_cli.models import ReplayPreserveAddress

    document = _document({"mode": "fixed-rate", "rate": {"value": 100, "unit": "pps"}})
    if preserve:
        document.spec.address = ReplayPreserveAddress(mode="preserve", policyVersion="test")
    source = tmp_path / "ipv6.pcap"
    packet = dpkt.ethernet.Ethernet(
        src=bytes.fromhex("000000000001"),
        dst=bytes.fromhex("000000000002"),
        type=dpkt.ethernet.ETH_TYPE_IP6,
        data=dpkt.ip6.IP6(
            src=bytes.fromhex("20010db8000000000000000000000001"),
            dst=bytes.fromhex("20010db8000000000000000000000002"),
        ),
    )
    with source.open("wb") as output:
        writer = dpkt.pcap.Writer(output)
        writer.writepkt(bytes(packet), 1)
    with pytest.raises(ValueError, match="cannot safely authorize"):
        compile_replay(source, tmp_path / "compiled", document)


def _capture() -> bytes:
    ethernet = bytes.fromhex(
        "00000000000200000000000108004500001c0000000040110000c6120001c6130001c000000700080000"
    )
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
        + struct.pack("<IIII", 2, 0, len(ethernet), len(ethernet))
        + ethernet
        + struct.pack("<IIII", 1, 500_000, len(ethernet), len(ethernet))
        + ethernet
    )


def _document(timing: dict[str, object]) -> PcapReplayDocument:
    return PcapReplayDocument.model_validate(
        {
            "apiVersion": "trex.example.io/v1",
            "kind": "PcapReplay",
            "spec": {
                "safety": {"isolatedLab": True},
                "ports": {"tx": "west", "rx": "east"},
                "capture": {
                    "name": "regression/sample",
                    "revision": 1,
                    "digest": "sha256:" + "1" * 64,
                    "size": len(_capture()),
                    "packetCount": 2,
                    "durationSeconds": 0.5,
                    "normalizedDurationSeconds": 0.0,
                    "nonMonotonicTimestampCount": 1,
                    "maximumBackwardJumpSeconds": 0.5,
                    "macEndpoints": ["00:00:00:00:00:01", "00:00:00:00:00:02"],
                    "ipv4Endpoints": ["198.18.0.1", "198.19.0.1"],
                    "hasBroadcast": False,
                    "hasMulticast": False,
                },
                "address": {
                    "mode": "rewrite",
                    "sourceRole": "client",
                    "destinationRole": "server",
                    "sourceMac": "00:00:00:00:00:0a",
                    "destinationMac": "00:00:00:00:00:0b",
                    "sourceIpv4": "198.18.1.1",
                    "destinationIpv4": "198.19.1.1",
                },
                "timing": timing,
            },
        }
    )


def _read(path: Path) -> list[tuple[float, bytes]]:
    with path.open("rb") as source:
        return [(float(timestamp), packet) for timestamp, packet in dpkt.pcap.Reader(source)]


def test_compiler_rewrites_endpoints_repairs_checksums_and_normalizes_time(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.pcap"
    source.write_bytes(_capture())
    result = compile_replay(
        source,
        tmp_path / "compiled",
        _document(
            {
                "mode": "capture",
                "multiplier": 2,
                "timestampPolicy": "normalize",
                "normalizedTimestampCount": 1,
            }
        ),
    )

    packets = _read(result.path)
    assert [timestamp for timestamp, _ in packets] == [0.0, 0.0]
    ethernet = dpkt.ethernet.Ethernet(packets[0][1])
    assert ethernet.src.hex(":") == "00:00:00:00:00:0a"
    assert ethernet.dst.hex(":") == "00:00:00:00:00:0b"
    assert isinstance(ethernet.data, dpkt.ip.IP)
    assert ethernet.data.src == bytes([198, 18, 1, 1])
    assert ethernet.data.dst == bytes([198, 19, 1, 1])
    assert ethernet.data.sum != 0
    assert isinstance(ethernet.data.data, dpkt.udp.UDP)
    assert ethernet.data.data.sum != 0
    assert result.normalized_timestamp_count == 1


def test_compiler_materializes_fixed_rate_and_top_speed_timing(tmp_path: Path) -> None:
    source = tmp_path / "source.pcap"
    source.write_bytes(_capture())

    fixed = compile_replay(
        source,
        tmp_path / "fixed",
        _document({"mode": "fixed-rate", "rate": {"unit": "pps", "value": 1000}}),
    )
    top = compile_replay(
        source,
        tmp_path / "top",
        _document({"mode": "top-speed"}),
    )

    assert fixed.effective_duration_seconds == 0.001
    assert _read(fixed.path)[1][0] == 0.001
    assert top.effective_duration_seconds == 0.000000001
    assert _read(top.path)[1][0] == 0.000000001

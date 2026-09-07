from __future__ import annotations

import hashlib
import ipaddress
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

import dpkt  # type: ignore[import-untyped]

from trex_cli.models import (
    PcapReplayDocument,
    ReplayCaptureTiming,
    ReplayFixedRateTiming,
    ReplayRewriteAddress,
)


@dataclass(frozen=True, slots=True)
class ReplayCompilation:
    path: Path
    digest: str
    packet_count: int
    captured_bytes: int
    effective_duration_seconds: float
    normalized_timestamp_count: int


def compile_replay(
    source: Path,
    output_root: Path,
    document: PcapReplayDocument,
) -> ReplayCompilation:
    """Materialize the exact packets and timing consumed by the TRex adapter."""
    identity = hashlib.sha256(
        document.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8")
    ).hexdigest()
    output_root.mkdir(parents=True, exist_ok=True)
    destination = output_root / f"{identity}.pcap"
    descriptor, temporary_name = tempfile.mkstemp(prefix=".replay-", dir=output_root)
    os.close(descriptor)
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    packet_count = 0
    captured_bytes = 0
    effective_timestamp = 0.0
    previous_source_timestamp: float | None = None
    normalized = 0
    try:
        with source.open("rb") as capture, temporary.open("wb") as output:
            reader = dpkt.pcap.Reader(capture)
            writer = dpkt.pcap.Writer(output, nano=True)
            for source_timestamp, raw_packet in reader:
                packet = _rewrite_packet(raw_packet, document)
                if packet_count:
                    delta, corrected = _packet_gap_seconds(
                        float(source_timestamp),
                        previous_source_timestamp,
                        len(packet),
                        document,
                    )
                    effective_timestamp += delta
                    normalized += int(corrected)
                writer.writepkt(packet, effective_timestamp)
                digest.update(packet)
                digest.update(effective_timestamp.hex().encode("ascii"))
                packet_count += 1
                captured_bytes += len(packet)
                previous_source_timestamp = float(source_timestamp)
            output.flush()
            os.fsync(output.fileno())
        if packet_count != document.spec.capture.packet_count:
            raise ValueError("capture packet count changed after Replay Plan publication")
        if destination.exists():
            temporary.unlink()
        else:
            os.replace(temporary, destination)
        return ReplayCompilation(
            path=destination,
            digest="sha256:" + digest.hexdigest(),
            packet_count=packet_count,
            captured_bytes=captured_bytes,
            effective_duration_seconds=effective_timestamp,
            normalized_timestamp_count=normalized,
        )
    finally:
        temporary.unlink(missing_ok=True)


def _rewrite_packet(raw_packet: bytes, document: PcapReplayDocument) -> bytes:
    ethernet = dpkt.ethernet.Ethernet(raw_packet)
    payload = ethernet.data
    if not isinstance(payload, (dpkt.ip.IP, dpkt.arp.ARP)):
        raise ValueError("replay cannot safely authorize this network protocol")
    if isinstance(payload, dpkt.arp.ARP) and (
        payload.pro != dpkt.ethernet.ETH_TYPE_IP or payload.pln != 4
    ):
        raise ValueError("replay cannot safely authorize this ARP protocol")
    address = document.spec.address
    if not isinstance(address, ReplayRewriteAddress):
        endpoints = (
            (payload.src, payload.dst)
            if isinstance(payload, dpkt.ip.IP)
            else (payload.spa, payload.tpa)
        )
        if any(
            str(ipaddress.IPv4Address(value)) not in document.spec.capture.ipv4_endpoints
            for value in endpoints
        ):
            raise ValueError("capture contains addresses absent from the authorized Replay Plan")
        return raw_packet
    ethernet.src = bytes.fromhex(address.source_mac.replace(":", ""))
    ethernet.dst = bytes.fromhex(address.destination_mac.replace(":", ""))
    payload = ethernet.data
    source_ip = ipaddress.IPv4Address(address.source_ipv4).packed
    destination_ip = ipaddress.IPv4Address(address.destination_ipv4).packed
    if isinstance(payload, dpkt.ip.IP):
        payload.src = source_ip
        payload.dst = destination_ip
        payload.sum = 0
        if isinstance(payload.data, (dpkt.udp.UDP, dpkt.tcp.TCP)):
            payload.data.sum = 0
    elif isinstance(payload, dpkt.arp.ARP):
        payload.sha = ethernet.src
        payload.tha = ethernet.dst
        payload.spa = source_ip
        payload.tpa = destination_ip
    return bytes(ethernet)


def _packet_gap_seconds(
    source_timestamp: float,
    previous_source_timestamp: float | None,
    packet_bytes: int,
    document: PcapReplayDocument,
) -> tuple[float, bool]:
    timing = document.spec.timing
    if isinstance(timing, ReplayCaptureTiming):
        assert previous_source_timestamp is not None
        raw_delta = source_timestamp - previous_source_timestamp
        corrected = raw_delta < 0
        return max(0.0, raw_delta) / timing.multiplier, corrected
    if isinstance(timing, ReplayFixedRateTiming):
        rate = timing.rate
        if rate.unit == "pps":
            return 1 / rate.value, False
        if rate.unit == "bps_l2":
            return packet_bytes * 8 / rate.value, False
        if rate.unit == "bps_l1":
            return (packet_bytes + 24) * 8 / rate.value, False
        raise ValueError("fixed-rate PCAP replay does not support percent_l1")
    return 0.000000001, False

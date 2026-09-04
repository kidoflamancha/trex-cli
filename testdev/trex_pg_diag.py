#!/usr/bin/env python3
"""Minimal red/green probe for TRex ixgbe hardware packet-group RX stats."""

from __future__ import annotations

import sys
import time

from trex.stl.api import (
    IP,
    UDP,
    Ether,
    STLClient,
    STLFlowStats,
    STLPktBuilder,
    STLStream,
    STLTXSingleBurst,
)

PACKET_COUNT = 10
PG_ID = 7
TX_PORT = 0
RX_PORT = 1
XSTAT_KEYS = (
    "rx_good_packets",
    "rx_total_packets",
    "rx_q0_errors",
    "flow_director_matched_filters",
    "flow_director_missed_filters",
)


def main() -> int:
    client = STLClient(server="127.0.0.1")
    client.connect()
    try:
        client.acquire(ports=[TX_PORT, RX_PORT], force=True)
        client.reset(ports=[TX_PORT, RX_PORT])
        before = client.get_xstats(RX_PORT)

        packet = (
            Ether(
                dst="02:00:00:02:00:00",
                src="02:00:00:02:00:00",
            )
            / IP(src="192.0.2.10", dst="192.0.2.11")
            / UDP(sport=1025, dport=12)
            / ("x" * 18)
        )
        stream = STLStream(
            packet=STLPktBuilder(pkt=packet),
            mode=STLTXSingleBurst(total_pkts=PACKET_COUNT, pps=100),
            flow_stats=STLFlowStats(pg_id=PG_ID),
        )
        client.add_streams(stream, ports=[TX_PORT])
        client.start(ports=[TX_PORT])
        client.wait_on_traffic(ports=[TX_PORT])
        time.sleep(0.2)

        after = client.get_xstats(RX_PORT)
        flow = client.get_pgid_stats([PG_ID])["flow_stats"][PG_ID]
        tx_packets = flow["tx_pkts"].get(TX_PORT, 0)
        rx_packets = flow["rx_pkts"].get(RX_PORT, 0)
        deltas = {
            key: after.get(key, 0) - before.get(key, 0)
            for key in XSTAT_KEYS
        }
        print(
            f"PG_RESULT tx{TX_PORT}={tx_packets} "
            f"rx{RX_PORT}={rx_packets}"
        )
        print("XSTAT_DELTA " + " ".join(f"{k}={v}" for k, v in deltas.items()))

        passed = (
            tx_packets == PACKET_COUNT
            and rx_packets == PACKET_COUNT
            and deltas["flow_director_matched_filters"] == PACKET_COUNT
            and deltas["flow_director_missed_filters"] == 0
        )
        print("VERDICT=" + ("PASS" if passed else "FAIL"))
        return 0 if passed else 1
    finally:
        try:
            client.reset(ports=[TX_PORT, RX_PORT])
            client.release(ports=[TX_PORT, RX_PORT])
        finally:
            client.disconnect()


if __name__ == "__main__":
    sys.exit(main())

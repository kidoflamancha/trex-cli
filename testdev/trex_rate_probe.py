#!/usr/bin/env python3
"""Short hardware-FlowStats rate probe for the SSH-forwarded TRex lab."""

from __future__ import annotations

import argparse
import json
import time
from typing import Any

from trex.stl.api import (
    IP,
    UDP,
    Ether,
    Raw,
    STLClient,
    STLFlowStats,
    STLPktBuilder,
    STLStream,
    STLTXCont,
    STLTXSingleBurst,
)

TX_PORT = 0
RX_PORT = 1
XSTAT_KEYS = (
    "flow_director_matched_filters",
    "flow_director_missed_filters",
    "rx_q0_errors",
)


def _counter(values: dict[Any, Any], port: int) -> int:
    return int(values.get(port, values.get(str(port), 0)) or 0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rates", default="80,100", help="comma-separated percent L1")
    parser.add_argument("--duration", type=float, default=3)
    parser.add_argument("--frame-size", type=int, default=64)
    parser.add_argument(
        "--learn",
        action="store_true",
        help="send reverse frames first so the switch learns the RX-side MAC",
    )
    args = parser.parse_args()
    rates = [float(item) for item in args.rates.split(",")]
    if not rates or any(rate <= 0 or rate > 100 for rate in rates):
        parser.error("rates must be in (0, 100]")
    if args.duration <= 0 or args.frame_size < 64:
        parser.error("duration must be positive and frame-size must be at least 64")

    client = STLClient(
        server="127.0.0.1",
        sync_port=14501,
        async_port=14500,
        username="trex-rate-probe",
        verbose_level="error",
    )
    client.connect()
    acquired = False
    try:
        client.acquire(ports=[TX_PORT, RX_PORT], force=False)
        acquired = True
        client.reset(ports=[TX_PORT, RX_PORT])
        info = client.get_port_info(ports=[TX_PORT, RX_PORT])
        speeds = {str(port): float(value["speed"]) for port, value in zip(
            [TX_PORT, RX_PORT], info, strict=True
        )}
        print("LINK " + json.dumps({"speedGbps": speeds}, sort_keys=True))

        header = (
            Ether(src="02:00:00:02:00:00", dst="02:00:00:02:00:00")
            / IP(src="198.18.0.1", dst="198.19.0.1")
            / UDP(sport=49152, dport=7)
        )
        padding = args.frame_size - 4 - len(header)
        if padding < 0:
            parser.error("frame-size is too small for Ethernet/IPv4/UDP")
        packet = header / Raw(load=bytes(padding))

        if args.learn:
            reverse_header = (
                Ether(src="02:00:00:02:00:00", dst="02:00:00:02:00:00")
                / IP(src="198.19.0.1", dst="198.18.0.1")
                / UDP(sport=7, dport=49152)
            )
            reverse_padding = args.frame_size - 4 - len(reverse_header)
            reverse = reverse_header / Raw(load=bytes(reverse_padding))
            learning_stream = STLStream(
                packet=STLPktBuilder(pkt=reverse),
                mode=STLTXSingleBurst(total_pkts=10, pps=1000),
            )
            client.add_streams(learning_stream, ports=[RX_PORT])
            client.start(ports=[RX_PORT])
            client.wait_on_traffic(ports=[RX_PORT], timeout=5)
            client.remove_all_streams(ports=[RX_PORT])
            print("LEARNING reverseFrames=10")

        for index, rate in enumerate(rates):
            pg_id = 31 + index
            stream = STLStream(
                packet=STLPktBuilder(pkt=packet),
                mode=STLTXCont(percentage=rate),
                flow_stats=STLFlowStats(pg_id=pg_id),
            )
            client.add_streams(stream, ports=[TX_PORT])
            client.clear_stats(ports=[TX_PORT, RX_PORT])
            xstats_before = client.get_xstats(RX_PORT)
            client.start(ports=[TX_PORT], duration=args.duration)
            client.wait_on_traffic(ports=[TX_PORT], timeout=args.duration + 5)
            time.sleep(0.5)
            ports = client.get_stats(ports=[TX_PORT, RX_PORT])
            xstats_after = client.get_xstats(RX_PORT)
            flow = client.get_pgid_stats([pg_id])["flow_stats"][pg_id]
            tx = _counter(flow["tx_pkts"], TX_PORT)
            rx = _counter(flow["rx_pkts"], RX_PORT)
            loss = max(0, tx - rx)
            port_tx = int(ports[TX_PORT].get("opackets", 0))
            port_rx = int(ports[RX_PORT].get("ipackets", 0))
            unclassified_rx = max(0, port_rx - rx)
            port_counters_support_flow = (
                port_tx == tx and port_rx >= rx and rx <= tx
            )
            marker_loss_supported_by_port = loss == 0 or port_rx < tx
            result = {
                "ratePercentL1": rate,
                "durationSeconds": args.duration,
                "frameSize": args.frame_size,
                "txFrames": tx,
                "rxFrames": rx,
                "lossFrames": loss,
                "lossPercent": 0 if tx == 0 else loss / tx * 100,
                "portTxFrames": port_tx,
                "portRxFrames": port_rx,
                "unclassifiedRxFrames": unclassified_rx,
                "flowStatsConsistent": (
                    port_counters_support_flow and marker_loss_supported_by_port
                ),
                "portErrors": sum(
                    int(ports[port].get("ierrors", 0))
                    + int(ports[port].get("oerrors", 0))
                    for port in (TX_PORT, RX_PORT)
                ),
                "xstatDelta": {
                    key: int(xstats_after.get(key, 0)) - int(xstats_before.get(key, 0))
                    for key in XSTAT_KEYS
                },
            }
            print("RATE_RESULT " + json.dumps(result, sort_keys=True))
            client.remove_all_streams(ports=[TX_PORT])
        return 0
    finally:
        try:
            if acquired:
                client.reset(ports=[TX_PORT, RX_PORT])
                client.release(ports=[TX_PORT, RX_PORT])
        finally:
            client.disconnect()


if __name__ == "__main__":
    raise SystemExit(main())

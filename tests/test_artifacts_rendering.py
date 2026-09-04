from __future__ import annotations

import json
from csv import DictReader
from io import StringIO

from trex_cli.artifacts import (
    _measurement_csv,
    _render_method_report,
    _render_report_context,
    _render_test_environment,
    _trial_lines,
)


def test_report_renders_latency_and_back_to_back_tables() -> None:
    latency = _render_method_report(
        "latency",
        {
            "definition": "store-and-forward",
            "frames": {
                "64": {
                    "same-destination": {"averageMicroseconds": 3.2},
                    "new-destination": {"averageMicroseconds": 4.1},
                }
            },
        },
    )
    back_to_back = _render_method_report(
        "back-to-back",
        {
            "frames": {
                "64": {
                    "averageFrames": 1000,
                    "minimumFrames": 900,
                    "maximumFrames": 1100,
                    "standardDeviationFrames": 50,
                    "correctedBufferSeconds": 0.001,
                }
            }
        },
    )

    assert "RFC 1242 definition: `store-and-forward`" in latency
    assert "| 64 | same-destination | 3.2 |" in latency
    assert "| 64 | 1000 | 900 | 1100 | 50 | 0.001 |" in back_to_back


def test_trial_ndjson_preserves_latency_and_back_to_back_raw_evidence() -> None:
    lines = _trial_lines(
        {
            "tests": {
                "latency": {
                    "frames": {
                        "64": {
                            "same-destination": {
                                "trials": [{"repetition": 1, "latencyMicroseconds": 3.2}]
                            }
                        }
                    }
                },
                "back-to-back": {
                    "frames": {
                        "64": {"searches": [{"repetition": 1, "longestZeroLossBurstFrames": 1000}]}
                    }
                },
            }
        }
    )

    records = [json.loads(line) for line in lines]
    assert records == [
        {
            "frameSize": 64,
            "latencyMicroseconds": 3.2,
            "repetition": 1,
            "scenario": "same-destination",
            "test": "latency",
        },
        {
            "frameSize": 64,
            "longestZeroLossBurstFrames": 1000,
            "repetition": 1,
            "test": "back-to-back",
        },
    ]


def test_measurement_csv_flattens_all_four_report_methods() -> None:
    content = _measurement_csv(
        {
            "tests": {
                "throughput": {"rates": {"64": {"percentL1": 75, "fps": 1000}}},
                "latency": {"frames": {"64": {"same-destination": {"averageMicroseconds": 3.2}}}},
                "frame-loss": {
                    "frames": {"64": {"points": [{"ratePercentL1": 100, "lossPercent": 25}]}}
                },
                "back-to-back": {"frames": {"64": {"averageFrames": 1000}}},
            }
        }
    ).decode()
    rows = list(DictReader(StringIO(content)))

    assert rows[0]["method"] == "throughput"
    assert rows[0]["percentL1"] == "75"
    assert rows[1]["scenario"] == "same-destination"
    assert rows[1]["averageLatencyMicroseconds"] == "3.2"
    assert rows[2]["offeredPercentL1"] == "100"
    assert rows[2]["lossPercent"] == "25"
    assert rows[3]["averageBurstFrames"] == "1000"


def test_report_renders_generic_dut_and_lab_context() -> None:
    rendered = _render_report_context(
        {
            "dut": {
                "name": "dut-1",
                "hardware": "switch-a",
                "softwareVersion": "1.2.3",
                "configurationDigest": "sha256:" + "a" * 64,
                "configurationArtifact": "dut-config.txt",
            },
            "topology": "port 0 -> DUT -> port 1",
            "medium": "10GBASE-SR",
            "protocol": "IPv4/UDP",
            "streamType": "unidirectional",
            "isolationStatement": "dedicated lab",
        }
    )

    assert "DUT: `dut-1`" in rendered
    assert "Topology: port 0 -> DUT -> port 1" in rendered


def test_report_renders_runtime_port_environment() -> None:
    rendered = _render_test_environment(
        {
            "trexVersion": "v3.08",
            "ports": {
                "0": {
                    "lineRateBps": 2_500_000_000,
                    "description": "Intel X550T",
                    "driver": "net_ixgbe",
                    "ieee1588": False,
                }
            },
        }
    )

    assert "TRex version: `v3.08`" in rendered
    assert "| 0 | 2500000000 | Intel X550T | net_ixgbe | False |" in rendered

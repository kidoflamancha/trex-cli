from __future__ import annotations

from copy import deepcopy

from trex_cli.publication import assess_rfc2544_publication

FRAME_SIZES = (64, 128, 256, 512, 1024, 1280, 1518)


def complete_summary() -> dict[str, object]:
    throughput_frames = {
        str(size): {
            "valid": True,
            "percentL1": 75.0,
            "fps": 1_000.0,
            "theoreticalMaxFps": 2_000.0,
            "trials": [
                {
                    "phase": "confirmation-1",
                    "durationSeconds": 60,
                    "valid": True,
                    "lossFrames": 0,
                }
            ],
        }
        for size in FRAME_SIZES
    }
    latency_frames = {
        str(size): {
            scenario: {
                "valid": True,
                "samplesMicroseconds": [10.0] * 20,
                "trials": [
                    {
                        "durationSeconds": 120,
                        "tagAfterSeconds": 60,
                        "valid": True,
                    }
                ]
                * 20,
            }
            for scenario in ("same-destination", "new-destination")
        }
        for size in FRAME_SIZES
    }
    frame_loss_frames = {
        str(size): {
            "valid": True,
            "stoppedAfterTwoZeroLossTrials": True,
            "points": [
                {
                    "ratePercentL1": 100,
                    "durationSeconds": 60,
                    "valid": True,
                    "lossPercent": 10,
                },
                {
                    "ratePercentL1": 90,
                    "durationSeconds": 60,
                    "valid": True,
                    "lossPercent": 0,
                },
                {
                    "ratePercentL1": 80,
                    "durationSeconds": 60,
                    "valid": True,
                    "lossPercent": 0,
                },
            ],
        }
        for size in FRAME_SIZES
    }
    back_to_back_frames = {
        str(size): {
            "valid": True,
            "repetitions": 20,
            "searches": [{"valid": True, "longestZeroLossBurstFrames": 1000} for _ in range(20)],
        }
        for size in FRAME_SIZES
    }
    return {
        "simulated": False,
        "mode": "strict",
        "reportContext": {
            "dut": {
                "name": "dut-1",
                "hardware": "example-switch",
                "softwareVersion": "1.2.3",
                "configurationDigest": "sha256:" + "a" * 64,
                "configurationArtifact": "dut-config.txt",
            },
            "topology": "TRex port 0 -> DUT -> TRex port 1",
            "medium": "10GBASE-SR",
            "protocol": "IPv4/UDP",
            "streamType": "single unidirectional stream",
            "isolationStatement": "Dedicated isolated laboratory path",
        },
        "testEnvironment": {
            "trexVersion": "v3.08",
            "ports": {
                "0": {
                    "lineRateBps": 2_500_000_000,
                    "driver": "net_ixgbe",
                    "description": "Intel X550T",
                    "ieee1588": True,
                },
                "1": {
                    "lineRateBps": 2_500_000_000,
                    "driver": "net_ixgbe",
                    "description": "Intel X550T",
                    "ieee1588": True,
                },
            },
        },
        "tests": {
            "throughput": {
                "standardConformance": "rfc2544-throughput-methodology",
                "ceilingPercentL1": 100,
                "frames": throughput_frames,
            },
            "latency": {
                "standardConformance": "rfc2544-latency-methodology",
                "timestampCalibration": {
                    "valid": True,
                    "calibrationId": "cal-1",
                    "calibrationDigest": "sha256:" + "c" * 64,
                    "calibrationArtifact": "latency-calibration.json",
                    "timestampMode": "ieee1588",
                    "measuredAt": "2026-08-01T00:00:00Z",
                    "validUntil": "2027-08-01T00:00:00Z",
                    "maximumUncertaintyMicroseconds": 0.2,
                },
                "definition": "store-and-forward",
                "frames": latency_frames,
            },
            "frame-loss": {
                "standardConformance": "rfc2544-frame-loss-methodology",
                "ceilingPercentL1": 100,
                "frames": frame_loss_frames,
            },
            "back-to-back": {
                "standardConformance": "rfc9004-back-to-back-methodology",
                "maximumBurstSeconds": 30,
                "bufferDepletionSeconds": 2,
                "frames": back_to_back_frames,
            },
        },
    }


def test_complete_publication_requires_all_raw_method_evidence() -> None:
    assessment = assess_rfc2544_publication(complete_summary())

    assert assessment.status == "COMPLETE"
    assert assessment.conformance == "rfc2544-rfc9004-complete"
    assert assessment.issues == ()


def test_publication_fails_closed_for_simulation_and_missing_latency_repetition() -> None:
    summary = deepcopy(complete_summary())
    summary["simulated"] = True
    tests = summary["tests"]
    assert isinstance(tests, dict)
    latency = tests["latency"]
    assert isinstance(latency, dict)
    frames = latency["frames"]
    assert isinstance(frames, dict)
    frame = frames["64"]
    assert isinstance(frame, dict)
    scenario = frame["new-destination"]
    assert isinstance(scenario, dict)
    scenario["samplesMicroseconds"] = [10.0] * 19

    assessment = assess_rfc2544_publication(summary)

    assert assessment.status == "PARTIAL"
    assert "measurement is simulated" in assessment.issues
    assert any("latency 64/new-destination" in issue for issue in assessment.issues)


def test_publication_fails_closed_without_dut_and_lab_context() -> None:
    summary = complete_summary()
    summary.pop("reportContext")

    assessment = assess_rfc2544_publication(summary)

    assert assessment.status == "PARTIAL"
    assert "DUT and laboratory report context is missing" in assessment.issues


def test_publication_fails_closed_without_runtime_port_evidence() -> None:
    summary = complete_summary()
    summary.pop("testEnvironment")

    assessment = assess_rfc2544_publication(summary)

    assert assessment.status == "PARTIAL"
    assert "TRex and port environment evidence is missing" in assessment.issues


def test_publication_accepts_justified_back_to_back_not_applicable_frames() -> None:
    summary = complete_summary()
    tests = summary["tests"]
    assert isinstance(tests, dict)
    back_to_back = tests["back-to-back"]
    assert isinstance(back_to_back, dict)
    frames = back_to_back["frames"]
    assert isinstance(frames, dict)
    frames["1518"] = {
        "valid": True,
        "applicability": "not-applicable-throughput-equals-theoretical",
        "throughputFps": 1000.0,
        "theoreticalMaxFps": 1000.0,
    }

    assessment = assess_rfc2544_publication(summary)

    assert assessment.status == "COMPLETE"


def test_publication_rejects_frame_loss_steps_over_ten_percent() -> None:
    summary = complete_summary()
    tests = summary["tests"]
    assert isinstance(tests, dict)
    frame_loss = tests["frame-loss"]
    assert isinstance(frame_loss, dict)
    frames = frame_loss["frames"]
    assert isinstance(frames, dict)
    frame = frames["64"]
    assert isinstance(frame, dict)
    points = frame["points"]
    assert isinstance(points, list)
    points[1]["ratePercentL1"] = 80

    assessment = assess_rfc2544_publication(summary)

    assert assessment.status == "PARTIAL"
    assert "frame-loss 64 curve is incomplete" in assessment.issues

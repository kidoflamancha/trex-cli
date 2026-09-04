from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import pairwise
from typing import Any, Literal

STANDARD_FRAME_SIZES = (64, 128, 256, 512, 1024, 1280, 1518)
REQUIRED_TESTS = ("throughput", "latency", "frame-loss", "back-to-back")


@dataclass(frozen=True, slots=True)
class PublicationAssessment:
    status: Literal["COMPLETE", "PARTIAL"]
    conformance: str
    issues: tuple[str, ...]


def assess_rfc2544_publication(summary: dict[str, Any]) -> PublicationAssessment:
    """Fail-closed assessment of the evidence bundle, independent of rendering."""
    issues: list[str] = []
    if summary.get("simulated") is not False:
        issues.append("measurement is simulated")
    if summary.get("mode") != "strict":
        issues.append("suite mode is not strict")
    if not _valid_report_context(summary.get("reportContext")):
        issues.append("DUT and laboratory report context is missing")
    if not _valid_test_environment(summary.get("testEnvironment")):
        issues.append("TRex and port environment evidence is missing")
    tests = summary.get("tests")
    if not isinstance(tests, dict):
        issues.append("method evidence is missing")
        return _assessment(issues)
    if tuple(tests) != REQUIRED_TESTS:
        issues.append("the four required methods are missing or out of order")

    _assess_throughput(tests.get("throughput"), issues)
    _assess_latency(tests.get("latency"), issues)
    _assess_frame_loss(tests.get("frame-loss"), issues)
    _assess_back_to_back(tests.get("back-to-back"), issues)
    return _assessment(issues)


def _assessment(issues: list[str]) -> PublicationAssessment:
    unique = tuple(dict.fromkeys(issues))
    return PublicationAssessment(
        status="PARTIAL" if unique else "COMPLETE",
        conformance=("rfc2544-suite-partial" if unique else "rfc2544-rfc9004-complete"),
        issues=unique,
    )


def _method_frames(
    value: object, name: str, conformance: str, issues: list[str]
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        issues.append(f"{name} evidence is missing")
        return None
    if value.get("standardConformance") != conformance:
        issues.append(f"{name} methodology is not conforming")
    frames = value.get("frames")
    if not isinstance(frames, dict) or set(frames) != {str(size) for size in STANDARD_FRAME_SIZES}:
        issues.append(f"{name} does not contain all standard frame sizes")
        return None
    return frames


def _assess_throughput(value: object, issues: list[str]) -> None:
    frames = _method_frames(value, "throughput", "rfc2544-throughput-methodology", issues)
    if not isinstance(value, dict) or frames is None:
        return
    if value.get("ceilingPercentL1") != 100:
        issues.append("throughput did not search the full 100% range")
    for frame_size, frame in frames.items():
        if not isinstance(frame, dict) or frame.get("valid") is not True:
            issues.append(f"throughput {frame_size} is invalid")
            continue
        trials = frame.get("trials")
        confirmed = isinstance(trials, list) and any(
            isinstance(trial, dict)
            and str(trial.get("phase", "")).startswith("confirmation")
            and _number(trial.get("durationSeconds"), minimum=60)
            and trial.get("valid") is True
            and trial.get("lossFrames") == 0
            for trial in trials
        )
        if not confirmed:
            issues.append(f"throughput {frame_size} lacks a 60 second zero-loss confirmation")


def _assess_latency(value: object, issues: list[str]) -> None:
    frames = _method_frames(value, "latency", "rfc2544-latency-methodology", issues)
    if not isinstance(value, dict) or frames is None:
        return
    calibration = value.get("timestampCalibration")
    if not _valid_calibration(calibration):
        issues.append("latency timestamp calibration is missing or invalid")
    if value.get("definition") not in {"store-and-forward", "bit-forwarding"}:
        issues.append("latency RFC 1242 definition is missing")
    for frame_size, frame in frames.items():
        if not isinstance(frame, dict):
            issues.append(f"latency {frame_size} evidence is invalid")
            continue
        for scenario_name in ("same-destination", "new-destination"):
            scenario = frame.get(scenario_name)
            samples = scenario.get("samplesMicroseconds") if isinstance(scenario, dict) else None
            trials = scenario.get("trials") if isinstance(scenario, dict) else None
            valid_trials = (
                isinstance(trials, list)
                and len(trials) >= 20
                and all(
                    isinstance(trial, dict)
                    and trial.get("valid") is True
                    and _number(trial.get("durationSeconds"), minimum=120)
                    and _number(trial.get("tagAfterSeconds"), minimum=60)
                    for trial in trials
                )
            )
            if (
                not isinstance(scenario, dict)
                or scenario.get("valid") is not True
                or not isinstance(samples, list)
                or len(samples) < 20
                or not isinstance(trials, list)
                or len(samples) != len(trials)
                or not valid_trials
            ):
                issues.append(f"latency {frame_size}/{scenario_name} lacks 20 valid tagged trials")


def _assess_frame_loss(value: object, issues: list[str]) -> None:
    frames = _method_frames(value, "frame-loss", "rfc2544-frame-loss-methodology", issues)
    if not isinstance(value, dict) or frames is None:
        return
    if value.get("ceilingPercentL1") != 100:
        issues.append("frame-loss curve did not start at 100%")
    for frame_size, frame in frames.items():
        points = frame.get("points") if isinstance(frame, dict) else None
        valid_points = (
            isinstance(points, list)
            and bool(points)
            and all(
                isinstance(point, dict)
                and point.get("valid") is True
                and _number(point.get("durationSeconds"), minimum=60)
                for point in points
            )
        )
        first_point = points[0] if isinstance(points, list) and points else None
        starts_at_maximum = (
            valid_points
            and isinstance(first_point, dict)
            and first_point.get("ratePercentL1") == 100
        )
        rates = (
            [point.get("ratePercentL1") for point in points if isinstance(point, dict)]
            if isinstance(points, list)
            else []
        )
        valid_steps = bool(rates) and all(
            isinstance(previous, int | float)
            and isinstance(current, int | float)
            and 0 < previous - current <= 10
            for previous, current in pairwise(rates)
        )
        ends_with_two_zero_loss = (
            isinstance(points, list)
            and len(points) >= 2
            and all(
                isinstance(point, dict) and point.get("lossPercent") == 0 for point in points[-2:]
            )
        )
        if (
            not isinstance(frame, dict)
            or frame.get("valid") is not True
            or frame.get("stoppedAfterTwoZeroLossTrials") is not True
            or not starts_at_maximum
            or not valid_steps
            or not ends_with_two_zero_loss
        ):
            issues.append(f"frame-loss {frame_size} curve is incomplete")


def _assess_back_to_back(value: object, issues: list[str]) -> None:
    frames = _method_frames(value, "back-to-back", "rfc9004-back-to-back-methodology", issues)
    if frames is None:
        return
    if not isinstance(value, dict):
        return
    if not _number(value.get("maximumBurstSeconds"), minimum=30):
        issues.append("back-to-back upper range is shorter than 30 seconds")
    if not _number(value.get("bufferDepletionSeconds"), minimum=2):
        issues.append("back-to-back buffer depletion interval is shorter than 2 seconds")
    for frame_size, frame in frames.items():
        if _valid_back_to_back_not_applicable(frame):
            continue
        searches = frame.get("searches") if isinstance(frame, dict) else None
        repetitions = frame.get("repetitions") if isinstance(frame, dict) else None
        if (
            not isinstance(frame, dict)
            or frame.get("valid") is not True
            or not isinstance(repetitions, int)
            or repetitions < 1
            or not isinstance(searches, list)
            or len(searches) != repetitions
            or not all(
                isinstance(search, dict)
                and search.get("valid") is True
                and isinstance(search.get("longestZeroLossBurstFrames"), int)
                for search in searches
            )
        ):
            issues.append(f"back-to-back {frame_size} searches are incomplete")


def _valid_report_context(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    dut = value.get("dut")
    return (
        isinstance(dut, dict)
        and all(dut.get(field) for field in ("name", "hardware", "softwareVersion"))
        and bool(dut.get("configurationArtifact"))
        and isinstance(dut.get("configurationDigest"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", str(dut["configurationDigest"])) is not None
        and all(
            value.get(field)
            for field in (
                "topology",
                "medium",
                "protocol",
                "streamType",
                "isolationStatement",
            )
        )
    )


def _valid_test_environment(value: object) -> bool:
    if not isinstance(value, dict) or not value.get("trexVersion"):
        return False
    ports = value.get("ports")
    return (
        isinstance(ports, dict)
        and len(ports) >= 2
        and all(
            isinstance(port, dict)
            and _number(port.get("lineRateBps"), minimum=1)
            and bool(port.get("driver"))
            and bool(port.get("description"))
            and port.get("ieee1588") is True
            for port in ports.values()
        )
    )


def _valid_calibration(value: object) -> bool:
    return (
        isinstance(value, dict)
        and value.get("valid") is True
        and bool(value.get("calibrationId"))
        and isinstance(value.get("calibrationDigest"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", str(value["calibrationDigest"])) is not None
        and bool(value.get("calibrationArtifact"))
        and value.get("timestampMode") == "ieee1588"
        and bool(value.get("measuredAt"))
        and bool(value.get("validUntil"))
        and _number(value.get("maximumUncertaintyMicroseconds"), minimum=0)
    )


def _valid_back_to_back_not_applicable(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    throughput = value.get("throughputFps")
    theoretical = value.get("theoreticalMaxFps")
    return (
        value.get("valid") is True
        and value.get("applicability") == "not-applicable-throughput-equals-theoretical"
        and isinstance(throughput, int | float)
        and isinstance(theoretical, int | float)
        and throughput >= theoretical
    )


def _number(value: object, *, minimum: float) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool) and value >= minimum

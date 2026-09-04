from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from statistics import fmean, pstdev
from typing import Literal, Protocol


@dataclass(frozen=True, slots=True)
class TrialObservation:
    valid: bool
    loss_frames: int
    tx_frames: int
    rx_frames: int
    target_rate_reached: bool
    details: dict[str, object]


class TrialFunction(Protocol):
    def __call__(
        self, frame_size: int, rate_percent: float, duration_seconds: float
    ) -> TrialObservation: ...


type LatencyDefinition = Literal["store-and-forward", "bit-forwarding"]


@dataclass(frozen=True, slots=True)
class LatencyObservation:
    valid: bool
    latency_microseconds: float | None
    details: dict[str, object]


class LatencyTrialFunction(Protocol):
    def __call__(
        self,
        frame_size: int,
        rate_percent: float,
        duration_seconds: float,
        tag_after_seconds: float,
    ) -> LatencyObservation: ...


@dataclass(frozen=True, slots=True)
class LatencySettings:
    trial_seconds: float = 120
    tag_after_seconds: float = 60
    repetitions: int = 20


@dataclass(frozen=True, slots=True)
class LatencyResult:
    frame_size: int
    throughput_percent_l1: float
    definition: LatencyDefinition
    valid: bool
    samples_microseconds: list[float]
    average_microseconds: float | None
    trials: list[dict[str, object]]


@dataclass(frozen=True, slots=True)
class BackToBackObservation:
    valid: bool
    tx_frames: int
    rx_frames: int
    details: dict[str, object]


class BackToBackTrialFunction(Protocol):
    def __call__(
        self, frame_size: int, burst_frames: int
    ) -> BackToBackObservation: ...


@dataclass(frozen=True, slots=True)
class BackToBackSettings:
    repetitions: int = 20
    minimum_step_frames: int = 1
    maximum_burst_frames: int = 1_000_000


@dataclass(frozen=True, slots=True)
class BackToBackResult:
    frame_size: int
    valid: bool
    longest_zero_loss_bursts: list[int]
    average_frames: float | None
    minimum_frames: int | None
    maximum_frames: int | None
    standard_deviation_frames: float | None
    implied_buffer_seconds: float | None
    corrected_buffer_seconds: float | None
    searches: list[dict[str, object]]


@dataclass(frozen=True, slots=True)
class SearchSettings:
    resolution: float
    trial_seconds: float
    confirmation_seconds: float
    confirmations: int
    search_samples: int = 1


@dataclass(frozen=True, slots=True)
class FrameSearchResult:
    frame_size: int
    throughput_percent_l1: float | None
    valid: bool
    trials: list[dict[str, object]]


@dataclass(frozen=True, slots=True)
class FrameLossSettings:
    step_percent: float
    trial_seconds: float
    consecutive_zero_loss: int = 2


@dataclass(frozen=True, slots=True)
class FrameLossResult:
    frame_size: int
    valid: bool
    stopped_after_consecutive_zero_loss: bool
    trials: list[dict[str, object]]


def measure_latency(
    frame_size: int,
    throughput_percent_l1: float,
    settings: LatencySettings,
    trial: LatencyTrialFunction,
    *,
    definition: LatencyDefinition,
) -> LatencyResult:
    samples: list[float] = []
    trials: list[dict[str, object]] = []
    valid = True
    for repetition in range(1, settings.repetitions + 1):
        observation = trial(
            frame_size,
            throughput_percent_l1,
            settings.trial_seconds,
            settings.tag_after_seconds,
        )
        sample = observation.latency_microseconds
        sample_valid = observation.valid and sample is not None and sample >= 0
        trials.append(
            {
                "repetition": repetition,
                "durationSeconds": settings.trial_seconds,
                "tagAfterSeconds": settings.tag_after_seconds,
                "valid": sample_valid,
                "latencyMicroseconds": sample,
                "details": observation.details,
            }
        )
        if sample_valid:
            assert sample is not None
            samples.append(sample)
        else:
            valid = False
    average = fmean(samples) if valid and len(samples) == settings.repetitions else None
    return LatencyResult(
        frame_size=frame_size,
        throughput_percent_l1=throughput_percent_l1,
        definition=definition,
        valid=valid,
        samples_microseconds=samples,
        average_microseconds=average,
        trials=trials,
    )


def measure_back_to_back(
    frame_size: int,
    *,
    theoretical_fps: float,
    throughput_fps: float,
    settings: BackToBackSettings,
    trial: BackToBackTrialFunction,
) -> BackToBackResult:
    searches: list[dict[str, object]] = []
    longest: list[int] = []
    prerequisites_valid = theoretical_fps > 0 and 0 <= throughput_fps < theoretical_fps
    all_repetitions_valid = prerequisites_valid
    for repetition in range(1, settings.repetitions + 1):
        repetition_valid = prerequisites_valid
        trials: list[dict[str, object]] = []
        maximum = trial(frame_size, settings.maximum_burst_frames)
        trials.append(_burst_record(settings.maximum_burst_frames, "upper-bound", maximum))
        if not maximum.valid or maximum.rx_frames >= maximum.tx_frames:
            all_repetitions_valid = False
            searches.append(
                {"repetition": repetition, "valid": False, "trials": trials}
            )
            continue

        low = 0
        high = settings.maximum_burst_frames
        step = settings.minimum_step_frames
        while high - low > step:
            candidate = ((low + high) // (2 * step)) * step
            if candidate <= low:
                candidate = low + step
            observation = trial(frame_size, candidate)
            trials.append(_burst_record(candidate, "binary-search", observation))
            if not observation.valid:
                repetition_valid = False
                all_repetitions_valid = False
                break
            if observation.rx_frames == observation.tx_frames:
                low = candidate
            else:
                high = candidate
        if not repetition_valid or low <= 0:
            all_repetitions_valid = False
            searches.append(
                {"repetition": repetition, "valid": False, "trials": trials}
            )
            continue

        verification = trial(frame_size, low)
        verification_record = _burst_record(low, "loss-verification", verification)
        verified = verification.valid and verification.rx_frames == verification.tx_frames
        all_repetitions_valid = all_repetitions_valid and verified
        searches.append(
            {
                "repetition": repetition,
                "valid": verified,
                "longestZeroLossBurstFrames": low if verified else None,
                "trials": trials,
                "verification": verification_record,
            }
        )
        if verified:
            longest.append(low)

    complete = all_repetitions_valid and len(longest) == settings.repetitions
    average = fmean(longest) if complete else None
    implied = average / theoretical_fps if average is not None else None
    corrected = (
        implied * (1 - throughput_fps / theoretical_fps)
        if implied is not None
        else None
    )
    return BackToBackResult(
        frame_size=frame_size,
        valid=complete,
        longest_zero_loss_bursts=longest,
        average_frames=average,
        minimum_frames=min(longest) if complete else None,
        maximum_frames=max(longest) if complete else None,
        standard_deviation_frames=pstdev(longest) if complete else None,
        implied_buffer_seconds=implied,
        corrected_buffer_seconds=corrected,
        searches=searches,
    )


def settings_for(mode: str, ceiling_percent: float) -> SearchSettings:
    base_resolution = 0.1 if mode == "strict" else 0.5
    resolution = min(base_resolution, max(ceiling_percent / 10, 0.0001))
    if mode == "strict":
        return SearchSettings(resolution, 10, 60, 3, search_samples=3)
    return SearchSettings(resolution, 3, 10, 1)


def frame_loss_settings_for(mode: str, ceiling_percent: float) -> FrameLossSettings:
    # RFC 2544 section 26.3 permits at most 10% granularity. A safety ceiling
    # below 10% still needs enough non-zero points to establish the trend.
    step = min(10.0, max(ceiling_percent / 10, 1e-12))
    return FrameLossSettings(step, 60 if mode == "strict" else 3)


def measure_frame_loss(
    frame_size: int,
    ceiling_percent: float,
    settings: FrameLossSettings,
    trial: TrialFunction,
    on_observation: Callable[[dict[str, object]], None] | None = None,
) -> FrameLossResult:
    history: list[dict[str, object]] = []
    consecutive_zero = 0
    rate = ceiling_percent

    while rate > 0:
        observation = trial(frame_size, rate, settings.trial_seconds)
        record = _trial_record(rate, settings.trial_seconds, "frame-loss", observation)
        record["lossPercent"] = (
            None
            if observation.tx_frames <= 0
            else observation.loss_frames * 100 / observation.tx_frames
        )
        history.append(record)
        if on_observation is not None:
            on_observation(record)
        if not observation.valid:
            retry = trial(frame_size, rate, settings.trial_seconds)
            retry_record = _trial_record(
                rate, settings.trial_seconds, "frame-loss-retry", retry
            )
            retry_record["lossPercent"] = (
                None if retry.tx_frames <= 0 else retry.loss_frames * 100 / retry.tx_frames
            )
            history.append(retry_record)
            if on_observation is not None:
                on_observation(retry_record)
            observation = retry
        if not observation.valid:
            return FrameLossResult(frame_size, False, False, history)
        if observation.loss_frames == 0:
            consecutive_zero += 1
            if consecutive_zero >= settings.consecutive_zero_loss:
                return FrameLossResult(frame_size, True, True, history)
        else:
            consecutive_zero = 0
        rate = _round_rate(rate - settings.step_percent, settings.step_percent)

    return FrameLossResult(frame_size, True, False, history)


def search_frame(
    frame_size: int,
    ceiling_percent: float,
    settings: SearchSettings,
    trial: TrialFunction,
    on_observation: Callable[[dict[str, object]], None] | None = None,
) -> FrameSearchResult:
    history: list[dict[str, object]] = []

    def observe(rate: float, duration: float, phase: str) -> TrialObservation | None:
        samples = settings.search_samples if phase == "search" else 1
        valid: list[TrialObservation] = []
        for sample in range(samples):
            sample_phase = phase if sample == 0 else f"{phase}-sample-{sample + 1}"
            first = trial(frame_size, rate, duration)
            record = _trial_record(rate, duration, sample_phase, first)
            history.append(record)
            if on_observation is not None:
                on_observation(record)
            if first.valid:
                valid.append(first)
                continue
            retry = trial(frame_size, rate, duration)
            record = _trial_record(rate, duration, f"{sample_phase}-retry", retry)
            history.append(record)
            if on_observation is not None:
                on_observation(record)
            if retry.valid:
                valid.append(retry)

        if not valid:
            return None
        if phase == "search":
            return next((sample for sample in valid if sample.loss_frames == 0), valid[-1])
        return valid[-1]

    ceiling = observe(ceiling_percent, settings.trial_seconds, "search")
    if ceiling is None:
        return FrameSearchResult(frame_size, None, False, history)

    if ceiling.loss_frames == 0:
        candidate = ceiling_percent
    else:
        low = 0.0
        high = ceiling_percent
        while high - low > settings.resolution:
            candidate = _round_rate((low + high) / 2, settings.resolution)
            if candidate <= low or candidate >= high:
                break
            observation = observe(candidate, settings.trial_seconds, "search")
            if observation is None:
                return FrameSearchResult(frame_size, None, False, history)
            if observation.loss_frames == 0:
                low = candidate
            else:
                high = candidate
        candidate = low

    if candidate <= 0:
        return FrameSearchResult(frame_size, 0.0, True, history)

    while candidate > 0:
        confirmation_failed = False
        for _ in range(settings.confirmations):
            confirmation = observe(candidate, settings.confirmation_seconds, "confirmation")
            if confirmation is None:
                return FrameSearchResult(frame_size, None, False, history)
            if confirmation.loss_frames:
                confirmation_failed = True
                break
        if not confirmation_failed:
            return FrameSearchResult(frame_size, candidate, True, history)
        candidate = _round_rate(candidate - settings.resolution, settings.resolution)

    return FrameSearchResult(frame_size, 0.0, True, history)


def _round_rate(value: float, resolution: float) -> float:
    return round(value / resolution) * resolution


def _trial_record(
    rate: float, duration: float, phase: str, observation: TrialObservation
) -> dict[str, object]:
    return {
        "phase": phase,
        "ratePercentL1": rate,
        "durationSeconds": duration,
        "valid": observation.valid,
        "lossFrames": observation.loss_frames,
        "txFrames": observation.tx_frames,
        "rxFrames": observation.rx_frames,
        "targetRateReached": observation.target_rate_reached,
        "details": observation.details,
    }


def _burst_record(
    burst_frames: int, phase: str, observation: BackToBackObservation
) -> dict[str, object]:
    return {
        "phase": phase,
        "burstFrames": burst_frames,
        "valid": observation.valid,
        "txFrames": observation.tx_frames,
        "rxFrames": observation.rx_frames,
        "lossFrames": max(observation.tx_frames - observation.rx_frames, 0),
        "details": observation.details,
    }

from __future__ import annotations

import pytest

from trex_cli.rfc2544 import (
    BackToBackObservation,
    BackToBackSettings,
    FrameLossSettings,
    LatencyObservation,
    LatencySettings,
    SearchSettings,
    TrialObservation,
    measure_back_to_back,
    measure_frame_loss,
    measure_latency,
    search_frame,
)


def observation(*, loss: int = 0, valid: bool = True) -> TrialObservation:
    return TrialObservation(
        valid=valid,
        loss_frames=loss,
        tx_frames=100,
        rx_frames=100 - loss,
        target_rate_reached=valid,
        details={},
    )


def test_ceiling_without_loss_is_confirmed() -> None:
    calls: list[tuple[float, float]] = []

    def trial(_frame: int, rate: float, duration: float) -> TrialObservation:
        calls.append((rate, duration))
        return observation()

    result = search_frame(64, 10, SearchSettings(0.5, 3, 10, 1), trial)

    assert result.valid is True
    assert result.throughput_percent_l1 == 10
    assert calls == [(10, 3), (10, 10)]


def test_binary_search_finds_highest_zero_loss_rate() -> None:
    def trial(_frame: int, rate: float, _duration: float) -> TrialObservation:
        return observation(loss=1 if rate > 4 else 0)

    result = search_frame(64, 10, SearchSettings(1, 3, 10, 1), trial)

    assert result.valid is True
    assert result.throughput_percent_l1 == 4
    assert [item["ratePercentL1"] for item in result.trials[:4]] == [10, 5, 2, 4]


def test_invalid_trial_is_retried_then_invalidates_frame() -> None:
    result = search_frame(
        64,
        10,
        SearchSettings(1, 3, 10, 1),
        lambda *_: observation(valid=False),
    )

    assert result.valid is False
    assert result.throughput_percent_l1 is None
    assert len(result.trials) == 2


def test_observation_callback_reports_each_trial_including_retry() -> None:
    events: list[dict[str, object]] = []

    result = search_frame(
        64,
        10,
        SearchSettings(1, 3, 10, 1),
        lambda *_: observation(valid=False),
        events.append,
    )

    assert result.valid is False
    assert [event["phase"] for event in events] == ["search", "search-retry"]


def test_binary_search_terminates_when_float_rounding_repeats_upper_bound() -> None:
    calls: list[float] = []

    def trial(_frame: int, rate: float, _duration: float) -> TrialObservation:
        calls.append(rate)
        if len(calls) > 20:
            pytest.fail(f"search did not converge: {calls[-6:]}")
        return observation(loss=1 if rate >= 78.8 else 0)

    result = search_frame(64, 100, SearchSettings(0.1, 0, 0, 0), trial)

    assert result.valid is True
    assert result.throughput_percent_l1 == 78.7


def test_confirmation_loss_steps_down_to_stable_zero_loss_rate() -> None:
    def trial(_frame: int, rate: float, duration: float) -> TrialObservation:
        # A 10-second search accepts 4%, but a 60-second confirmation requires 3%.
        loss = int(rate > (4 if duration == 10 else 3))
        return observation(loss=loss)

    result = search_frame(64, 10, SearchSettings(1, 10, 60, 2), trial)

    assert result.valid is True
    assert result.throughput_percent_l1 == 3
    assert [item["ratePercentL1"] for item in result.trials[-3:]] == [4, 3, 3]


def test_search_samples_continue_when_one_sample_has_zero_loss() -> None:
    attempts: dict[float, int] = {}

    def trial(_frame: int, rate: float, _duration: float) -> TrialObservation:
        attempts[rate] = attempts.get(rate, 0) + 1
        if rate == 10:
            return observation(loss=1)
        if rate == 5:
            return observation(loss=1 if attempts[rate] < 3 else 0)
        return observation()

    result = search_frame(64, 10, SearchSettings(5, 1, 1, 1, search_samples=3), trial)

    assert result.valid is True
    assert result.throughput_percent_l1 == 5
    assert attempts[5] == 4  # three search samples and one confirmation


def test_frame_loss_descends_until_two_successive_zero_loss_trials() -> None:
    def trial(_frame: int, rate: float, _duration: float) -> TrialObservation:
        return observation(loss=1 if rate >= 90 else 0)

    result = measure_frame_loss(64, 100, FrameLossSettings(10, 60), trial)

    assert result.valid is True
    assert result.stopped_after_consecutive_zero_loss is True
    assert [point["ratePercentL1"] for point in result.trials] == [100, 90, 80, 70]
    assert [point["lossPercent"] for point in result.trials] == [1.0, 1.0, 0.0, 0.0]


def test_frame_loss_retries_invalid_observation() -> None:
    attempts = 0

    def trial(_frame: int, _rate: float, _duration: float) -> TrialObservation:
        nonlocal attempts
        attempts += 1
        return observation(valid=attempts != 1)

    result = measure_frame_loss(64, 10, FrameLossSettings(1, 3), trial)

    assert result.valid is True
    assert [point["phase"] for point in result.trials[:3]] == [
        "frame-loss",
        "frame-loss-retry",
        "frame-loss",
    ]


def test_latency_preserves_twenty_tagged_samples_and_uses_arithmetic_mean() -> None:
    calls: list[tuple[int, float, float, float]] = []

    def trial(
        frame_size: int,
        rate_percent: float,
        duration_seconds: float,
        tag_after_seconds: float,
    ) -> LatencyObservation:
        calls.append((frame_size, rate_percent, duration_seconds, tag_after_seconds))
        return LatencyObservation(True, float(len(calls)), {"clock": "calibrated"})

    result = measure_latency(
        128,
        69.3,
        LatencySettings(),
        trial,
        definition="store-and-forward",
    )

    assert result.valid is True
    assert result.definition == "store-and-forward"
    assert result.samples_microseconds == [float(value) for value in range(1, 21)]
    assert result.average_microseconds == 10.5
    assert calls == [(128, 69.3, 120, 60)] * 20


def test_back_to_back_repeats_binary_search_and_reports_rfc9004_statistics() -> None:
    def trial(_frame_size: int, burst_frames: int) -> BackToBackObservation:
        received = min(burst_frames, 8)
        return BackToBackObservation(
            valid=True,
            tx_frames=burst_frames,
            rx_frames=received,
            details={"counterSource": "flow-stats"},
        )

    result = measure_back_to_back(
        64,
        theoretical_fps=1000,
        throughput_fps=750,
        settings=BackToBackSettings(
            repetitions=3,
            minimum_step_frames=1,
            maximum_burst_frames=16,
        ),
        trial=trial,
    )

    assert result.valid is True
    assert result.longest_zero_loss_bursts == [8, 8, 8]
    assert result.average_frames == 8
    assert result.minimum_frames == 8
    assert result.maximum_frames == 8
    assert result.standard_deviation_frames == 0
    assert result.implied_buffer_seconds == 0.008
    assert result.corrected_buffer_seconds == 0.002
    assert len(result.searches) == 3
    assert all(search["verification"]["lossFrames"] == 0 for search in result.searches)


def test_back_to_back_keeps_repetitions_independent_after_an_invalid_probe() -> None:
    calls = 0

    def trial(_frame_size: int, burst_frames: int) -> BackToBackObservation:
        nonlocal calls
        calls += 1
        if calls == 1:
            return BackToBackObservation(False, burst_frames, 0, {"reason": "counter-gap"})
        return BackToBackObservation(True, burst_frames, min(burst_frames, 4), {})

    result = measure_back_to_back(
        64,
        theoretical_fps=1000,
        throughput_fps=750,
        settings=BackToBackSettings(repetitions=2, maximum_burst_frames=8),
        trial=trial,
    )

    assert result.valid is False
    assert [search["valid"] for search in result.searches] == [False, True]
    assert result.longest_zero_loss_bursts == [4]

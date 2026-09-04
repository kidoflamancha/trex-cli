from __future__ import annotations

import json
import logging
import math
import threading
import time
from collections import defaultdict
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from typing import Any

from trex_cli import __version__

_REQUEST_ID: ContextVar[str | None] = ContextVar("request_id", default=None)
_STANDARD_LOG_FIELDS = frozenset(logging.makeLogRecord({}).__dict__) | {
    "message",
    "asctime",
}
_HISTOGRAM_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
_HTTP_METHODS = frozenset({"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"})


def bind_request_id(request_id: str) -> Token[str | None]:
    return _REQUEST_ID.set(request_id)


def reset_request_id(token: Token[str | None]) -> None:
    _REQUEST_ID.reset(token)


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        request_id = _REQUEST_ID.get()
        if request_id is not None:
            payload["requestId"] = request_id
        for name, value in record.__dict__.items():
            if name not in _STANDARD_LOG_FIELDS and not name.startswith("_"):
                if name == "requestId" and request_id is not None:
                    continue
                payload[name] = _json_value(value)
        if record.exc_info is not None:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


class RuntimeMetrics:
    def __init__(self, *, engine: str, simulated: bool) -> None:
        self._engine = engine
        self._simulated = simulated
        self._started_at = time.time()
        self._lock = threading.Lock()
        self._http_requests: defaultdict[tuple[str, str, str], int] = defaultdict(int)
        self._http_duration_buckets: defaultdict[tuple[str, str], list[int]] = defaultdict(
            lambda: [0] * len(_HISTOGRAM_BUCKETS)
        )
        self._http_duration_counts: defaultdict[tuple[str, str], int] = defaultdict(int)
        self._http_duration_sums: defaultdict[tuple[str, str], float] = defaultdict(float)
        self._job_transitions: defaultdict[tuple[str, str, str, str], int] = defaultdict(int)
        self._cleanup_runs: defaultdict[str, int] = defaultdict(int)
        self._cleanup_deleted_records = 0
        self._cleanup_reclaimed_bytes = 0
        self._engine_available: bool | None = None

    def observe_http(self, method: str, route: str, status_code: int, duration: float) -> None:
        method = method if method in _HTTP_METHODS else "OTHER"
        status_class = f"{status_code // 100}xx"
        with self._lock:
            self._http_requests[(method, route, status_class)] += 1
            key = (method, route)
            for index, bucket in enumerate(_HISTOGRAM_BUCKETS):
                if duration <= bucket:
                    self._http_duration_buckets[key][index] += 1
            self._http_duration_counts[key] += 1
            self._http_duration_sums[key] += duration

    def observe_job_transition(
        self, *, kind: str, previous: str, current: str, event: str
    ) -> None:
        with self._lock:
            self._job_transitions[(kind, previous, current, event)] += 1

    def observe_cleanup(
        self, *, dry_run: bool, failed: bool, deleted_records: int, reclaimed_bytes: int
    ) -> None:
        outcome = "failed" if failed else "success"
        mode = "dry-run" if dry_run else "apply"
        with self._lock:
            self._cleanup_runs[f"{mode}:{outcome}"] += 1
            self._cleanup_deleted_records += deleted_records
            self._cleanup_reclaimed_bytes += reclaimed_bytes

    def set_engine_available(self, available: bool) -> None:
        with self._lock:
            self._engine_available = available

    def render(
        self,
        *,
        job_states: dict[str, int],
        port_states: dict[str, int],
        artifact_count: int,
        artifact_bytes: int,
    ) -> str:
        with self._lock:
            http_requests = dict(self._http_requests)
            http_duration_buckets = {
                key: tuple(values) for key, values in self._http_duration_buckets.items()
            }
            http_duration_counts = dict(self._http_duration_counts)
            http_duration_sums = dict(self._http_duration_sums)
            job_transitions = dict(self._job_transitions)
            cleanup_runs = dict(self._cleanup_runs)
            deleted_records = self._cleanup_deleted_records
            reclaimed_bytes = self._cleanup_reclaimed_bytes
            engine_available = self._engine_available
        lines = [
            "# HELP trex_agent_info Static Agent build and engine information.",
            "# TYPE trex_agent_info gauge",
            _sample(
                "trex_agent_info",
                1,
                version=__version__,
                engine=self._engine,
                simulated=str(self._simulated).lower(),
            ),
            "# HELP trex_agent_process_start_time_seconds Process start time since Unix epoch.",
            "# TYPE trex_agent_process_start_time_seconds gauge",
            _sample("trex_agent_process_start_time_seconds", self._started_at),
        ]
        if engine_available is not None:
            lines.extend(
                [
                    "# HELP trex_agent_engine_available Whether the last engine probe succeeded.",
                    "# TYPE trex_agent_engine_available gauge",
                    _sample("trex_agent_engine_available", int(engine_available)),
                ]
            )
        lines.extend(_gauges("trex_agent_jobs", "Current Jobs by state.", "state", job_states))
        lines.extend(
            _gauges("trex_agent_logical_ports", "Logical ports by status.", "status", port_states)
        )
        lines.extend(
            [
                "# HELP trex_agent_artifacts Registered content-addressed Artifacts.",
                "# TYPE trex_agent_artifacts gauge",
                _sample("trex_agent_artifacts", artifact_count),
                "# HELP trex_agent_artifact_bytes Registered Artifact bytes.",
                "# TYPE trex_agent_artifact_bytes gauge",
                _sample("trex_agent_artifact_bytes", artifact_bytes),
                "# HELP trex_agent_http_requests_total HTTP requests by route and status class.",
                "# TYPE trex_agent_http_requests_total counter",
            ]
        )
        for (method, route, status_class), value in sorted(http_requests.items()):
            lines.append(
                _sample(
                    "trex_agent_http_requests_total",
                    value,
                    method=method,
                    route=route,
                    status_class=status_class,
                )
            )
        lines.extend(
            [
                "# HELP trex_agent_http_request_duration_seconds HTTP request duration.",
                "# TYPE trex_agent_http_request_duration_seconds histogram",
            ]
        )
        for (method, route), counts in sorted(http_duration_buckets.items()):
            for bucket, count in zip(_HISTOGRAM_BUCKETS, counts, strict=True):
                lines.append(
                    _sample(
                        "trex_agent_http_request_duration_seconds_bucket",
                        count,
                        method=method,
                        route=route,
                        le=str(bucket),
                    )
                )
            lines.append(
                _sample(
                    "trex_agent_http_request_duration_seconds_bucket",
                    http_duration_counts[(method, route)],
                    method=method,
                    route=route,
                    le="+Inf",
                )
            )
            lines.append(
                _sample(
                    "trex_agent_http_request_duration_seconds_count",
                    http_duration_counts[(method, route)],
                    method=method,
                    route=route,
                )
            )
            lines.append(
                _sample(
                    "trex_agent_http_request_duration_seconds_sum",
                    http_duration_sums[(method, route)],
                    method=method,
                    route=route,
                )
            )
        lines.extend(
            [
                "# HELP trex_agent_job_transitions_total Job state transitions.",
                "# TYPE trex_agent_job_transitions_total counter",
            ]
        )
        for (kind, previous, current, event), value in sorted(job_transitions.items()):
            lines.append(
                _sample(
                    "trex_agent_job_transitions_total",
                    value,
                    kind=kind,
                    previous=previous,
                    current=current,
                    event=event,
                )
            )
        lines.extend(
            [
                "# HELP trex_agent_artifact_cleanup_runs_total Artifact cleanup runs.",
                "# TYPE trex_agent_artifact_cleanup_runs_total counter",
            ]
        )
        for key, value in sorted(cleanup_runs.items()):
            mode, outcome = key.split(":", 1)
            lines.append(
                _sample(
                    "trex_agent_artifact_cleanup_runs_total", value, mode=mode, outcome=outcome
                )
            )
        lines.extend(
            [
                "# HELP trex_agent_artifact_cleanup_deleted_records_total Deleted records.",
                "# TYPE trex_agent_artifact_cleanup_deleted_records_total counter",
                _sample("trex_agent_artifact_cleanup_deleted_records_total", deleted_records),
                "# HELP trex_agent_artifact_cleanup_reclaimed_bytes_total Reclaimed bytes.",
                "# TYPE trex_agent_artifact_cleanup_reclaimed_bytes_total counter",
                _sample("trex_agent_artifact_cleanup_reclaimed_bytes_total", reclaimed_bytes),
            ]
        )
        return "\n".join(lines) + "\n"


def _gauges(name: str, help_text: str, label: str, values: dict[str, int]) -> list[str]:
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} gauge"]
    for key, value in sorted(values.items()):
        lines.append(_sample(name, value, **{label: key}))
    return lines


def _sample(name: str, value: int | float, **labels: str) -> str:
    encoded_labels = ",".join(
        f'{key}="{_escape_label(label)}"' for key, label in sorted(labels.items())
    )
    suffix = f"{{{encoded_labels}}}" if encoded_labels else ""
    rendered = str(value) if isinstance(value, int) else format(value, ".15g")
    return f"{name}{suffix} {rendered}"


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return str(value)

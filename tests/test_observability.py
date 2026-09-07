from __future__ import annotations

import json
import logging

from trex_cli.observability import (
    JsonLogFormatter,
    RuntimeMetrics,
    bind_request_id,
    reset_request_id,
)


def test_json_log_formatter_adds_context_and_structured_fields() -> None:
    record = logging.LogRecord(
        name="trex_cli.jobs",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="job_state_transition",
        args=(),
        exc_info=None,
    )
    record.jobId = "job_123"
    record.requestId = "spoofed-by-record"
    record.previousState = "RUNNING"
    record.state = "SUCCEEDED"
    token = bind_request_id("request-123")
    try:
        payload = json.loads(JsonLogFormatter().format(record))
    finally:
        reset_request_id(token)

    assert payload["event"] == "job_state_transition"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "trex_cli.jobs"
    assert payload["requestId"] == "request-123"
    assert payload["jobId"] == "job_123"
    assert payload["previousState"] == "RUNNING"
    assert payload["state"] == "SUCCEEDED"
    assert payload["timestamp"].endswith("+00:00")


def test_runtime_metrics_render_bounded_counters_histograms_and_gauges() -> None:
    metrics = RuntimeMetrics(engine="simulated", simulated=True)
    metrics.set_engine_available(True)
    metrics.observe_http("GET", "/v1/jobs/{job_id}", 200, 0.01)
    metrics.observe_http("UNBOUNDED-METHOD", "unmatched", 404, 0.001)
    metrics.observe_job_transition(
        kind="StatelessTraffic",
        previous="RUNNING",
        current="SUCCEEDED",
        event="JOB_SUCCEEDED",
    )
    metrics.observe_cleanup(
        dry_run=False,
        failed=False,
        deleted_records=2,
        reclaimed_bytes=512,
    )

    rendered = metrics.render(
        job_states={"SUCCEEDED": 3},
        port_states={"AVAILABLE": 2},
        artifact_count=9,
        artifact_bytes=4096,
    )

    assert 'trex_agent_info{engine="simulated",simulated="true",version="1.0.1"} 1' in rendered
    assert 'trex_agent_jobs{state="SUCCEEDED"} 3' in rendered
    assert 'trex_agent_logical_ports{status="AVAILABLE"} 2' in rendered
    assert "trex_agent_artifacts 9" in rendered
    assert "trex_agent_artifact_bytes 4096" in rendered
    assert (
        'trex_agent_http_requests_total{method="GET",route="/v1/jobs/{job_id}",'
        'status_class="2xx"} 1'
    ) in rendered
    assert (
        'trex_agent_http_requests_total{method="OTHER",route="unmatched",'
        'status_class="4xx"} 1'
    ) in rendered
    assert (
        'trex_agent_http_request_duration_seconds_bucket{le="0.01",method="GET",'
        'route="/v1/jobs/{job_id}"} 1'
    ) in rendered
    assert (
        'trex_agent_job_transitions_total{current="SUCCEEDED",event="JOB_SUCCEEDED",'
        'kind="StatelessTraffic",previous="RUNNING"} 1'
    ) in rendered
    assert (
        'trex_agent_artifact_cleanup_runs_total{mode="apply",outcome="success"} 1'
    ) in rendered
    assert "trex_agent_artifact_cleanup_deleted_records_total 2" in rendered
    assert "trex_agent_artifact_cleanup_reclaimed_bytes_total 512" in rendered

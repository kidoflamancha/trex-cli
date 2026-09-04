from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal, Never, cast

import httpx
import typer
from pydantic import ValidationError

from trex_cli.models import (
    JOB_DOCUMENT_ADAPTER,
    ArpStormSpec,
    DhcpStormSpec,
    DnsStormSpec,
    JobSnapshot,
    JobState,
    Verdict,
)
from trex_cli.profiles import ProfileError, Profiles, TestPlan
from trex_cli.test_control import PlannedTest
from trex_cli.test_plan import (
    ArpStormPlan,
    DhcpStormPlan,
    DnsStormPlan,
    IntentPlan,
    PcapReplayPlan,
    Rfc2544IntentPlan,
    StatefulReplayPlan,
    TestPlanError,
    TestPlanModule,
    UdpWorkloadPlan,
)
from trex_cli.yaml_loader import load_yaml

app = typer.Typer(add_completion=False, help="Submit and observe trex-cli Jobs.")
job_app = typer.Typer(add_completion=False, help="Manage Jobs.")
artifact_app = typer.Typer(add_completion=False, help="Download Artifacts.")
auth_app = typer.Typer(add_completion=False, help="Manage Agent authentication credentials.")
profile_app = typer.Typer(add_completion=False, help="Inspect versioned test profiles.")
plan_app = typer.Typer(add_completion=False, help="Resolve and run immutable test plans.")
traffic_app = typer.Typer(add_completion=False, help="Plan and run L2/L3 traffic intent.")
storm_app = typer.Typer(add_completion=False, help="Plan and run bounded protocol storms.")
dns_storm_app = typer.Typer(add_completion=False, help="Plan and run DNS query storms.")
dhcp_storm_app = typer.Typer(add_completion=False, help="Plan and run DHCP Discover storms.")
arp_storm_app = typer.Typer(add_completion=False, help="Plan and run ARP Request storms.")
benchmark_app = typer.Typer(add_completion=False, help="Plan and run benchmark methods.")
rfc2544_app = typer.Typer(add_completion=False, help="Plan and run RFC2544 suites.")
pcap_app = typer.Typer(add_completion=False, help="Publish and inspect immutable PCAP resources.")
app.add_typer(job_app, name="job")
app.add_typer(artifact_app, name="artifact")
app.add_typer(auth_app, name="auth")
app.add_typer(profile_app, name="profile")
app.add_typer(plan_app, name="plan")
app.add_typer(traffic_app, name="traffic")
traffic_app.add_typer(storm_app, name="storm")
storm_app.add_typer(dns_storm_app, name="dns")
storm_app.add_typer(dhcp_storm_app, name="dhcp")
storm_app.add_typer(arp_storm_app, name="arp")
app.add_typer(benchmark_app, name="benchmark")
app.add_typer(pcap_app, name="pcap")
benchmark_app.add_typer(rfc2544_app, name="rfc2544")


class ClientContext:
    def __init__(self, agent_url: str, token: str | None) -> None:
        self.agent_url = agent_url.rstrip("/")
        self.token = token

    @property
    def headers(self) -> dict[str, str]:
        if not self.token:
            raise typer.BadParameter("--token or TREX_AGENT_TOKEN is required for Agent commands")
        return {"Authorization": f"Bearer {self.token}"}


@app.callback()
def root(
    ctx: typer.Context,
    agent_url: str = typer.Option("http://127.0.0.1:8080", "--agent-url", envvar="TREX_AGENT_URL"),
    token: str | None = typer.Option(None, "--token", envvar="TREX_AGENT_TOKEN", hide_input=True),
) -> None:
    ctx.obj = ClientContext(agent_url, token)


@app.command()
def run(
    ctx: typer.Context,
    source: str = typer.Argument(..., help="Raw Job YAML path or plan id"),
    plans_dir: Path = typer.Option(Path(".trex-plans"), "--plans-dir"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    client_context = _context(ctx)
    idempotency_key = uuid.uuid4().hex
    source_path = Path(source)
    if source_path.is_file():
        snapshot = _submit(client_context, source_path, idempotency_key, None)
    else:
        try:
            plan = _load_any_plan(source, plans_dir)
        except (ProfileError, TestPlanError) as error:
            _profile_error(error)
        snapshot = _submit_document(client_context, plan.document, idempotency_key, None)
    try:
        terminal = _wait(client_context, snapshot.job_id, snapshot.revision)
    except KeyboardInterrupt:
        _cancel(client_context, snapshot.job_id, "cli-interrupt")
        terminal = _wait(client_context, snapshot.job_id, snapshot.revision)
    _print_snapshot(terminal, output)
    raise typer.Exit(_exit_code(terminal))


@job_app.command("submit")
def submit(
    ctx: typer.Context,
    document: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    idempotency_key: str | None = typer.Option(None, "--idempotency-key"),
    retry_of: str | None = typer.Option(None, "--retry-of"),
    output: str = typer.Option("human", "--output", help="human, json, or id"),
) -> None:
    snapshot = _submit(_context(ctx), document, idempotency_key or uuid.uuid4().hex, retry_of)
    if output == "id":
        typer.echo(snapshot.job_id)
    else:
        _print_snapshot(snapshot, output)


@job_app.command("watch")
def watch(ctx: typer.Context, job_id: str) -> None:
    client_context = _context(ctx)
    current = _get(client_context, job_id)
    typer.echo(f"{current.revision}\t{current.state}")
    if current.state.terminal:
        return
    for snapshot in _events(client_context, job_id, current.revision):
        typer.echo(f"{snapshot.revision}\t{snapshot.state}")


@job_app.command("result")
def result(
    ctx: typer.Context,
    job_id: str,
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    client_context = _context(ctx)
    current = _get(client_context, job_id)
    terminal = (
        current if current.state.terminal else _wait(client_context, job_id, current.revision)
    )
    _print_snapshot(terminal, output)
    raise typer.Exit(_exit_code(terminal))


@job_app.command("cancel")
def cancel(
    ctx: typer.Context,
    job_id: str,
    reason: str = typer.Option(..., "--reason"),
) -> None:
    snapshot = _cancel(_context(ctx), job_id, reason)
    _print_snapshot(snapshot, "human")


@artifact_app.command("get")
def artifact_get(
    ctx: typer.Context,
    digest: str,
    output: Path = typer.Option(..., "--output", dir_okay=False),
) -> None:
    client_context = _context(ctx)
    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"{client_context.agent_url}/v1/artifacts/{digest}",
                headers=client_context.headers,
            )
            _raise_for_problem(response)
            output.write_bytes(response.content)
    except httpx.HTTPError as error:
        _connection_error(error)
    typer.echo(str(output))


@artifact_app.command("cleanup")
def artifact_cleanup(
    ctx: typer.Context,
    apply: bool = typer.Option(
        False, "--apply", help="Delete eligible files; the default is a dry run"
    ),
    delete_orphans: bool = typer.Option(
        False, "--delete-orphans", help="Also delete old unregistered content-addressed files"
    ),
    yes: bool = typer.Option(False, "--yes", help="Skip confirmation when applying cleanup"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    if output not in {"human", "json"}:
        raise typer.BadParameter("--output must be human or json")
    if apply and not yes and not typer.confirm("Delete the eligible Artifact files?"):
        raise typer.Abort()
    context = _context(ctx)
    try:
        with httpx.Client(timeout=None) as client:
            response = client.post(
                f"{context.agent_url}/v1/maintenance/artifacts:cleanup",
                headers=context.headers,
                json={"dryRun": not apply, "deleteOrphans": delete_orphans},
            )
    except httpx.HTTPError as error:
        _connection_error(error)
    _raise_for_problem(response)
    report = cast(dict[str, Any], response.json())
    if output == "json":
        typer.echo(json.dumps(report, indent=2))
    else:
        typer.echo(f"Mode: {'dry-run' if report['dryRun'] else 'apply'}")
        typer.echo(f"Expired records: {report['expiredRecords']}")
        typer.echo(f"Deleted records: {report['deletedRecords']}")
        typer.echo(f"Missing files: {report['missingFiles']}")
        typer.echo(f"Orphan files: {report['orphanFiles']}")
        typer.echo(f"Deleted orphans: {report['deletedOrphans']}")
        typer.echo(f"Reclaimed bytes: {report['reclaimedBytes']}")
        for failure in report["failures"]:
            typer.echo(f"Failure: {failure}", err=True)
    if report["failures"]:
        raise typer.Exit(3)


@auth_app.command("reload")
def auth_reload(
    ctx: typer.Context,
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    if output not in {"human", "json"}:
        raise typer.BadParameter("--output must be human or json")
    context = _context(ctx)
    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(
                f"{context.agent_url}/v1/maintenance/auth:reload",
                headers=context.headers,
            )
    except httpx.HTTPError as error:
        _connection_error(error)
    _raise_for_problem(response)
    result = cast(dict[str, Any], response.json())
    if output == "json":
        typer.echo(json.dumps(result, indent=2))
        return
    typer.echo(f"Status: {result['status']}")
    for credential in result["credentials"]:
        typer.echo(f"{credential['name']}\t{credential['role']}")


@pcap_app.command("publish")
def pcap_publish(
    ctx: typer.Context,
    source: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    name: str = typer.Option(..., "--name", help="Immutable catalog resource name"),
    description: str | None = typer.Option(None, "--description"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    context = _context(ctx)
    params = {"name": name, **({"description": description} if description else {})}
    try:
        with source.open("rb") as capture:
            with httpx.Client(timeout=None) as client:
                response = client.post(
                    f"{context.agent_url}/v1/catalog/captures",
                    headers={
                        **context.headers,
                        "Content-Type": "application/vnd.tcpdump.pcap",
                    },
                    params=params,
                    content=capture,
                )
    except httpx.HTTPError as error:
        _connection_error(error)
    _raise_for_problem(response)
    _print_capture_resource(response.json(), output)


@pcap_app.command("list")
def pcap_list(
    ctx: typer.Context,
    query: str = typer.Option("", "--query"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    result = _catalog_get(
        _context(ctx), "/v1/catalog", params={"kind": "CaptureResource", "query": query}
    )
    if output == "json":
        typer.echo(json.dumps(result, indent=2))
        return
    if output != "human":
        raise typer.BadParameter("--output must be human or json")
    for item in result["items"]:
        typer.echo(f"{item['ref']}\t{item['digest']}")


@pcap_app.command("show")
def pcap_show(
    ctx: typer.Context,
    ref: str,
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    result = _catalog_get(_context(ctx), f"/v1/catalog/CaptureResource/{ref}")
    _print_capture_resource(result, output)


@pcap_app.command("plan")
def pcap_plan(
    ctx: typer.Context,
    capture: str = typer.Option(..., "--capture"),
    path: str = typer.Option(..., "--path"),
    source_role: str = typer.Option(..., "--from"),
    destination_role: str = typer.Option(..., "--to"),
    address_mode: str = typer.Option("rewrite", "--address-mode"),
    timing_mode: str = typer.Option("capture", "--timing"),
    multiplier: float = typer.Option(1, "--multiplier", min=0.001, max=1_000),
    timestamp_policy: str = typer.Option("reject", "--timestamp-policy"),
    rate: str | None = typer.Option(None, "--rate"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    planned = _control_plan(
        _context(ctx),
        _pcap_replay_intent(
            capture=capture,
            path=path,
            source_role=source_role,
            destination_role=destination_role,
            address_mode=address_mode,
            timing_mode=timing_mode,
            multiplier=multiplier,
            timestamp_policy=timestamp_policy,
            rate=rate,
        ),
    )
    _print_control_plan(planned, output)


@pcap_app.command("run")
def pcap_run(
    ctx: typer.Context,
    capture: str = typer.Option(..., "--capture"),
    path: str = typer.Option(..., "--path"),
    source_role: str = typer.Option(..., "--from"),
    destination_role: str = typer.Option(..., "--to"),
    address_mode: str = typer.Option("rewrite", "--address-mode"),
    timing_mode: str = typer.Option("capture", "--timing"),
    multiplier: float = typer.Option(1, "--multiplier", min=0.001, max=1_000),
    timestamp_policy: str = typer.Option("reject", "--timestamp-policy"),
    rate: str | None = typer.Option(None, "--rate"),
    yes: bool = typer.Option(False, "--yes"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    context = _context(ctx)
    planned = _control_plan(
        context,
        _pcap_replay_intent(
            capture=capture,
            path=path,
            source_role=source_role,
            destination_role=destination_role,
            address_mode=address_mode,
            timing_mode=timing_mode,
            multiplier=multiplier,
            timestamp_policy=timestamp_policy,
            rate=rate,
        ),
    )
    if output == "human" or not yes:
        _print_control_plan(planned, "human")
    if not yes and not typer.confirm("Start this immutable replay plan?"):
        raise typer.Abort()
    started = _control_start(context, planned.plan_id)
    try:
        terminal = _control_wait(context, started.job_id, started.revision)
    except KeyboardInterrupt:
        _control_cancel(context, started.job_id, "cli-interrupt")
        terminal = _control_wait(context, started.job_id, started.revision)
    _print_snapshot(terminal, output)
    raise typer.Exit(_exit_code(terminal))


@pcap_app.command("stateful-plan")
def pcap_stateful_plan(
    ctx: typer.Context,
    capture: str = typer.Option(..., "--capture"),
    session_id: str = typer.Option(..., "--session"),
    path: str = typer.Option(..., "--path"),
    client_role: str = typer.Option(..., "--client"),
    server_role: str = typer.Option(..., "--server"),
    cps: float = typer.Option(..., "--cps", min=0.001),
    max_active_connections: int = typer.Option(..., "--max-active", min=1),
    duration: str = typer.Option(..., "--duration"),
    client_ipv4_start: str | None = typer.Option(None, "--client-ip-start"),
    client_ipv4_end: str | None = typer.Option(None, "--client-ip-end"),
    server_ipv4_start: str | None = typer.Option(None, "--server-ip-start"),
    server_ipv4_end: str | None = typer.Option(None, "--server-ip-end"),
    client_port_start: int = typer.Option(1024, "--client-port-start", min=1024, max=65_535),
    client_port_end: int = typer.Option(65_535, "--client-port-end", min=1024, max=65_535),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    planned = _control_plan(
        _context(ctx),
        _stateful_replay_intent(
            capture=capture,
            session_id=session_id,
            path=path,
            client_role=client_role,
            server_role=server_role,
            cps=cps,
            max_active_connections=max_active_connections,
            duration=duration,
            client_ipv4_start=client_ipv4_start,
            client_ipv4_end=client_ipv4_end,
            server_ipv4_start=server_ipv4_start,
            server_ipv4_end=server_ipv4_end,
            client_port_start=client_port_start,
            client_port_end=client_port_end,
        ),
    )
    _print_control_plan(planned, output)


@pcap_app.command("stateful-run")
def pcap_stateful_run(
    ctx: typer.Context,
    capture: str = typer.Option(..., "--capture"),
    session_id: str = typer.Option(..., "--session"),
    path: str = typer.Option(..., "--path"),
    client_role: str = typer.Option(..., "--client"),
    server_role: str = typer.Option(..., "--server"),
    cps: float = typer.Option(..., "--cps", min=0.001),
    max_active_connections: int = typer.Option(..., "--max-active", min=1),
    duration: str = typer.Option(..., "--duration"),
    client_ipv4_start: str | None = typer.Option(None, "--client-ip-start"),
    client_ipv4_end: str | None = typer.Option(None, "--client-ip-end"),
    server_ipv4_start: str | None = typer.Option(None, "--server-ip-start"),
    server_ipv4_end: str | None = typer.Option(None, "--server-ip-end"),
    client_port_start: int = typer.Option(1024, "--client-port-start", min=1024, max=65_535),
    client_port_end: int = typer.Option(65_535, "--client-port-end", min=1024, max=65_535),
    yes: bool = typer.Option(False, "--yes"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    context = _context(ctx)
    planned = _control_plan(
        context,
        _stateful_replay_intent(
            capture=capture,
            session_id=session_id,
            path=path,
            client_role=client_role,
            server_role=server_role,
            cps=cps,
            max_active_connections=max_active_connections,
            duration=duration,
            client_ipv4_start=client_ipv4_start,
            client_ipv4_end=client_ipv4_end,
            server_ipv4_start=server_ipv4_start,
            server_ipv4_end=server_ipv4_end,
            client_port_start=client_port_start,
            client_port_end=client_port_end,
        ),
    )
    if output == "human" or not yes:
        _print_control_plan(planned, "human")
    if not yes and not typer.confirm("Start this immutable stateful replay plan?"):
        raise typer.Abort()
    started = _control_start(context, planned.plan_id)
    try:
        terminal = _control_wait(context, started.job_id, started.revision)
    except KeyboardInterrupt:
        _control_cancel(context, started.job_id, "cli-interrupt")
        terminal = _control_wait(context, started.job_id, started.revision)
    _print_snapshot(terminal, output)
    raise typer.Exit(_exit_code(terminal))


@pcap_app.command("workload-plan")
def pcap_workload_plan(
    ctx: typer.Context,
    capture: str = typer.Option(..., "--capture"),
    path: str = typer.Option(..., "--path"),
    client_role: str = typer.Option(..., "--client"),
    server_role: str = typer.Option(..., "--server"),
    cps: float = typer.Option(..., "--cps", min=0.001),
    max_active_connections: int = typer.Option(..., "--max-active", min=1),
    duration: str = typer.Option(..., "--duration"),
    client_ipv4_start: str | None = typer.Option(None, "--client-ip-start"),
    client_ipv4_end: str | None = typer.Option(None, "--client-ip-end"),
    server_ipv4_start: str | None = typer.Option(None, "--server-ip-start"),
    server_ipv4_end: str | None = typer.Option(None, "--server-ip-end"),
    client_port_start: int = typer.Option(1024, "--client-port-start", min=1024, max=65_535),
    client_port_end: int = typer.Option(65_535, "--client-port-end", min=1024, max=65_535),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    planned = _control_plan(
        _context(ctx),
        _capture_workload_intent(
            capture=capture,
            path=path,
            client_role=client_role,
            server_role=server_role,
            cps=cps,
            max_active_connections=max_active_connections,
            duration=duration,
            client_ipv4_start=client_ipv4_start,
            client_ipv4_end=client_ipv4_end,
            server_ipv4_start=server_ipv4_start,
            server_ipv4_end=server_ipv4_end,
            client_port_start=client_port_start,
            client_port_end=client_port_end,
        ),
    )
    _print_control_plan(planned, output)


@pcap_app.command("workload-run")
def pcap_workload_run(
    ctx: typer.Context,
    capture: str = typer.Option(..., "--capture"),
    path: str = typer.Option(..., "--path"),
    client_role: str = typer.Option(..., "--client"),
    server_role: str = typer.Option(..., "--server"),
    cps: float = typer.Option(..., "--cps", min=0.001),
    max_active_connections: int = typer.Option(..., "--max-active", min=1),
    duration: str = typer.Option(..., "--duration"),
    client_ipv4_start: str | None = typer.Option(None, "--client-ip-start"),
    client_ipv4_end: str | None = typer.Option(None, "--client-ip-end"),
    server_ipv4_start: str | None = typer.Option(None, "--server-ip-start"),
    server_ipv4_end: str | None = typer.Option(None, "--server-ip-end"),
    client_port_start: int = typer.Option(1024, "--client-port-start", min=1024, max=65_535),
    client_port_end: int = typer.Option(65_535, "--client-port-end", min=1024, max=65_535),
    yes: bool = typer.Option(False, "--yes"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    context = _context(ctx)
    planned = _control_plan(
        context,
        _capture_workload_intent(
            capture=capture,
            path=path,
            client_role=client_role,
            server_role=server_role,
            cps=cps,
            max_active_connections=max_active_connections,
            duration=duration,
            client_ipv4_start=client_ipv4_start,
            client_ipv4_end=client_ipv4_end,
            server_ipv4_start=server_ipv4_start,
            server_ipv4_end=server_ipv4_end,
            client_port_start=client_port_start,
            client_port_end=client_port_end,
        ),
    )
    if output == "human" or not yes:
        _print_control_plan(planned, "human")
    if not yes and not typer.confirm("Start this immutable capture workload plan?"):
        raise typer.Abort()
    started = _control_start(context, planned.plan_id)
    try:
        terminal = _control_wait(context, started.job_id, started.revision)
    except KeyboardInterrupt:
        _control_cancel(context, started.job_id, "cli-interrupt")
        terminal = _control_wait(context, started.job_id, started.revision)
    _print_snapshot(terminal, output)
    raise typer.Exit(_exit_code(terminal))


@pcap_app.command("udp-workload-plan")
def pcap_udp_workload_plan(
    ctx: typer.Context,
    capture: str = typer.Option(..., "--capture"),
    path: str = typer.Option(..., "--path"),
    initiator_role: str = typer.Option(..., "--initiator"),
    responder_role: str = typer.Option(..., "--responder"),
    fps: float = typer.Option(..., "--fps", min=0.001),
    duration: str = typer.Option(..., "--duration"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    planned = _control_plan(
        _context(ctx),
        _udp_workload_intent(
            capture=capture,
            path=path,
            initiator_role=initiator_role,
            responder_role=responder_role,
            fps=fps,
            duration=duration,
        ),
    )
    _print_control_plan(planned, output)


@pcap_app.command("udp-workload-run")
def pcap_udp_workload_run(
    ctx: typer.Context,
    capture: str = typer.Option(..., "--capture"),
    path: str = typer.Option(..., "--path"),
    initiator_role: str = typer.Option(..., "--initiator"),
    responder_role: str = typer.Option(..., "--responder"),
    fps: float = typer.Option(..., "--fps", min=0.001),
    duration: str = typer.Option(..., "--duration"),
    yes: bool = typer.Option(False, "--yes"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    context = _context(ctx)
    planned = _control_plan(
        context,
        _udp_workload_intent(
            capture=capture,
            path=path,
            initiator_role=initiator_role,
            responder_role=responder_role,
            fps=fps,
            duration=duration,
        ),
    )
    if output == "human" or not yes:
        _print_control_plan(planned, "human")
    if not yes and not typer.confirm("Start this immutable UDP workload plan?"):
        raise typer.Abort()
    started = _control_start(context, planned.plan_id)
    try:
        terminal = _control_wait(context, started.job_id, started.revision)
    except KeyboardInterrupt:
        _control_cancel(context, started.job_id, "cli-interrupt")
        terminal = _control_wait(context, started.job_id, started.revision)
    _print_snapshot(terminal, output)
    raise typer.Exit(_exit_code(terminal))


@profile_app.command("list")
def profile_list(
    profile_dir: Path = typer.Option(Path("profiles"), "--profile-dir"),
) -> None:
    for name in _profiles(profile_dir, Path(".trex-plans")).list_profiles():
        typer.echo(name)


@profile_app.command("show")
def profile_show(
    name: str,
    profile_dir: Path = typer.Option(Path("profiles"), "--profile-dir"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    try:
        profile = _profiles(profile_dir, Path(".trex-plans")).show(name)
    except ProfileError as error:
        _profile_error(error)
    if output == "json":
        typer.echo(
            json.dumps(
                {
                    "name": profile.name,
                    "digest": profile.source_digest,
                    "document": profile.document.model_dump(
                        mode="json", by_alias=True, exclude_none=True
                    ),
                },
                indent=2,
            )
        )
        return
    if output != "human":
        raise typer.BadParameter("--output must be human or json")
    typer.echo(f"Profile: {profile.name}")
    typer.echo(f"Digest: {profile.source_digest}")
    typer.echo(f"Kind: {profile.document.kind}")


@plan_app.command("create")
def plan_create(
    profile: str = typer.Option(..., "--profile"),
    set_values: list[str] | None = typer.Option(
        None, "--set", help="Repeatable path=value override"
    ),
    profile_dir: Path = typer.Option(Path("profiles"), "--profile-dir"),
    plans_dir: Path = typer.Option(Path(".trex-plans"), "--plans-dir"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    try:
        plan = _profiles(profile_dir, plans_dir).create(profile, set_values or [])
    except ProfileError as error:
        _profile_error(error)
    _print_plan(plan, output)


@plan_app.command("stateless")
def plan_stateless(
    profile: str = typer.Option(..., "--profile"),
    set_values: list[str] | None = typer.Option(
        None, "--set", help="Repeatable path=value override"
    ),
    profile_dir: Path = typer.Option(Path("profiles"), "--profile-dir"),
    plans_dir: Path = typer.Option(Path(".trex-plans"), "--plans-dir"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    try:
        plan = _profiles(profile_dir, plans_dir).create(
            profile, set_values or [], expected_kind="StatelessTraffic"
        )
    except ProfileError as error:
        _profile_error(error)
    _print_plan(plan, output)


@plan_app.command("rfc2544")
def plan_rfc2544(
    profile: str = typer.Option(..., "--profile"),
    set_values: list[str] | None = typer.Option(
        None, "--set", help="Repeatable path=value override"
    ),
    profile_dir: Path = typer.Option(Path("profiles"), "--profile-dir"),
    plans_dir: Path = typer.Option(Path(".trex-plans"), "--plans-dir"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    try:
        plan = _profiles(profile_dir, plans_dir).create(
            profile, set_values or [], expected_kind="Rfc2544Throughput"
        )
    except ProfileError as error:
        _profile_error(error)
    _print_plan(plan, output)


@plan_app.command("list")
def plan_list(plans_dir: Path = typer.Option(Path(".trex-plans"), "--plans-dir")) -> None:
    for plan_id in _profiles(Path("profiles"), plans_dir).list_plans():
        typer.echo(plan_id)


@plan_app.command("show")
def plan_show(
    plan_id: str,
    plans_dir: Path = typer.Option(Path(".trex-plans"), "--plans-dir"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    try:
        plan = _load_any_plan(plan_id, plans_dir)
    except (ProfileError, TestPlanError) as error:
        _profile_error(error)
    _print_any_plan(plan, output)


@plan_app.command("start")
def plan_start(
    ctx: typer.Context,
    plan_id: str,
    plans_dir: Path = typer.Option(Path(".trex-plans"), "--plans-dir"),
    yes: bool = typer.Option(False, "--yes", help="Skip the interactive confirmation"),
    output: str = typer.Option("human", "--output", help="human, json, or id"),
) -> None:
    context = _context(ctx)
    local_path = plans_dir / f"{plan_id}.json"
    if context.token and not local_path.is_file():
        snapshot = _control_start(context, plan_id)
        if output == "id":
            typer.echo(snapshot.job_id)
        else:
            _print_snapshot(snapshot, output)
        return
    try:
        plan = _load_any_plan(plan_id, plans_dir)
    except (ProfileError, TestPlanError) as error:
        _profile_error(error)
    if not yes:
        _print_any_plan(plan, "human")
        if not typer.confirm("Start this immutable plan?"):
            raise typer.Abort()
    snapshot = _submit_document(context, plan.document, plan.plan_id, None)
    if output == "id":
        typer.echo(snapshot.job_id)
    else:
        _print_snapshot(snapshot, output)


@traffic_app.command("plan")
def traffic_plan(
    ctx: typer.Context,
    profile: str = typer.Option(..., "--profile"),
    path: str = typer.Option(..., "--path"),
    rate: str = typer.Option(..., "--rate", help="Per-egress rate, for example 1gbps"),
    duration: str = typer.Option(..., "--duration", help="Bounded duration, for example 30s"),
    flows: list[str] | None = typer.Option(None, "--flow", help="Repeatable flow selection"),
    parameters: list[str] | None = typer.Option(
        None, "--param", help="Repeatable declared profile parameter name=value"
    ),
    profile_dir: Path = typer.Option(Path("traffic-profiles"), "--profile-dir"),
    path_dir: Path = typer.Option(Path("lab-paths"), "--path-dir"),
    plans_dir: Path = typer.Option(Path(".trex-plans"), "--plans-dir"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    context = _context(ctx)
    if context.token:
        planned = _control_plan(
            context,
            {
                "kind": "traffic",
                "profile": profile,
                "path": path,
                "parameters": _parameter_values(parameters or []),
                "rate": rate,
                "duration": duration,
                "flows": flows or [],
            },
        )
        _print_control_plan(planned, output)
        return
    plan = _plan_traffic(
        profile=profile,
        path=path,
        rate=rate,
        duration=duration,
        flows=flows or [],
        parameters=parameters or [],
        profile_dir=profile_dir,
        path_dir=path_dir,
        plans_dir=plans_dir,
    )
    _print_intent_plan(plan, output)


@dns_storm_app.command("plan")
def dns_storm_plan(
    ctx: typer.Context,
    path: str = typer.Option(..., "--path"),
    client_role: str = typer.Option(..., "--client"),
    server_role: str = typer.Option(..., "--server"),
    name: str = typer.Option(..., "--name"),
    query_type: str = typer.Option("A", "--type"),
    recursion_desired: bool = typer.Option(
        True, "--recursion-desired/--no-recursion-desired"
    ),
    source_port_start: int = typer.Option(1024, "--source-port-start", min=1024, max=65_535),
    source_port_end: int = typer.Option(65_535, "--source-port-end", min=1024, max=65_535),
    pps: float = typer.Option(..., "--pps", min=0.001),
    duration: str = typer.Option(..., "--duration"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    planned = _control_plan(
        _context(ctx),
        _dns_storm_intent(
            path=path,
            client_role=client_role,
            server_role=server_role,
            name=name,
            query_type=query_type,
            recursion_desired=recursion_desired,
            source_port_start=source_port_start,
            source_port_end=source_port_end,
            pps=pps,
            duration=duration,
        ),
    )
    _print_control_plan(planned, output)


@dns_storm_app.command("run")
def dns_storm_run(
    ctx: typer.Context,
    path: str = typer.Option(..., "--path"),
    client_role: str = typer.Option(..., "--client"),
    server_role: str = typer.Option(..., "--server"),
    name: str = typer.Option(..., "--name"),
    query_type: str = typer.Option("A", "--type"),
    recursion_desired: bool = typer.Option(
        True, "--recursion-desired/--no-recursion-desired"
    ),
    source_port_start: int = typer.Option(1024, "--source-port-start", min=1024, max=65_535),
    source_port_end: int = typer.Option(65_535, "--source-port-end", min=1024, max=65_535),
    pps: float = typer.Option(..., "--pps", min=0.001),
    duration: str = typer.Option(..., "--duration"),
    yes: bool = typer.Option(False, "--yes"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    context = _context(ctx)
    planned = _control_plan(
        context,
        _dns_storm_intent(
            path=path,
            client_role=client_role,
            server_role=server_role,
            name=name,
            query_type=query_type,
            recursion_desired=recursion_desired,
            source_port_start=source_port_start,
            source_port_end=source_port_end,
            pps=pps,
            duration=duration,
        ),
    )
    if output == "human" or not yes:
        _print_control_plan(planned, "human")
    if not yes and not typer.confirm("Start this immutable DNS query storm plan?"):
        raise typer.Abort()
    started = _control_start(context, planned.plan_id)
    try:
        terminal = _control_wait(context, started.job_id, started.revision)
    except KeyboardInterrupt:
        _control_cancel(context, started.job_id, "cli-interrupt")
        terminal = _control_wait(context, started.job_id, started.revision)
    _print_snapshot(terminal, output)
    raise typer.Exit(_exit_code(terminal))


@dhcp_storm_app.command("plan")
def dhcp_storm_plan(
    ctx: typer.Context,
    path: str = typer.Option(..., "--path"),
    client_role: str = typer.Option(..., "--client"),
    server_role: str = typer.Option(..., "--server"),
    clients: int = typer.Option(1, "--clients", min=1),
    pps: float = typer.Option(..., "--pps", min=0.001),
    duration: str = typer.Option(..., "--duration"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    planned = _control_plan(
        _context(ctx),
        _dhcp_storm_intent(
            path=path,
            client_role=client_role,
            server_role=server_role,
            clients=clients,
            pps=pps,
            duration=duration,
        ),
    )
    _print_control_plan(planned, output)


@dhcp_storm_app.command("run")
def dhcp_storm_run(
    ctx: typer.Context,
    path: str = typer.Option(..., "--path"),
    client_role: str = typer.Option(..., "--client"),
    server_role: str = typer.Option(..., "--server"),
    clients: int = typer.Option(1, "--clients", min=1),
    pps: float = typer.Option(..., "--pps", min=0.001),
    duration: str = typer.Option(..., "--duration"),
    yes: bool = typer.Option(False, "--yes"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    context = _context(ctx)
    planned = _control_plan(
        context,
        _dhcp_storm_intent(
            path=path,
            client_role=client_role,
            server_role=server_role,
            clients=clients,
            pps=pps,
            duration=duration,
        ),
    )
    if output == "human" or not yes:
        _print_control_plan(planned, "human")
    if not yes and not typer.confirm("Start this immutable DHCP Discover storm plan?"):
        raise typer.Abort()
    started = _control_start(context, planned.plan_id)
    try:
        terminal = _control_wait(context, started.job_id, started.revision)
    except KeyboardInterrupt:
        _control_cancel(context, started.job_id, "cli-interrupt")
        terminal = _control_wait(context, started.job_id, started.revision)
    _print_snapshot(terminal, output)
    raise typer.Exit(_exit_code(terminal))


@arp_storm_app.command("plan")
def arp_storm_plan(
    ctx: typer.Context,
    path: str = typer.Option(..., "--path"),
    sender_role: str = typer.Option(..., "--sender"),
    target_role: str = typer.Option(..., "--target"),
    senders: int = typer.Option(1, "--senders", min=1),
    pps: float = typer.Option(..., "--pps", min=0.001),
    duration: str = typer.Option(..., "--duration"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    planned = _control_plan(
        _context(ctx),
        _arp_storm_intent(
            path=path,
            sender_role=sender_role,
            target_role=target_role,
            senders=senders,
            pps=pps,
            duration=duration,
        ),
    )
    _print_control_plan(planned, output)


@arp_storm_app.command("run")
def arp_storm_run(
    ctx: typer.Context,
    path: str = typer.Option(..., "--path"),
    sender_role: str = typer.Option(..., "--sender"),
    target_role: str = typer.Option(..., "--target"),
    senders: int = typer.Option(1, "--senders", min=1),
    pps: float = typer.Option(..., "--pps", min=0.001),
    duration: str = typer.Option(..., "--duration"),
    yes: bool = typer.Option(False, "--yes"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    context = _context(ctx)
    planned = _control_plan(
        context,
        _arp_storm_intent(
            path=path,
            sender_role=sender_role,
            target_role=target_role,
            senders=senders,
            pps=pps,
            duration=duration,
        ),
    )
    if output == "human" or not yes:
        _print_control_plan(planned, "human")
    if not yes and not typer.confirm("Start this immutable ARP Request storm plan?"):
        raise typer.Abort()
    started = _control_start(context, planned.plan_id)
    try:
        terminal = _control_wait(context, started.job_id, started.revision)
    except KeyboardInterrupt:
        _control_cancel(context, started.job_id, "cli-interrupt")
        terminal = _control_wait(context, started.job_id, started.revision)
    _print_snapshot(terminal, output)
    raise typer.Exit(_exit_code(terminal))


@traffic_app.command("run")
def traffic_run(
    ctx: typer.Context,
    profile: str = typer.Option(..., "--profile"),
    path: str = typer.Option(..., "--path"),
    rate: str = typer.Option(..., "--rate", help="Per-egress rate, for example 1gbps"),
    duration: str = typer.Option(..., "--duration", help="Bounded duration, for example 30s"),
    flows: list[str] | None = typer.Option(None, "--flow", help="Repeatable flow selection"),
    parameters: list[str] | None = typer.Option(
        None, "--param", help="Repeatable declared profile parameter name=value"
    ),
    profile_dir: Path = typer.Option(Path("traffic-profiles"), "--profile-dir"),
    path_dir: Path = typer.Option(Path("lab-paths"), "--path-dir"),
    plans_dir: Path = typer.Option(Path(".trex-plans"), "--plans-dir"),
    yes: bool = typer.Option(False, "--yes", help="Skip the interactive confirmation"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    context = _context(ctx)
    if context.token:
        planned = _control_plan(
            context,
            {
                "kind": "traffic",
                "profile": profile,
                "path": path,
                "parameters": _parameter_values(parameters or []),
                "rate": rate,
                "duration": duration,
                "flows": flows or [],
            },
        )
        if output == "human" or not yes:
            _print_control_plan(planned, "human")
        if not yes and not typer.confirm("Start this immutable plan?"):
            raise typer.Abort()
        snapshot = _control_start(context, planned.plan_id)
        try:
            terminal = _control_wait(context, snapshot.job_id, snapshot.revision)
        except KeyboardInterrupt:
            _control_cancel(context, snapshot.job_id, "cli-interrupt")
            terminal = _control_wait(context, snapshot.job_id, snapshot.revision)
        _print_snapshot(terminal, output)
        raise typer.Exit(_exit_code(terminal))
    plan = _plan_traffic(
        profile=profile,
        path=path,
        rate=rate,
        duration=duration,
        flows=flows or [],
        parameters=parameters or [],
        profile_dir=profile_dir,
        path_dir=path_dir,
        plans_dir=plans_dir,
    )
    if output == "human" or not yes:
        _print_intent_plan(plan, "human")
    if not yes and not typer.confirm("Start this immutable plan?"):
        raise typer.Abort()
    snapshot = _submit_document(context, plan.document, plan.plan_id, None)
    try:
        terminal = _wait(context, snapshot.job_id, snapshot.revision)
    except KeyboardInterrupt:
        _cancel(context, snapshot.job_id, "cli-interrupt")
        terminal = _wait(context, snapshot.job_id, snapshot.revision)
    _print_snapshot(terminal, output)
    raise typer.Exit(_exit_code(terminal))


@rfc2544_app.command("plan")
def rfc2544_plan(
    ctx: typer.Context,
    profile: str = typer.Option(..., "--profile"),
    path: str = typer.Option(..., "--path"),
    flow: str | None = typer.Option(None, "--forward", help="Forward benchmark flow"),
    reverse: str | None = typer.Option(None, "--reverse", help="Explicit reverse flow"),
    direction_mode: str = typer.Option("unidirectional", "--direction-mode"),
    mode: str = typer.Option("fast", "--mode", help="fast or strict"),
    frame_sizes: list[int] | None = typer.Option(
        None, "--frame-size", help="Repeatable fast-mode frame size"
    ),
    tests: list[str] | None = typer.Option(None, "--test", help="Repeatable RFC2544 method"),
    latency_definition: str | None = typer.Option(None, "--latency-definition"),
    latency_scenarios: list[str] | None = typer.Option(None, "--latency-scenario"),
    latency_new_destination_flow: str | None = typer.Option(None, "--latency-new-destination-flow"),
    back_to_back_max_burst_frames: int | None = typer.Option(
        None, "--back-to-back-max-burst-frames", min=2
    ),
    back_to_back_repetitions: int | None = typer.Option(None, "--back-to-back-repetitions", min=1),
    back_to_back_minimum_step_frames: int | None = typer.Option(
        None, "--back-to-back-minimum-step-frames", min=1
    ),
    back_to_back_maximum_burst_seconds: float | None = typer.Option(
        None, "--back-to-back-maximum-burst-seconds", min=30
    ),
    back_to_back_buffer_depletion_seconds: float | None = typer.Option(
        None, "--back-to-back-buffer-depletion-seconds", min=2
    ),
    parameters: list[str] | None = typer.Option(None, "--param"),
    profile_dir: Path = typer.Option(Path("traffic-profiles"), "--profile-dir"),
    path_dir: Path = typer.Option(Path("lab-paths"), "--path-dir"),
    plans_dir: Path = typer.Option(Path(".trex-plans"), "--plans-dir"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    context = _context(ctx)
    if context.token:
        planned = _control_plan(
            context,
            _rfc2544_intent(
                profile=profile,
                path=path,
                flow=flow,
                reverse=reverse,
                direction_mode=direction_mode,
                mode=mode,
                frame_sizes=frame_sizes,
                tests=tests or ["throughput"],
                latency_definition=latency_definition,
                latency_scenarios=latency_scenarios or [],
                latency_new_destination_flow=latency_new_destination_flow,
                back_to_back_max_burst_frames=back_to_back_max_burst_frames,
                back_to_back_repetitions=back_to_back_repetitions,
                back_to_back_minimum_step_frames=back_to_back_minimum_step_frames,
                back_to_back_maximum_burst_seconds=back_to_back_maximum_burst_seconds,
                back_to_back_buffer_depletion_seconds=back_to_back_buffer_depletion_seconds,
                parameters=parameters or [],
            ),
        )
        _print_control_plan(planned, output)
        return
    plan = _plan_rfc2544(
        profile=profile,
        path=path,
        flow=flow,
        reverse=reverse,
        direction_mode=direction_mode,
        mode=mode,
        frame_sizes=frame_sizes,
        tests=tests or ["throughput"],
        latency_definition=latency_definition,
        latency_scenarios=latency_scenarios or [],
        latency_new_destination_flow=latency_new_destination_flow,
        back_to_back_max_burst_frames=back_to_back_max_burst_frames,
        back_to_back_repetitions=back_to_back_repetitions,
        back_to_back_minimum_step_frames=back_to_back_minimum_step_frames,
        back_to_back_maximum_burst_seconds=back_to_back_maximum_burst_seconds,
        back_to_back_buffer_depletion_seconds=back_to_back_buffer_depletion_seconds,
        parameters=parameters or [],
        profile_dir=profile_dir,
        path_dir=path_dir,
        plans_dir=plans_dir,
    )
    _print_rfc2544_plan(plan, output)


@rfc2544_app.command("run")
def rfc2544_run(
    ctx: typer.Context,
    profile: str = typer.Option(..., "--profile"),
    path: str = typer.Option(..., "--path"),
    flow: str | None = typer.Option(None, "--forward", help="Forward benchmark flow"),
    reverse: str | None = typer.Option(None, "--reverse", help="Explicit reverse flow"),
    direction_mode: str = typer.Option("unidirectional", "--direction-mode"),
    mode: str = typer.Option("fast", "--mode", help="fast or strict"),
    frame_sizes: list[int] | None = typer.Option(None, "--frame-size"),
    tests: list[str] | None = typer.Option(None, "--test", help="Repeatable RFC2544 method"),
    latency_definition: str | None = typer.Option(None, "--latency-definition"),
    latency_scenarios: list[str] | None = typer.Option(None, "--latency-scenario"),
    latency_new_destination_flow: str | None = typer.Option(None, "--latency-new-destination-flow"),
    back_to_back_max_burst_frames: int | None = typer.Option(
        None, "--back-to-back-max-burst-frames", min=2
    ),
    back_to_back_repetitions: int | None = typer.Option(None, "--back-to-back-repetitions", min=1),
    back_to_back_minimum_step_frames: int | None = typer.Option(
        None, "--back-to-back-minimum-step-frames", min=1
    ),
    back_to_back_maximum_burst_seconds: float | None = typer.Option(
        None, "--back-to-back-maximum-burst-seconds", min=30
    ),
    back_to_back_buffer_depletion_seconds: float | None = typer.Option(
        None, "--back-to-back-buffer-depletion-seconds", min=2
    ),
    parameters: list[str] | None = typer.Option(None, "--param"),
    profile_dir: Path = typer.Option(Path("traffic-profiles"), "--profile-dir"),
    path_dir: Path = typer.Option(Path("lab-paths"), "--path-dir"),
    plans_dir: Path = typer.Option(Path(".trex-plans"), "--plans-dir"),
    yes: bool = typer.Option(False, "--yes", help="Skip the interactive confirmation"),
    output: str = typer.Option("human", "--output", help="human or json"),
) -> None:
    context = _context(ctx)
    if context.token:
        planned = _control_plan(
            context,
            _rfc2544_intent(
                profile=profile,
                path=path,
                flow=flow,
                reverse=reverse,
                direction_mode=direction_mode,
                mode=mode,
                frame_sizes=frame_sizes,
                tests=tests or ["throughput"],
                latency_definition=latency_definition,
                latency_scenarios=latency_scenarios or [],
                latency_new_destination_flow=latency_new_destination_flow,
                back_to_back_max_burst_frames=back_to_back_max_burst_frames,
                back_to_back_repetitions=back_to_back_repetitions,
                back_to_back_minimum_step_frames=back_to_back_minimum_step_frames,
                back_to_back_maximum_burst_seconds=back_to_back_maximum_burst_seconds,
                back_to_back_buffer_depletion_seconds=back_to_back_buffer_depletion_seconds,
                parameters=parameters or [],
            ),
        )
        if output == "human" or not yes:
            _print_control_plan(planned, "human")
        if not yes and not typer.confirm("Start this immutable plan?"):
            raise typer.Abort()
        snapshot = _control_start(context, planned.plan_id)
        try:
            terminal = _control_wait(context, snapshot.job_id, snapshot.revision)
        except KeyboardInterrupt:
            _control_cancel(context, snapshot.job_id, "cli-interrupt")
            terminal = _control_wait(context, snapshot.job_id, snapshot.revision)
        _print_snapshot(terminal, output)
        raise typer.Exit(_exit_code(terminal))
    plan = _plan_rfc2544(
        profile=profile,
        path=path,
        flow=flow,
        reverse=reverse,
        direction_mode=direction_mode,
        mode=mode,
        frame_sizes=frame_sizes,
        tests=tests or ["throughput"],
        latency_definition=latency_definition,
        latency_scenarios=latency_scenarios or [],
        latency_new_destination_flow=latency_new_destination_flow,
        back_to_back_max_burst_frames=back_to_back_max_burst_frames,
        back_to_back_repetitions=back_to_back_repetitions,
        back_to_back_minimum_step_frames=back_to_back_minimum_step_frames,
        back_to_back_maximum_burst_seconds=back_to_back_maximum_burst_seconds,
        back_to_back_buffer_depletion_seconds=back_to_back_buffer_depletion_seconds,
        parameters=parameters or [],
        profile_dir=profile_dir,
        path_dir=path_dir,
        plans_dir=plans_dir,
    )
    if output == "human" or not yes:
        _print_rfc2544_plan(plan, "human")
    if not yes and not typer.confirm("Start this immutable plan?"):
        raise typer.Abort()
    snapshot = _submit_document(context, plan.document, plan.plan_id, None)
    try:
        terminal = _wait(context, snapshot.job_id, snapshot.revision)
    except KeyboardInterrupt:
        _cancel(context, snapshot.job_id, "cli-interrupt")
        terminal = _wait(context, snapshot.job_id, snapshot.revision)
    _print_snapshot(terminal, output)
    raise typer.Exit(_exit_code(terminal))


def _context(ctx: typer.Context) -> ClientContext:
    value = ctx.find_root().obj
    if not isinstance(value, ClientContext):
        raise RuntimeError("CLI context is not initialized")
    return value


def _profiles(profile_dir: Path, plans_dir: Path) -> Profiles:
    return Profiles(profile_dir, plans_dir)


def _intent_plans(profile_dir: Path, path_dir: Path, plans_dir: Path) -> TestPlanModule:
    return TestPlanModule(profile_dir, path_dir, plans_dir)


def _plan_traffic(
    *,
    profile: str,
    path: str,
    rate: str,
    duration: str,
    flows: list[str],
    parameters: list[str],
    profile_dir: Path,
    path_dir: Path,
    plans_dir: Path,
) -> IntentPlan:
    try:
        return _intent_plans(profile_dir, path_dir, plans_dir).plan_traffic(
            profile_name=profile,
            path_name=path,
            parameters=parameters,
            rate=rate,
            duration=duration,
            flow_names=flows,
        )
    except TestPlanError as error:
        _profile_error(error)


def _plan_rfc2544(
    *,
    profile: str,
    path: str,
    flow: str | None,
    reverse: str | None,
    direction_mode: str,
    mode: str,
    frame_sizes: list[int] | None,
    tests: list[str],
    latency_definition: str | None,
    latency_scenarios: list[str],
    latency_new_destination_flow: str | None,
    back_to_back_max_burst_frames: int | None,
    back_to_back_repetitions: int | None,
    back_to_back_minimum_step_frames: int | None,
    back_to_back_maximum_burst_seconds: float | None,
    back_to_back_buffer_depletion_seconds: float | None,
    parameters: list[str],
    profile_dir: Path,
    path_dir: Path,
    plans_dir: Path,
) -> Rfc2544IntentPlan:
    if mode not in {"fast", "strict"}:
        raise typer.BadParameter("--mode must be fast or strict")
    allowed_direction_modes = {
        "unidirectional",
        "bidirectional-simultaneous",
        "unidirectional-each",
    }
    if direction_mode not in allowed_direction_modes:
        raise typer.BadParameter(
            "--direction-mode must be unidirectional, bidirectional-simultaneous, "
            "or unidirectional-each"
        )
    allowed_tests = {"throughput", "latency", "frame-loss", "back-to-back"}
    if not tests or len(set(tests)) != len(tests) or not set(tests) <= allowed_tests:
        raise typer.BadParameter(
            "--test must be unique and chosen from throughput, latency, frame-loss, or back-to-back"
        )
    latency: dict[str, Any] | None = None
    if "latency" in tests:
        if latency_definition not in {"store-and-forward", "bit-forwarding"}:
            raise typer.BadParameter(
                "--latency-definition is required and must be store-and-forward or bit-forwarding"
            )
        latency = {
            "definition": latency_definition,
            "scenarios": latency_scenarios,
        }
    elif latency_definition is not None or latency_scenarios:
        raise typer.BadParameter("latency options require --test latency")
    if latency_new_destination_flow is not None and "new-destination" not in latency_scenarios:
        raise typer.BadParameter(
            "--latency-new-destination-flow requires --latency-scenario new-destination"
        )
    back_to_back: dict[str, Any] | None = None
    if "back-to-back" in tests:
        if back_to_back_max_burst_frames is None:
            raise typer.BadParameter(
                "--back-to-back-max-burst-frames is required by --test back-to-back"
            )
        back_to_back = {
            "maximumBurstFrames": back_to_back_max_burst_frames,
            **(
                {"repetitions": back_to_back_repetitions}
                if back_to_back_repetitions is not None
                else {}
            ),
            **(
                {"minimumStepFrames": back_to_back_minimum_step_frames}
                if back_to_back_minimum_step_frames is not None
                else {}
            ),
            **(
                {"maximumBurstSeconds": back_to_back_maximum_burst_seconds}
                if back_to_back_maximum_burst_seconds is not None
                else {}
            ),
            **(
                {"bufferDepletionSeconds": back_to_back_buffer_depletion_seconds}
                if back_to_back_buffer_depletion_seconds is not None
                else {}
            ),
        }
    elif any(
        value is not None
        for value in (
            back_to_back_max_burst_frames,
            back_to_back_repetitions,
            back_to_back_minimum_step_frames,
            back_to_back_maximum_burst_seconds,
            back_to_back_buffer_depletion_seconds,
        )
    ):
        raise typer.BadParameter("back-to-back options require --test back-to-back")
    try:
        return _intent_plans(profile_dir, path_dir, plans_dir).plan_rfc2544_suite(
            profile_name=profile,
            path_name=path,
            parameters=parameters,
            mode=cast(Literal["strict", "fast"], mode),
            flow_name=flow,
            reverse_flow_name=reverse,
            direction_mode=cast(
                Literal[
                    "unidirectional",
                    "bidirectional-simultaneous",
                    "unidirectional-each",
                ],
                direction_mode,
            ),
            frame_sizes=frame_sizes,
            tests=tuple(
                cast(
                    Literal["throughput", "latency", "frame-loss", "back-to-back"],
                    item,
                )
                for item in tests
            ),
            latency=latency,
            latency_new_destination_flow_name=latency_new_destination_flow,
            back_to_back=back_to_back,
        )
    except TestPlanError as error:
        _profile_error(error)


def _parameter_values(assignments: list[str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for assignment in assignments:
        if "=" not in assignment:
            raise typer.BadParameter("--param must use name=value")
        name, raw_value = assignment.split("=", 1)
        if name in values:
            raise typer.BadParameter(f"--param supplied more than once: {name}")
        values[name] = load_yaml(raw_value)
    return values


def _rfc2544_intent(
    *,
    profile: str,
    path: str,
    flow: str | None,
    reverse: str | None,
    direction_mode: str,
    mode: str,
    frame_sizes: list[int] | None,
    tests: list[str],
    latency_definition: str | None,
    latency_scenarios: list[str],
    latency_new_destination_flow: str | None,
    back_to_back_max_burst_frames: int | None,
    back_to_back_repetitions: int | None,
    back_to_back_minimum_step_frames: int | None,
    back_to_back_maximum_burst_seconds: float | None,
    back_to_back_buffer_depletion_seconds: float | None,
    parameters: list[str],
) -> dict[str, Any]:
    return {
        "kind": "benchmark-rfc2544",
        "profile": profile,
        "path": path,
        "parameters": _parameter_values(parameters),
        "mode": mode,
        "flow": flow,
        "reverseFlow": reverse,
        "directionMode": direction_mode,
        "frameSizes": frame_sizes,
        "tests": tests,
        "latency": (
            {
                "definition": latency_definition,
                "scenarios": latency_scenarios,
            }
            if "latency" in tests
            else None
        ),
        "latencyNewDestinationFlow": latency_new_destination_flow,
        "backToBack": (
            {
                "maximumBurstFrames": back_to_back_max_burst_frames,
                **(
                    {"repetitions": back_to_back_repetitions}
                    if back_to_back_repetitions is not None
                    else {}
                ),
                **(
                    {"minimumStepFrames": back_to_back_minimum_step_frames}
                    if back_to_back_minimum_step_frames is not None
                    else {}
                ),
                **(
                    {"maximumBurstSeconds": back_to_back_maximum_burst_seconds}
                    if back_to_back_maximum_burst_seconds is not None
                    else {}
                ),
                **(
                    {"bufferDepletionSeconds": back_to_back_buffer_depletion_seconds}
                    if back_to_back_buffer_depletion_seconds is not None
                    else {}
                ),
            }
            if "back-to-back" in tests
            else None
        ),
    }


def _pcap_replay_intent(
    *,
    capture: str,
    path: str,
    source_role: str,
    destination_role: str,
    address_mode: str,
    timing_mode: str,
    multiplier: float,
    timestamp_policy: str,
    rate: str | None,
) -> dict[str, Any]:
    if address_mode not in {"rewrite", "preserve"}:
        raise typer.BadParameter("--address-mode must be rewrite or preserve")
    if timing_mode not in {"capture", "fixed-rate", "top-speed"}:
        raise typer.BadParameter("--timing must be capture, fixed-rate, or top-speed")
    if timestamp_policy not in {"reject", "normalize"}:
        raise typer.BadParameter("--timestamp-policy must be reject or normalize")
    if timing_mode == "fixed-rate" and rate is None:
        raise typer.BadParameter("--rate is required by --timing fixed-rate")
    if timing_mode != "fixed-rate" and rate is not None:
        raise typer.BadParameter("--rate is only valid with --timing fixed-rate")
    return {
        "kind": "pcap-replay",
        "capture": capture,
        "path": path,
        "sourceRole": source_role,
        "destinationRole": destination_role,
        "addressMode": address_mode,
        "timingMode": timing_mode,
        "multiplier": multiplier,
        "timestampPolicy": timestamp_policy,
        "rate": rate,
    }


def _stateful_replay_intent(
    *,
    capture: str,
    session_id: str,
    path: str,
    client_role: str,
    server_role: str,
    cps: float,
    max_active_connections: int,
    duration: str,
    client_ipv4_start: str | None = None,
    client_ipv4_end: str | None = None,
    server_ipv4_start: str | None = None,
    server_ipv4_end: str | None = None,
    client_port_start: int = 1024,
    client_port_end: int = 65_535,
) -> dict[str, Any]:
    return {
        "kind": "pcap-stateful-replay",
        "capture": capture,
        "sessionId": session_id,
        "path": path,
        "clientRole": client_role,
        "serverRole": server_role,
        "cps": cps,
        "maxActiveConnections": max_active_connections,
        "duration": duration,
        **({"clientIpv4Start": client_ipv4_start} if client_ipv4_start else {}),
        **({"clientIpv4End": client_ipv4_end} if client_ipv4_end else {}),
        **({"serverIpv4Start": server_ipv4_start} if server_ipv4_start else {}),
        **({"serverIpv4End": server_ipv4_end} if server_ipv4_end else {}),
        "clientPortStart": client_port_start,
        "clientPortEnd": client_port_end,
    }


def _capture_workload_intent(
    *,
    capture: str,
    path: str,
    client_role: str,
    server_role: str,
    cps: float,
    max_active_connections: int,
    duration: str,
    client_ipv4_start: str | None = None,
    client_ipv4_end: str | None = None,
    server_ipv4_start: str | None = None,
    server_ipv4_end: str | None = None,
    client_port_start: int = 1024,
    client_port_end: int = 65_535,
) -> dict[str, Any]:
    return {
        "kind": "pcap-capture-workload",
        "capture": capture,
        "path": path,
        "clientRole": client_role,
        "serverRole": server_role,
        "cps": cps,
        "maxActiveConnections": max_active_connections,
        "duration": duration,
        **({"clientIpv4Start": client_ipv4_start} if client_ipv4_start else {}),
        **({"clientIpv4End": client_ipv4_end} if client_ipv4_end else {}),
        **({"serverIpv4Start": server_ipv4_start} if server_ipv4_start else {}),
        **({"serverIpv4End": server_ipv4_end} if server_ipv4_end else {}),
        "clientPortStart": client_port_start,
        "clientPortEnd": client_port_end,
    }


def _udp_workload_intent(
    *,
    capture: str,
    path: str,
    initiator_role: str,
    responder_role: str,
    fps: float,
    duration: str,
) -> dict[str, Any]:
    return {
        "kind": "pcap-udp-workload",
        "capture": capture,
        "path": path,
        "initiatorRole": initiator_role,
        "responderRole": responder_role,
        "fps": fps,
        "duration": duration,
    }


def _dns_storm_intent(
    *,
    path: str,
    client_role: str,
    server_role: str,
    name: str,
    query_type: str,
    recursion_desired: bool,
    source_port_start: int,
    source_port_end: int,
    pps: float,
    duration: str,
) -> dict[str, Any]:
    normalized_type = query_type.upper()
    if normalized_type not in {"A", "AAAA"}:
        raise typer.BadParameter("--type must be A or AAAA")
    return {
        "kind": "dns-storm",
        "path": path,
        "clientRole": client_role,
        "serverRole": server_role,
        "name": name,
        "queryType": normalized_type,
        "recursionDesired": recursion_desired,
        "sourcePortStart": source_port_start,
        "sourcePortEnd": source_port_end,
        "pps": pps,
        "duration": duration,
    }


def _dhcp_storm_intent(
    *,
    path: str,
    client_role: str,
    server_role: str,
    clients: int,
    pps: float,
    duration: str,
) -> dict[str, Any]:
    return {
        "kind": "dhcp-storm",
        "path": path,
        "clientRole": client_role,
        "serverRole": server_role,
        "clients": clients,
        "pps": pps,
        "duration": duration,
    }


def _arp_storm_intent(
    *,
    path: str,
    sender_role: str,
    target_role: str,
    senders: int,
    pps: float,
    duration: str,
) -> dict[str, Any]:
    return {
        "kind": "arp-storm",
        "path": path,
        "senderRole": sender_role,
        "targetRole": target_role,
        "senders": senders,
        "pps": pps,
        "duration": duration,
    }


def _load_any_plan(
    plan_id: str, plans_dir: Path
) -> (
    TestPlan
    | IntentPlan
    | Rfc2544IntentPlan
    | PcapReplayPlan
    | StatefulReplayPlan
    | UdpWorkloadPlan
    | DnsStormPlan
    | DhcpStormPlan
    | ArpStormPlan
):
    path = plans_dir / f"{plan_id}.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _profiles(Path("profiles"), plans_dir).get(plan_id)
    except json.JSONDecodeError as error:
        raise TestPlanError(f"stored plan is not valid JSON: {plan_id}") from error
    if isinstance(raw, dict) and raw.get("apiVersion") in {
        "trex.example.io/test-plan/v1",
        "trex.example.io/plan/v2alpha1",
    }:
        return _intent_plans(Path("traffic-profiles"), Path("lab-paths"), plans_dir).get(plan_id)
    return _profiles(Path("profiles"), plans_dir).get(plan_id)


def _profile_error(error: ProfileError | TestPlanError) -> Never:
    typer.echo(f"INVALID_PLAN: {error}", err=True)
    raise typer.Exit(2)


def _load_document(path: Path) -> dict[str, Any]:
    raw = load_yaml(path.read_text(encoding="utf-8"))
    try:
        document = JOB_DOCUMENT_ADAPTER.validate_python(raw)
    except ValidationError as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(2) from error
    return document.model_dump(mode="json", by_alias=True, exclude_none=True)


def _submit(
    context: ClientContext, path: Path, idempotency_key: str, retry_of: str | None
) -> JobSnapshot:
    return _submit_document(context, _load_document(path), idempotency_key, retry_of)


def _submit_document(
    context: ClientContext,
    document: Any,
    idempotency_key: str,
    retry_of: str | None,
) -> JobSnapshot:
    payload: dict[str, Any] = {
        "document": document.model_dump(mode="json", by_alias=True, exclude_none=True)
        if hasattr(document, "model_dump")
        else document
    }
    if retry_of is not None:
        payload["retryOf"] = retry_of
    headers = {**context.headers, "Idempotency-Key": idempotency_key}
    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(f"{context.agent_url}/v1/jobs", headers=headers, json=payload)
    except httpx.HTTPError as error:
        _connection_error(error)
    _raise_for_problem(response)
    return JobSnapshot.model_validate(response.json())


def _control_plan(context: ClientContext, intent: dict[str, Any]) -> PlannedTest:
    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(
                f"{context.agent_url}/v1/plans",
                headers=context.headers,
                json=intent,
            )
    except httpx.HTTPError as error:
        _connection_error(error)
    _raise_for_problem(response)
    return PlannedTest.model_validate(response.json())


def _catalog_get(
    context: ClientContext,
    path: str,
    *,
    params: dict[str, str] | None = None,
) -> dict[str, Any]:
    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"{context.agent_url}{path}",
                headers=context.headers,
                params=params,
            )
    except httpx.HTTPError as error:
        _connection_error(error)
    _raise_for_problem(response)
    return cast(dict[str, Any], response.json())


def _control_start(context: ClientContext, plan_id: str) -> JobSnapshot:
    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(
                f"{context.agent_url}/v1/plans/{plan_id}:start",
                headers=context.headers,
            )
    except httpx.HTTPError as error:
        _connection_error(error)
    _raise_for_problem(response)
    return JobSnapshot.model_validate(response.json())


def _control_get(
    context: ClientContext,
    job_id: str,
    *,
    after_revision: int | None = None,
    wait_seconds: float = 0,
) -> JobSnapshot:
    params: dict[str, int | float] = {"waitSeconds": wait_seconds}
    if after_revision is not None:
        params["afterRevision"] = after_revision
    try:
        with httpx.Client(timeout=max(30, wait_seconds + 5)) as client:
            response = client.get(
                f"{context.agent_url}/v1/tests/{job_id}",
                headers=context.headers,
                params=params,
            )
    except httpx.HTTPError as error:
        _connection_error(error)
    _raise_for_problem(response)
    return JobSnapshot.model_validate(response.json())


def _control_wait(context: ClientContext, job_id: str, after_revision: int) -> JobSnapshot:
    current = _control_get(
        context,
        job_id,
        after_revision=after_revision,
        wait_seconds=30,
    )
    while not current.state.terminal:
        current = _control_get(
            context,
            job_id,
            after_revision=current.revision,
            wait_seconds=30,
        )
    return current


def _control_cancel(context: ClientContext, job_id: str, reason: str) -> JobSnapshot:
    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(
                f"{context.agent_url}/v1/tests/{job_id}:control",
                headers=context.headers,
                json={
                    "action": "cancel",
                    "requestId": uuid.uuid4().hex,
                    "reason": reason,
                },
            )
    except httpx.HTTPError as error:
        _connection_error(error)
    _raise_for_problem(response)
    return JobSnapshot.model_validate(response.json())


def _get(context: ClientContext, job_id: str) -> JobSnapshot:
    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(f"{context.agent_url}/v1/jobs/{job_id}", headers=context.headers)
    except httpx.HTTPError as error:
        _connection_error(error)
    _raise_for_problem(response)
    return JobSnapshot.model_validate(response.json())


def _events(context: ClientContext, job_id: str, after_revision: int) -> Iterator[JobSnapshot]:
    headers = {**context.headers, "Last-Event-ID": str(after_revision)}
    try:
        with httpx.Client(timeout=None) as client:
            with client.stream(
                "GET", f"{context.agent_url}/v1/jobs/{job_id}/events", headers=headers
            ) as response:
                _raise_for_problem(response)
                data_lines: list[str] = []
                for line in response.iter_lines():
                    if line.startswith("data: "):
                        data_lines.append(line.removeprefix("data: "))
                    elif not line and data_lines:
                        yield JobSnapshot.model_validate(json.loads("\n".join(data_lines)))
                        data_lines.clear()
    except httpx.HTTPError as error:
        _connection_error(error)


def _wait(context: ClientContext, job_id: str, after_revision: int) -> JobSnapshot:
    last = _get(context, job_id)
    if last.state.terminal:
        return last
    for snapshot in _events(context, job_id, max(after_revision, last.revision)):
        last = snapshot
    return last


def _cancel(context: ClientContext, job_id: str, reason: str) -> JobSnapshot:
    payload = {"cancelRequestId": uuid.uuid4().hex, "reason": reason}
    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(
                f"{context.agent_url}/v1/jobs/{job_id}:cancel",
                headers=context.headers,
                json=payload,
            )
    except httpx.HTTPError as error:
        _connection_error(error)
    _raise_for_problem(response)
    return JobSnapshot.model_validate(response.json())


def _raise_for_problem(response: httpx.Response) -> None:
    if response.is_success:
        return
    try:
        problem = response.json()
        typer.echo(
            f"{problem.get('code', response.status_code)}: {problem.get('detail')}", err=True
        )
    except json.JSONDecodeError:
        typer.echo(f"HTTP {response.status_code}: {response.text}", err=True)
    raise typer.Exit(2 if response.status_code < 500 else 3)


def _connection_error(error: httpx.HTTPError) -> Never:
    typer.echo(f"UNAVAILABLE: unable to reach the Agent: {error}", err=True)
    raise typer.Exit(3) from error


def _print_snapshot(snapshot: JobSnapshot, output: str) -> None:
    if output == "json":
        typer.echo(snapshot.model_dump_json(by_alias=True, indent=2, exclude_none=True))
        return
    if output != "human":
        raise typer.BadParameter("--output must be human or json")
    typer.echo(f"Job: {snapshot.job_id}")
    typer.echo(f"State: {snapshot.state}")
    if snapshot.result is not None:
        typer.echo(f"Verdict: {snapshot.result.verdict}")
        typer.echo(f"Methodology: {snapshot.result.methodology}")
        typer.echo(f"Simulated: {str(snapshot.result.provenance.simulated).lower()}")
    if snapshot.problem is not None:
        typer.echo(f"Problem: {snapshot.problem.code}: {snapshot.problem.message}")


def _print_capture_resource(resource: dict[str, Any], output: str) -> None:
    if output == "json":
        typer.echo(json.dumps(resource, indent=2))
        return
    if output != "human":
        raise typer.BadParameter("--output must be human or json")
    analysis = resource["document"]["analysis"]
    typer.echo(f"Capture: {resource['ref']}")
    typer.echo(f"Digest: {resource['digest']}")
    typer.echo(f"Packets: {analysis['packetCount']}")
    typer.echo(f"Duration: {analysis['durationSeconds']}s")
    typer.echo(f"Non-monotonic timestamps: {analysis['nonMonotonicTimestampCount']}")


def _exit_code(snapshot: JobSnapshot) -> int:
    if snapshot.state == JobState.CANCELLED:
        return 130
    if snapshot.state == JobState.FAILED:
        return 3
    if snapshot.result is None:
        return 3
    if snapshot.result.verdict == Verdict.FAIL:
        return 1
    if snapshot.result.verdict == Verdict.INVALID:
        return 3
    return 0


def _print_plan(plan: TestPlan, output: str) -> None:
    if output == "json":
        typer.echo(json.dumps(plan.payload(), indent=2))
        return
    if output != "human":
        raise typer.BadParameter("--output must be human or json")
    typer.echo(f"Plan: {plan.plan_id}")
    typer.echo(f"Profile: {plan.profile_name}")
    typer.echo(f"Kind: {plan.document.kind}")
    if plan.overrides:
        typer.echo("Overrides: " + ", ".join(plan.overrides))


def _print_intent_plan(plan: IntentPlan, output: str) -> None:
    if output == "json":
        typer.echo(json.dumps(plan.payload(), indent=2))
        return
    if output != "human":
        raise typer.BadParameter("--output must be human or json")
    typer.echo(f"Plan: {plan.plan_id}")
    typer.echo("Intent: traffic")
    typer.echo(f"Profile: {plan.profile_name}")
    typer.echo(f"Path: {plan.path_name}")
    typer.echo("Flows: " + ", ".join(plan.flow_names))
    typer.echo(f"Rate: {plan.rate_input} per-egress")
    typer.echo(f"Duration: {plan.duration_input}")
    typer.echo(
        "Frames: "
        + ", ".join(
            f"{size}B wire/{size - 4}B generated/{size + 20}B L1" for size in plan.wire_sizes
        )
    )


def _print_rfc2544_plan(plan: Rfc2544IntentPlan, output: str) -> None:
    if output == "json":
        typer.echo(json.dumps(plan.payload(), indent=2))
        return
    if output != "human":
        raise typer.BadParameter("--output must be human or json")
    values = plan.payload()["resolvedFrameSizes"]["values"]
    typer.echo(f"Plan: {plan.plan_id}")
    typer.echo("Intent: benchmark-rfc2544")
    typer.echo("Tests: " + ", ".join(plan.tests))
    typer.echo(f"Mode: {plan.mode}")
    typer.echo(f"Profile: {plan.profile_name}")
    typer.echo(f"Path: {plan.path_name}")
    typer.echo(f"Flow: {plan.flow_name}")
    if plan.reverse_flow_name is not None:
        typer.echo(f"Reverse flow: {plan.reverse_flow_name}")
    typer.echo(f"Direction mode: {plan.direction_mode}")
    typer.echo("Frame sizes (wire/FCS included): " + ", ".join(str(item) for item in values))


def _print_control_plan(plan: PlannedTest, output: str) -> None:
    if output == "json":
        typer.echo(plan.model_dump_json(by_alias=True, indent=2, exclude_none=True))
        return
    if output != "human":
        raise typer.BadParameter("--output must be human or json")
    typer.echo(f"Plan: {plan.plan_id}")
    typer.echo(f"Intent: {plan.intent}")
    for label in ("profile", "capture", "path"):
        resource = plan.resources.get(label)
        if resource is not None:
            typer.echo(f"{label.title()}: {resource.ref} ({resource.digest})")
    typer.echo("Safety: " + json.dumps(plan.safety, ensure_ascii=False, sort_keys=True))


def _print_any_plan(
    plan: (
        TestPlan
        | IntentPlan
        | Rfc2544IntentPlan
        | PcapReplayPlan
        | StatefulReplayPlan
        | UdpWorkloadPlan
        | DnsStormPlan
        | DhcpStormPlan
        | ArpStormPlan
    ),
    output: str,
) -> None:
    if isinstance(plan, IntentPlan):
        _print_intent_plan(plan, output)
    elif isinstance(plan, Rfc2544IntentPlan):
        _print_rfc2544_plan(plan, output)
    elif isinstance(plan, PcapReplayPlan):
        if output == "json":
            typer.echo(json.dumps(plan.payload(), indent=2))
        elif output == "human":
            typer.echo(f"Plan: {plan.plan_id}")
            typer.echo("Intent: pcap-replay")
            typer.echo(f"Capture: {plan.capture_name}@{plan.capture_revision}")
            typer.echo(f"Path: {plan.path_name}@{plan.path_revision}")
        else:
            raise typer.BadParameter("--output must be human or json")
    elif isinstance(plan, UdpWorkloadPlan):
        if output == "json":
            typer.echo(json.dumps(plan.payload(), indent=2))
        elif output == "human":
            typer.echo(f"Plan: {plan.plan_id}")
            typer.echo("Intent: pcap-udp-workload")
            typer.echo(f"Capture: {plan.capture_name}@{plan.capture_revision}")
            typer.echo(
                f"Workload: {plan.document.spec.workload.template_count} templates / "
                f"{plan.document.spec.workload.source_flow_count} source flows"
            )
            typer.echo(f"Path: {plan.path_name}@{plan.path_revision}")
        else:
            raise typer.BadParameter("--output must be human or json")
    elif isinstance(plan, DnsStormPlan):
        assert isinstance(plan.document.spec, DnsStormSpec)
        if output == "json":
            typer.echo(json.dumps(plan.payload(), indent=2))
        elif output == "human":
            typer.echo(f"Plan: {plan.plan_id}")
            typer.echo("Intent: dns-storm")
            typer.echo(f"Path: {plan.path_name}@{plan.path_revision}")
            typer.echo(
                f"Question: {plan.document.spec.question.name} "
                f"{plan.document.spec.question.type} @ {plan.document.spec.run.pps:g} pps"
            )
        else:
            raise typer.BadParameter("--output must be human or json")
    elif isinstance(plan, DhcpStormPlan):
        assert isinstance(plan.document.spec, DhcpStormSpec)
        if output == "json":
            typer.echo(json.dumps(plan.payload(), indent=2))
        elif output == "human":
            typer.echo(f"Plan: {plan.plan_id}")
            typer.echo("Intent: dhcp-storm")
            typer.echo(f"Path: {plan.path_name}@{plan.path_revision}")
            typer.echo(
                f"Discover: {plan.document.spec.clients.count} client identities "
                f"@ {plan.document.spec.run.pps:g} pps"
            )
        else:
            raise typer.BadParameter("--output must be human or json")
    elif isinstance(plan, ArpStormPlan):
        assert isinstance(plan.document.spec, ArpStormSpec)
        if output == "json":
            typer.echo(json.dumps(plan.payload(), indent=2))
        elif output == "human":
            typer.echo(f"Plan: {plan.plan_id}")
            typer.echo("Intent: arp-storm")
            typer.echo(f"Path: {plan.path_name}@{plan.path_revision}")
            typer.echo(
                f"Request: {plan.document.spec.senders.count} sender identities "
                f"to {plan.document.spec.target.ipv4} @ {plan.document.spec.run.pps:g} pps"
            )
        else:
            raise typer.BadParameter("--output must be human or json")
    elif isinstance(plan, StatefulReplayPlan):
        if output == "json":
            typer.echo(json.dumps(plan.payload(), indent=2))
        elif output == "human":
            workload = plan.document.spec.workload
            typer.echo(f"Plan: {plan.plan_id}")
            typer.echo(
                "Intent: "
                + ("pcap-capture-workload" if workload is not None else "pcap-stateful-replay")
            )
            typer.echo(f"Capture: {plan.capture_name}@{plan.capture_revision}")
            if workload is not None:
                typer.echo(
                    f"Workload: {workload.template_count} templates / "
                    f"{workload.source_session_count} source sessions"
                )
            else:
                session = plan.document.spec.session
                if session is not None:
                    typer.echo(f"Session: {session.id}")
            typer.echo(f"Path: {plan.path_name}@{plan.path_revision}")
        else:
            raise typer.BadParameter("--output must be human or json")
    else:
        _print_plan(plan, output)

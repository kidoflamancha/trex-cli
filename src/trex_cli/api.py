from __future__ import annotations

import hashlib
import hmac
import logging
import re
import time
import uuid
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from tempfile import SpooledTemporaryFile
from typing import Annotated, Any, BinaryIO, cast

from fastapi import Body, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
    StreamingResponse,
)

from trex_cli import __version__
from trex_cli.artifacts import ArtifactStore
from trex_cli.astf_adapter import RemoteTrexAstfEngine
from trex_cli.async_compat import to_thread
from trex_cli.config import AgentConfig, RemoteTrexAstfEngineConfig, RemoteTrexEngineConfig
from trex_cli.engine import SimulatedEngine, TrafficEngine
from trex_cli.errors import DatabaseMigrationError, TrexCliError
from trex_cli.jobs import TestJobs
from trex_cli.models import (
    ArtifactCleanupBody,
    CancelBody,
    JobState,
    Principal,
    Role,
    SubmitBody,
)
from trex_cli.observability import RuntimeMetrics, bind_request_id, reset_request_id
from trex_cli.storage import LATEST_SCHEMA_VERSION, SqliteStore
from trex_cli.test_control import (
    ArpStormIntent,
    CancelTest,
    CaptureWorkloadIntent,
    DhcpStormIntent,
    DnsStormIntent,
    PcapReplayIntent,
    ResourceKind,
    Rfc2544TestIntent,
    StatefulReplayIntent,
    TestControl,
    TrafficTestIntent,
    UdpWorkloadIntent,
)
from trex_cli.test_plan import (
    CATALOG_API_VERSION,
    LEGACY_CATALOG_API_VERSION,
    LEGACY_TEST_PLAN_API_VERSION,
    TEST_PLAN_API_VERSION,
    TestPlanError,
    TestPlanModule,
)
from trex_cli.trex_adapter import RemoteTrexStlEngine

_LOGGER = logging.getLogger(__name__)
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def create_app(config: AgentConfig, *, plans: TestPlanModule | None = None) -> FastAPI:
    database = SqliteStore(config.database_path)
    artifacts = ArtifactStore(
        config.artifact_root,
        database,
        retention_days=config.artifact_retention_days,
        orphan_grace_period_ms=config.artifact_orphan_grace_period,
    )
    engine: TrafficEngine
    if isinstance(config.engine, RemoteTrexEngineConfig):
        engine = RemoteTrexStlEngine(
            config.engine,
            policy=config.safety,
            capture_root=config.capture_root,
        )
    elif isinstance(config.engine, RemoteTrexAstfEngineConfig):
        engine = RemoteTrexAstfEngine(
            config.engine,
            capture_root=config.capture_root,
        )
    else:
        engine = SimulatedEngine(config.safety, config.engine.step_delay_ms)
    metrics = RuntimeMetrics(engine=engine.mode, simulated=engine.simulated)
    jobs = TestJobs(config, database, artifacts, engine, metrics=metrics)
    plans = plans or TestPlanModule(
        config.traffic_profile_root,
        config.lab_path_root,
        config.plan_root,
        config.capture_root,
        config.safety,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        started = False
        try:
            await jobs.start()
            started = True
        except DatabaseMigrationError as error:
            application.state.startup_problem = error
            _LOGGER.error(
                "agent_startup_failed",
                extra={"problemCode": error.code, "details": error.details},
            )
        yield
        if started:
            await jobs.stop()

    application = FastAPI(title="trex-agent", version=__version__, lifespan=lifespan)
    application.state.jobs = jobs
    application.state.config = config
    application.state.plans = plans
    application.state.startup_problem = None

    @application.middleware("http")
    async def observe_http(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        supplied_request_id = request.headers.get("X-Request-ID", "")
        request_id = (
            supplied_request_id
            if _REQUEST_ID_PATTERN.fullmatch(supplied_request_id)
            else uuid.uuid4().hex
        )
        token = bind_request_id(request_id)
        started = time.perf_counter()
        try:
            try:
                response = await call_next(request)
            except Exception:
                duration = time.perf_counter() - started
                route = _route_template(request)
                metrics.observe_http(request.method, route, 500, duration)
                _LOGGER.exception(
                    "http_request",
                    extra={
                        "method": request.method,
                        "route": route,
                        "statusCode": 500,
                        "durationSeconds": duration,
                    },
                )
                raise
            duration = time.perf_counter() - started
            route = _route_template(request)
            metrics.observe_http(request.method, route, response.status_code, duration)
            response.headers["X-Request-ID"] = request_id
            response.headers["Trex-Agent-Version"] = __version__
            principal = getattr(request.state, "principal", None)
            fields: dict[str, Any] = {
                "method": request.method,
                "route": route,
                "statusCode": response.status_code,
                "durationSeconds": duration,
            }
            if principal is not None:
                fields["principal"] = principal.name
                fields["role"] = principal.role
            _LOGGER.info(
                "http_request",
                extra=fields,
            )
            return response
        finally:
            reset_request_id(token)

    def authenticate(request: Request, *, require_operator: bool = False) -> Principal:
        authorization = request.headers.get("Authorization")
        if authorization is None or not authorization.startswith("Bearer "):
            _LOGGER.warning("authentication_failed", extra={"reason": "missing-bearer-token"})
            raise TrexCliError(
                code="UNAUTHENTICATED",
                message="a Bearer Token is required",
                category="INPUT",
            )
        supplied = authorization.removeprefix("Bearer ")
        supplied_digest = hashlib.sha256(supplied.encode("utf-8")).digest()
        for name, (digest, role) in config.token_digests.items():
            if hmac.compare_digest(supplied_digest, digest):
                principal = Principal(name=name, role=role)
                request.state.principal = principal
                _LOGGER.info(
                    "authentication_succeeded",
                    extra={"principal": principal.name, "role": principal.role},
                )
                startup_problem = application.state.startup_problem
                if startup_problem is not None:
                    raise TrexCliError(
                        code="AGENT_NOT_READY",
                        category="RESOURCE",
                        message="the Agent database is not ready",
                        details={"cause": startup_problem.message},
                    )
                if require_operator and principal.role != Role.OPERATOR:
                    _LOGGER.warning(
                        "authorization_denied",
                        extra={
                            "principal": principal.name,
                            "role": principal.role,
                            "requiredRole": Role.OPERATOR,
                        },
                    )
                    raise TrexCliError(
                        code="PERMISSION_DENIED",
                        message="operator role is required",
                        category="INPUT",
                    )
                return principal
        _LOGGER.warning("authentication_failed", extra={"reason": "invalid-bearer-token"})
        raise TrexCliError(
            code="UNAUTHENTICATED",
            message="the Bearer Token is invalid",
            category="INPUT",
        )

    @application.exception_handler(TrexCliError)
    async def handle_domain_error(_: Request, error: TrexCliError) -> JSONResponse:
        return JSONResponse(
            status_code=_status_for(error.code),
            media_type="application/problem+json",
            content={
                "type": f"urn:trex-cli:problem:{error.code.lower()}",
                "title": error.code,
                "status": _status_for(error.code),
                "code": error.code,
                "category": error.category,
                "retryable": error.retryable,
                "detail": error.message,
                "details": error.details,
            },
        )

    @application.exception_handler(RequestValidationError)
    async def handle_validation_error(_: Request, error: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            media_type="application/problem+json",
            content={
                "type": "urn:trex-cli:problem:invalid_document",
                "title": "INVALID_DOCUMENT",
                "status": 400,
                "code": "INVALID_DOCUMENT",
                "category": "INPUT",
                "retryable": False,
                "detail": "the request does not satisfy the v1 Interface",
                "details": {"errors": error.errors()},
            },
        )

    @application.exception_handler(TestPlanError)
    async def handle_plan_error(_: Request, error: TestPlanError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            media_type="application/problem+json",
            content={
                "type": "urn:trex-cli:problem:invalid_intent",
                "title": "INVALID_INTENT",
                "status": 400,
                "code": "INVALID_INTENT",
                "category": "INPUT",
                "retryable": False,
                "detail": str(error),
                "details": {},
            },
        )

    @application.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "alive"}

    @application.get("/readyz")
    async def readiness() -> JSONResponse:
        startup_problem = application.state.startup_problem
        if startup_problem is not None:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "not-ready",
                    "reason": startup_problem.code,
                    "details": startup_problem.details,
                },
            )
        engine_status = await engine.probe()
        metrics.set_engine_available(engine_status.available)
        ports = await database.port_statuses()
        schema_version = await database.schema_version()
        return JSONResponse(
            content={
                "status": "ready",
                "engine": engine.mode,
                "simulated": engine.simulated,
                "engineAvailable": engine_status.available,
                "engineDetails": engine_status.details,
                "ports": ports,
                "databaseSchemaVersion": schema_version,
                "transportSecurity": _transport_security(config),
            }
        )

    @application.get("/version")
    async def version_information(request: Request) -> dict[str, Any]:
        authenticate(request)
        return {
            "agentVersion": __version__,
            "httpApiVersions": ["v1"],
            "jobApiVersions": ["trex.example.io/v1"],
            "catalogApiVersions": [CATALOG_API_VERSION],
            "testPlanApiVersions": [TEST_PLAN_API_VERSION],
            "legacyReadApiVersions": [
                LEGACY_CATALOG_API_VERSION,
                LEGACY_TEST_PLAN_API_VERSION,
            ],
            "databaseSchemaVersion": LATEST_SCHEMA_VERSION,
            "artifactManifestVersions": [2],
            "transportSecurity": _transport_security(config),
        }

    @application.get("/metrics", response_class=PlainTextResponse)
    async def runtime_metrics(request: Request) -> PlainTextResponse:
        authenticate(request)
        job_states, artifact_count, artifact_bytes = await database.observation_counts()
        ports = await database.port_statuses()
        port_states = Counter(str(value["status"]) for value in ports.values())
        return PlainTextResponse(
            metrics.render(
                job_states={state: job_states.get(state, 0) for state in JobState},
                port_states={
                    status: port_states.get(status, 0)
                    for status in ("AVAILABLE", "LEASED", "QUARANTINED")
                },
                artifact_count=artifact_count,
                artifact_bytes=artifact_bytes,
            ),
            media_type="text/plain; version=0.0.4",
        )

    @application.post("/v1/jobs", status_code=202)
    async def submit_job(
        request: Request,
        body: SubmitBody,
        idempotency_key: Annotated[
            str, Header(alias="Idempotency-Key", min_length=1, max_length=128)
        ],
    ) -> dict[str, Any]:
        principal = authenticate(request, require_operator=True)
        snapshot = await jobs.submit(body, principal=principal, idempotency_key=idempotency_key)
        return snapshot.model_dump(mode="json", by_alias=True, exclude_none=True)

    @application.get("/v1/catalog")
    async def search_catalog(
        request: Request,
        query: str = "",
        kinds: Annotated[list[ResourceKind] | None, Query(alias="kind")] = None,
    ) -> dict[str, Any]:
        principal = authenticate(request)
        control = TestControl(plans=plans, jobs=jobs, principal=principal)
        result = await control.search_catalog(
            query=query,
            kinds=set(kinds) if kinds is not None else None,
        )
        return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    @application.post("/v1/catalog/captures", status_code=201)
    async def publish_capture(
        request: Request,
        name: Annotated[str, Query(min_length=1, max_length=256)],
        description: Annotated[str | None, Query(max_length=512)] = None,
    ) -> dict[str, Any]:
        principal = authenticate(request, require_operator=True)
        maximum_bytes = 1_073_741_824
        received = 0
        with SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b") as source:
            async for chunk in request.stream():
                received += len(chunk)
                if received > maximum_bytes:
                    raise TrexCliError(
                        code="INVALID_DOCUMENT",
                        message="capture exceeds the 1 GiB publication limit",
                        category="INPUT",
                    )
                source.write(chunk)
            source.seek(0)
            control = TestControl(plans=plans, jobs=jobs, principal=principal)
            result = await control.publish_capture(
                name=name,
                source=cast(BinaryIO, source),
                description=description,
            )
        return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    @application.get("/v1/catalog/{kind}/{resource_ref:path}")
    async def describe_resource(
        kind: ResourceKind, resource_ref: str, request: Request
    ) -> dict[str, Any]:
        principal = authenticate(request)
        control = TestControl(plans=plans, jobs=jobs, principal=principal)
        result = await control.describe_resource(f"{kind}/{resource_ref}")
        return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    @application.post("/v1/plans", status_code=201)
    async def plan_test(
        request: Request,
        intent: Annotated[
            TrafficTestIntent
            | Rfc2544TestIntent
            | PcapReplayIntent
            | StatefulReplayIntent
            | CaptureWorkloadIntent
            | UdpWorkloadIntent
            | DnsStormIntent
            | DhcpStormIntent
            | ArpStormIntent,
            Body(discriminator="kind"),
        ],
    ) -> dict[str, Any]:
        principal = authenticate(request)
        control = TestControl(plans=plans, jobs=jobs, principal=principal)
        result = await control.plan_test(intent)
        return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    @application.post("/v1/plans/{plan_id}:start", status_code=202)
    async def start_test(plan_id: str, request: Request) -> dict[str, Any]:
        principal = authenticate(request, require_operator=True)
        control = TestControl(plans=plans, jobs=jobs, principal=principal)
        result = await control.start_test(plan_id)
        return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    @application.get("/v1/tests/{job_id}")
    async def get_test(
        job_id: str,
        request: Request,
        after_revision: Annotated[int | None, Query(alias="afterRevision", ge=0)] = None,
        wait_seconds: Annotated[float, Query(alias="waitSeconds", ge=0, le=30)] = 0,
    ) -> dict[str, Any]:
        principal = authenticate(request)
        control = TestControl(plans=plans, jobs=jobs, principal=principal)
        result = await control.get_test(
            job_id,
            after_revision=after_revision,
            wait_seconds=wait_seconds,
        )
        return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    @application.post("/v1/tests/{job_id}:control", status_code=202)
    async def control_test(job_id: str, request: Request, command: CancelTest) -> dict[str, Any]:
        principal = authenticate(request, require_operator=True)
        control = TestControl(plans=plans, jobs=jobs, principal=principal)
        result = await control.control_test(job_id, command)
        return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    @application.get("/v1/calibrations")
    async def list_calibrations(request: Request) -> dict[str, Any]:
        authenticate(request)
        return {"items": await database.list_calibrations()}

    @application.get("/v1/jobs/{job_id}")
    async def get_job(job_id: str, request: Request) -> dict[str, Any]:
        authenticate(request)
        snapshot = await jobs.get(job_id)
        return snapshot.model_dump(mode="json", by_alias=True, exclude_none=True)

    @application.get("/v1/jobs/{job_id}/events")
    async def observe_job(
        job_id: str,
        request: Request,
        after_revision: Annotated[int | None, Query(alias="after_revision", ge=0)] = None,
        last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
    ) -> StreamingResponse:
        authenticate(request)
        cursor = after_revision
        if cursor is None and last_event_id is not None:
            try:
                cursor = int(last_event_id)
            except ValueError as error:
                raise TrexCliError(
                    code="INVALID_DOCUMENT",
                    message="Last-Event-ID must be an integer revision",
                    category="INPUT",
                ) from error

        async def stream() -> AsyncIterator[str]:
            async for snapshot in jobs.observe(job_id, cursor):
                if await request.is_disconnected():
                    return
                data = snapshot.model_dump_json(by_alias=True, exclude_none=True)
                yield f"id: {snapshot.revision}\nevent: snapshot\ndata: {data}\n\n"

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @application.post("/v1/jobs/{job_id}:cancel", status_code=202)
    async def cancel_job(
        job_id: str,
        request: Request,
        body: CancelBody,
    ) -> dict[str, Any]:
        principal = authenticate(request, require_operator=True)
        snapshot = await jobs.cancel(
            job_id,
            body.cancel_request_id,
            body.reason,
            principal=principal,
        )
        return snapshot.model_dump(mode="json", by_alias=True, exclude_none=True)

    @application.get("/v1/artifacts/{digest}")
    async def get_artifact(digest: str, request: Request) -> FileResponse:
        authenticate(request)
        path, media_type, _size = await jobs.artifact(digest)
        return FileResponse(path, media_type=media_type, filename=digest.removeprefix("sha256:"))

    @application.post("/v1/maintenance/artifacts:cleanup")
    async def cleanup_artifacts(
        request: Request, body: ArtifactCleanupBody
    ) -> dict[str, Any]:
        authenticate(request, require_operator=True)
        report = await artifacts.cleanup(
            dry_run=body.dry_run,
            delete_orphans=body.delete_orphans,
        )
        metrics.observe_cleanup(
            dry_run=report.dry_run,
            failed=bool(report.failures),
            deleted_records=report.deleted_records,
            reclaimed_bytes=report.reclaimed_bytes,
        )
        _LOGGER.info(
            "artifact_cleanup",
            extra={
                "dryRun": report.dry_run,
                "deleteOrphans": body.delete_orphans,
                "expiredRecords": report.expired_records,
                "deletedRecords": report.deleted_records,
                "missingFiles": report.missing_files,
                "orphanFiles": report.orphan_files,
                "deletedOrphans": report.deleted_orphans,
                "reclaimedBytes": report.reclaimed_bytes,
                "failureCount": len(report.failures),
            },
        )
        return report.payload()

    @application.post("/v1/maintenance/auth:reload")
    async def reload_authentication(request: Request) -> dict[str, Any]:
        principal = authenticate(request, require_operator=True)
        try:
            await to_thread(config.resolve_secrets)
        except (OSError, UnicodeError, ValueError) as error:
            _LOGGER.error(
                "authentication_reload_failed",
                extra={"principal": principal.name, "error": str(error)},
            )
            raise TrexCliError(
                code="CREDENTIAL_RELOAD_FAILED",
                message=(
                    "authentication credentials could not be reloaded; "
                    "prior credentials remain active"
                ),
                category="RESOURCE",
                retryable=True,
            ) from error
        _LOGGER.info(
            "authentication_reloaded",
            extra={"principal": principal.name, "credentialCount": len(config.auth.tokens)},
        )
        return {
            "status": "reloaded",
            "credentials": [
                {"name": token.name, "role": token.role} for token in config.auth.tokens
            ],
        }

    return application


def _status_for(code: str) -> int:
    return {
        "INVALID_DOCUMENT": 400,
        "UNSUPPORTED_VERSION": 400,
        "UNSAFE_REQUEST": 400,
        "UNAUTHENTICATED": 401,
        "PERMISSION_DENIED": 403,
        "NOT_FOUND": 404,
        "IDEMPOTENCY_CONFLICT": 409,
        "EVENT_CURSOR_EXPIRED": 410,
        "AGENT_NOT_READY": 503,
        "CREDENTIAL_RELOAD_FAILED": 503,
    }.get(code, 500)


def _route_template(request: Request) -> str:
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return str(path) if path is not None else "unmatched"


def _transport_security(config: AgentConfig) -> str:
    return "tls" if config.tls is not None else "insecure-http"

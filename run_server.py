#!/usr/bin/env python3
"""BIG-IP Protocol Performance Tuner — FastAPI application entry point.

Serves:
  - /api/*          FastAPI JSON routes
  - /*              React SPA (frontend/dist) with SPA fallback for client-side routing
  - Dev port 8001  / Container port 8000 (overridden by PORT env-var)
"""

from __future__ import annotations

import logging
import os
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Body, Depends, FastAPI, HTTPException, Path as FPath
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.bigip_client import BigIpClient
from backend.config import (
    FRONTEND_DIST_DIR,
    GRAFANA_EXTERNAL_URL,
    VICTORIAMETRICS_URL,
    ensure_config_dir,
)
from backend.models import (
    AnalysisRequest,
    AnalysisRunResponse,
    BigIpDeviceSummary,
    ConnectBigIpRequest,
    EnrollmentUpdateRequest,
    RemediationApplyRequest,
    RemediationRecord,
    ScheduleAuditEntry,
    ScheduleCreateRequest,
    StorageSettings,
    StorageStatusResponse,
    TuningSchedule,
)
from backend.optimizer.analyzer import ProtocolAnalyzer
from backend.otel_exporter import OtelMetricsExporter
from backend.session_store import SessionStore
from backend.storage_manager import enforce_storage_limits, get_victoriametrics_disk_usage
from backend.vm_client import VictoriaMetricsClient

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("tuner")

# ---------------------------------------------------------------------------
# Global singletons (initialised in lifespan)
# ---------------------------------------------------------------------------
_store: SessionStore
_otel: OtelMetricsExporter
_vm: VictoriaMetricsClient
_analyzer: ProtocolAnalyzer
_scheduler: BackgroundScheduler
_clients: dict[str, BigIpClient] = {}
_clients_lock = threading.Lock()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_or_create_client(session_id: str) -> BigIpClient:
    with _clients_lock:
        if session_id not in _clients:
            rec = _store.get_session(session_id)
            if not rec:
                raise HTTPException(status_code=404, detail=f"BIG-IP session {session_id} not found")
            username, password = _store.get_decrypted_credentials(session_id)
            client = BigIpClient(
                session_id=session_id,
                host=rec["host"],
                port=int(rec.get("port", 443)),
                username=username,
                password=password,
                verify_ssl=bool(rec.get("verify_ssl", False)),
                enable_tmctl=bool(rec.get("enable_tmctl", False)),
                demo_mode=bool(rec.get("demo_mode", False)),
            )
            client.authenticate()
            _clients[session_id] = client
        return _clients[session_id]


def _scheduled_poll_job() -> None:
    """Periodic telemetry poll for all registered BIG-IPs."""
    with _clients_lock:
        active_ids = list(_clients.keys())
    for session_id in active_ids:
        try:
            client = _get_or_create_client(session_id)
            enrolled = _store.get_enrolled_vs(session_id)
            samples = client.poll_protocol_telemetry(enrolled)
            _otel.export_samples(samples)
        except Exception as exc:
            logger.warning("Telemetry poll failed for %s: %s", session_id, exc)


def _scheduled_analysis_job(schedule_id: str) -> None:
    """APScheduler job: run analysis and optionally auto-remediate per schedule config."""
    schedule: TuningSchedule | None = None
    for s in _store.list_schedules():
        if s.id == schedule_id:
            schedule = s
            break
    if not schedule or not schedule.enabled:
        return

    recs_found = 0
    recs_applied = 0
    summary_parts: list[str] = []

    target_ids = schedule.bigip_ids or [rec["id"] for rec in _store.list_sessions()]
    for session_id in target_ids:
        try:
            client = _get_or_create_client(session_id)
            enrolled = _store.get_enrolled_vs(session_id)
            recs, vs_count, source = _analyzer.analyze_device(
                client=client,
                enrolled_paths=enrolled,
                target_vs_filter=set(schedule.virtual_servers) if schedule.virtual_servers else None,
                protocols=set(schedule.protocols),  # type: ignore[arg-type]
                window=schedule.analysis_window,
            )
            recs_found += len(recs)
            if schedule.mode == "auto_remediate":
                min_conf = {"High": 3, "Medium": 2, "Low": 1}[schedule.min_confidence]
                for rec in recs:
                    if min_conf <= {"High": 3, "Medium": 2, "Low": 1}[rec.confidence]:
                        try:
                            _apply_single_remediation(client, rec)
                            recs_applied += 1
                        except Exception as exc:
                            logger.warning("Auto-remediation failed for %s: %s", rec.id, exc)
            summary_parts.append(f"{client.host}: {len(recs)} recs (src={source})")
        except Exception as exc:
            logger.warning("Scheduled analysis failed for session %s: %s", session_id, exc)
            summary_parts.append(f"session {session_id}: ERROR {exc}")

    schedule.last_run_at = _utc_now_iso()
    schedule.last_recommendations_count = recs_found
    schedule.last_applied_count = recs_applied
    _store.upsert_schedule(schedule)
    _store.append_schedule_audit(
        ScheduleAuditEntry(
            timestamp=_utc_now_iso(),
            schedule_id=schedule_id,
            schedule_name=schedule.name,
            mode=schedule.mode,
            recommendations_found=recs_found,
            remediations_applied=recs_applied,
            summary="; ".join(summary_parts) or "No devices processed",
        )
    )


def _apply_single_remediation(
    client: BigIpClient, rec: Any, operator_note: str | None = None
) -> None:
    """Apply a single TuningRecommendation via ProfileRemediator and persist the record."""
    from backend.optimizer.remediator import ProfileRemediator
    remediator = ProfileRemediator()
    record = remediator.apply(client, rec, operator_note=operator_note)
    _store.add_remediation_record(record)

    try:
        _emit_grafana_annotation(client.host, rec.virtual_server, rec.protocol, record.change_id)
    except Exception:
        pass


def _emit_grafana_annotation(bigip_host: str, vs: str, protocol: str, change_id: str) -> None:
    from backend.config import GRAFANA_INTERNAL_URL
    payload = {
        "dashboardUID": "bigip-protocol-tuning",
        "time": int(datetime.now(timezone.utc).timestamp() * 1000),
        "tags": ["remediation", "bigip-tuner", protocol],
        "text": f"Tuning applied: {bigip_host} / {vs} [{protocol}] — {change_id}",
    }
    httpx.post(
        f"{GRAFANA_INTERNAL_URL}/api/annotations",
        json=payload,
        auth=("admin", os.environ.get("GF_SECURITY_ADMIN_PASSWORD", "admin")),
        timeout=5.0,
    )


# ---------------------------------------------------------------------------
# Lifespan (startup / shutdown)
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _store, _otel, _vm, _analyzer, _scheduler

    ensure_config_dir()
    _store = SessionStore()
    _otel = OtelMetricsExporter()
    _vm = VictoriaMetricsClient(base_url=VICTORIAMETRICS_URL)
    _analyzer = ProtocolAnalyzer(vm_client=_vm, otel_exporter=_otel)

    settings = _store.get_storage_settings()
    _otel.set_endpoint(settings.otel_endpoint)

    # Reconnect all persisted sessions
    for rec in _store.list_sessions():
        try:
            _get_or_create_client(rec["id"])
            logger.info("Reconnected session %s (%s)", rec["id"], rec["host"])
        except Exception as exc:
            logger.warning("Could not auto-reconnect %s: %s", rec.get("host", rec["id"]), exc)

    # Kick off background scheduler
    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(
        _scheduled_poll_job,
        "interval",
        seconds=settings.poll_interval_seconds,
        id="telemetry_poll",
        replace_existing=True,
    )
    _scheduler.add_job(
        lambda: enforce_storage_limits(_store),
        "interval",
        minutes=15,
        id="storage_enforce",
        replace_existing=True,
    )
    # Register persisted APScheduler jobs
    for sched in _store.list_schedules():
        if sched.enabled:
            _register_apscheduler_job(sched)

    _scheduler.start()
    logger.info("Scheduler started — telemetry poll every %ds", settings.poll_interval_seconds)
    yield
    _scheduler.shutdown(wait=False)


def _register_apscheduler_job(sched: TuningSchedule) -> None:
    if _scheduler.get_job(sched.id):
        _scheduler.remove_job(sched.id)
    if not sched.enabled:
        return
    if sched.schedule_type == "cron" and sched.cron_expression:
        parts = sched.cron_expression.split()
        if len(parts) == 5:
            _scheduler.add_job(
                _scheduled_analysis_job,
                "cron",
                args=[sched.id],
                minute=parts[1],
                hour=parts[2],
                day=parts[3],
                month=parts[4],
                day_of_week=parts[0],
                id=sched.id,
                replace_existing=True,
            )
    else:
        _scheduler.add_job(
            _scheduled_analysis_job,
            "interval",
            hours=sched.interval_hours,
            args=[sched.id],
            id=sched.id,
            replace_existing=True,
        )


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="BIG-IP Protocol Performance Tuner",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# BIG-IP Connection & Discovery
# ---------------------------------------------------------------------------

@app.post("/api/connect", response_model=BigIpDeviceSummary)
def connect_bigip(req: ConnectBigIpRequest):
    """Register and authenticate a BIG-IP device."""
    # Pre-auth to discover identity fields
    temp_client = BigIpClient(
        session_id="temp",
        host=req.host,
        port=req.port,
        username=req.username,
        password=req.password,
        verify_ssl=req.verify_ssl,
        enable_tmctl=req.enable_tmctl,
        demo_mode=req.demo_mode,
    )
    try:
        temp_client.authenticate()
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"BIG-IP authentication failed: {exc}")

    # Identity fields are populated on the client object by authenticate()
    rec = _store.upsert_session(
        host=req.host,
        port=req.port,
        username=req.username,
        password=req.password,
        verify_ssl=req.verify_ssl,
        enable_tmctl=req.enable_tmctl,
        demo_mode=req.demo_mode,
        label=req.label,
        hostname=temp_client.hostname,
        version=temp_client.version,
        platform=temp_client.platform,
    )
    sid = rec["id"]
    temp_client.session_id = sid

    with _clients_lock:
        _clients[sid] = temp_client

    enrolled = _store.get_enrolled_vs(sid) or []
    vs_list = []
    try:
        all_vs = temp_client.discover_virtual_servers(None)
        if not enrolled:
            enrolled = [vs.full_path for vs in all_vs]
            _store.set_enrolled_vs(sid, enrolled)
        vs_list = all_vs
    except Exception as exc:
        logger.warning("VS discovery failed for %s: %s", req.host, exc)

    return BigIpDeviceSummary(
        id=sid,
        host=req.host,
        port=req.port,
        username=req.username,
        label=rec.get("label"),
        verify_ssl=req.verify_ssl,
        enable_tmctl=req.enable_tmctl,
        demo_mode=req.demo_mode,
        connected=True,
        hostname=temp_client.hostname,
        version=temp_client.version,
        platform=temp_client.platform,
        virtual_servers=vs_list,
        enrolled_count=len(enrolled),
    )


@app.get("/api/bigips", response_model=list[BigIpDeviceSummary])
def list_bigips():
    """List all registered BIG-IP sessions with connection status."""
    result = []
    for rec in _store.list_sessions():
        sid = rec["id"]
        connected = False
        hostname = rec.get("hostname")
        version = rec.get("version")
        platform = rec.get("platform")
        vs_list = []
        enrolled = _store.get_enrolled_vs(sid) or []
        last_error = None

        with _clients_lock:
            client = _clients.get(sid)

        if client:
            connected = client.connected
            if connected:
                try:
                    vs_list = client.discover_virtual_servers(enrolled if enrolled else None)
                except Exception as exc:
                    last_error = str(exc)

        result.append(
            BigIpDeviceSummary(
                id=sid,
                host=rec["host"],
                port=int(rec.get("port", 443)),
                username=rec.get("username", "admin"),
                label=rec.get("label"),
                verify_ssl=bool(rec.get("verify_ssl", False)),
                enable_tmctl=bool(rec.get("enable_tmctl", False)),
                demo_mode=bool(rec.get("demo_mode", False)),
                connected=connected,
                hostname=hostname,
                version=version,
                platform=platform,
                last_error=last_error,
                virtual_servers=vs_list,
                enrolled_count=len(enrolled),
            )
        )
    return result


@app.delete("/api/session/{session_id}")
def remove_session(session_id: str = FPath(...)):
    with _clients_lock:
        client = _clients.pop(session_id, None)
    if client:
        try:
            client.logout()
        except Exception:
            pass
    removed = _store.remove_session(session_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"removed": session_id}


@app.put("/api/session/{session_id}/enrollment")
def update_enrollment(session_id: str, req: EnrollmentUpdateRequest):
    """Set which Virtual Servers on a BIG-IP are enrolled for monitoring and tuning."""
    if not _store.get_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    enrolled = _store.set_enrolled_vs(session_id, req.enrolled_virtual_servers)
    return {"session_id": session_id, "enrolled_count": len(enrolled), "enrolled": enrolled}


# ---------------------------------------------------------------------------
# Analysis & Remediation
# ---------------------------------------------------------------------------

@app.post("/api/analyze/run", response_model=AnalysisRunResponse)
def run_analysis(req: AnalysisRequest):
    """Run on-the-fly traffic analysis and generate tuning recommendations."""
    target_ids = req.bigip_ids or [r["id"] for r in _store.list_sessions()]
    all_recs = []
    total_vs = 0
    sources_seen = set()

    for session_id in target_ids:
        try:
            client = _get_or_create_client(session_id)
        except HTTPException:
            continue
        enrolled = _store.get_enrolled_vs(session_id)
        vs_filter = set(req.virtual_servers) if req.virtual_servers else None
        recs, vs_count, source = _analyzer.analyze_device(
            client=client,
            enrolled_paths=enrolled,
            target_vs_filter=vs_filter,
            protocols=set(req.protocols),  # type: ignore[arg-type]
            window=req.window,
        )
        all_recs.extend(recs)
        total_vs += vs_count
        sources_seen.add(source)

    return AnalysisRunResponse(
        run_id=f"run-{uuid.uuid4().hex[:10]}",
        window=req.window,
        analyzed_at=_utc_now_iso(),
        bigip_count=len(target_ids),
        virtual_server_count=total_vs,
        recommendations=all_recs,
        telemetry_source=", ".join(sorted(sources_seen)) or "none",
    )


@app.post("/api/remediate/apply")
def apply_remediation(req: RemediationApplyRequest):
    """Apply selected recommendations to BIG-IP(s) via iControl REST."""
    applied_ids: list[str] = []
    errors: list[dict] = []

    for rec in req.recommendations:
        try:
            client = _get_or_create_client(rec.bigip_id)
            _apply_single_remediation(client, rec, operator_note=req.operator_note)
            applied_ids.append(rec.id)
        except Exception as exc:
            errors.append({"recommendation_id": rec.id, "error": str(exc)})

    return {"applied_count": len(applied_ids), "applied": applied_ids, "errors": errors}


@app.post("/api/remediate/rollback/{change_id}")
def rollback_remediation(change_id: str = FPath(...)):
    """Roll back a previously applied remediation to its pre-snapshot state."""
    record = _store.get_remediation_record(change_id)
    if not record:
        raise HTTPException(status_code=404, detail="Remediation record not found")
    if record.status == "rolled_back":
        raise HTTPException(status_code=409, detail="Already rolled back")

    try:
        from backend.optimizer.remediator import ProfileRemediator
        client = _get_or_create_client(record.bigip_id)
        record = ProfileRemediator().rollback(client, record)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Rollback failed: {exc}")

    _store.update_remediation_record(record)
    return record


@app.get("/api/remediate/history")
def remediation_history(limit: int = 100):
    return [r.model_dump() for r in _store.list_remediation_records(limit=min(limit, 500))]


# ---------------------------------------------------------------------------
# Schedules
# ---------------------------------------------------------------------------

@app.post("/api/schedules", response_model=TuningSchedule)
def create_schedule(req: ScheduleCreateRequest):
    sched = TuningSchedule(
        **req.model_dump(),
        id=f"sched-{uuid.uuid4().hex[:10]}",
        created_at=_utc_now_iso(),
    )
    _store.upsert_schedule(sched)
    if sched.enabled:
        _register_apscheduler_job(sched)
    return sched


@app.get("/api/schedules", response_model=list[TuningSchedule])
def list_schedules():
    schedules = _store.list_schedules()
    # Enrich with next_run_at from APScheduler
    for sched in schedules:
        job = _scheduler.get_job(sched.id)
        if job and job.next_run_time:
            sched.next_run_at = job.next_run_time.isoformat()
    return schedules


@app.patch("/api/schedules/{schedule_id}")
def update_schedule(schedule_id: str, updates: dict = Body(...)):
    schedules = _store.list_schedules()
    sched = next((s for s in schedules if s.id == schedule_id), None)
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    updated = sched.model_copy(update=updates)
    _store.upsert_schedule(updated)
    _register_apscheduler_job(updated)
    return updated


@app.delete("/api/schedules/{schedule_id}")
def delete_schedule(schedule_id: str = FPath(...)):
    if _scheduler.get_job(schedule_id):
        _scheduler.remove_job(schedule_id)
    removed = _store.delete_schedule(schedule_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"removed": schedule_id}


@app.get("/api/schedules/audit")
def schedule_audit(limit: int = 50):
    return [e.model_dump() for e in _store.list_schedule_audit(limit=min(limit, 250))]


# ---------------------------------------------------------------------------
# Storage & Settings
# ---------------------------------------------------------------------------

@app.get("/api/storage/status", response_model=StorageStatusResponse)
def storage_status():
    settings = _store.get_storage_settings()
    used_bytes, _ = get_victoriametrics_disk_usage()
    max_bytes = int(settings.max_storage_gb * 1024 * 1024 * 1024)
    used_mb = used_bytes / (1024 * 1024)
    pct = (used_bytes / max_bytes * 100) if max_bytes > 0 else 0.0

    # Check VM health
    vm_ok = False
    vm_series = 0
    otel_ok = False
    try:
        vm_ok = _vm.is_healthy()
        if vm_ok:
            vm_series = _vm.query_scalar("count(bigip_vs_cur_conns)") or 0  # type: ignore[assignment]
    except Exception:
        pass
    try:
        httpx.get(settings.otel_endpoint.replace("/v1/metrics", ""), timeout=2.0)
        otel_ok = True
    except Exception:
        pass

    last_enforced, enforcement_actions = _store.get_storage_enforcement_meta()
    return StorageStatusResponse(
        settings=settings,
        used_bytes=used_bytes,
        used_mb=round(used_mb, 2),
        max_gb=settings.max_storage_gb,
        utilization_pct=round(pct, 2),
        active_series=int(vm_series),
        vm_healthy=vm_ok,
        otel_healthy=otel_ok,
        last_enforced_at=last_enforced,
        enforcement_actions=enforcement_actions,
    )


@app.put("/api/storage/settings", response_model=StorageSettings)
def update_storage_settings(settings: StorageSettings):
    saved = _store.update_storage_settings(settings)
    # Update poll interval in scheduler
    _otel.set_endpoint(settings.otel_endpoint)
    if _scheduler.get_job("telemetry_poll"):
        _scheduler.reschedule_job(
            "telemetry_poll",
            trigger="interval",
            seconds=settings.poll_interval_seconds,
        )
    return saved


# ---------------------------------------------------------------------------
# Health & Info
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "version": "1.0.0",
        "bigips_connected": len(_clients),
        "vm_url": VICTORIAMETRICS_URL,
        "grafana_url": GRAFANA_EXTERNAL_URL,
    }


# ---------------------------------------------------------------------------
# React SPA static file serving
# ---------------------------------------------------------------------------

if FRONTEND_DIST_DIR.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST_DIR / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str):
        index = FRONTEND_DIST_DIR / "index.html"
        return FileResponse(index)
else:
    @app.get("/", include_in_schema=False)
    def root():
        return {"message": "BIG-IP Protocol Performance Tuner API", "docs": "/api/docs"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8001"))
    uvicorn.run("run_server:app", host="0.0.0.0", port=port, reload=False)

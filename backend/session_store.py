"""Encrypted BIG-IP session store and persistent application state manager."""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from backend.config import (
    DEFAULT_DEDUP_MIN_SCRAPE_INTERVAL,
    DEFAULT_MAX_STORAGE_GB,
    DEFAULT_POLL_INTERVAL_SECONDS,
    DEFAULT_RETENTION_PERIOD,
    GRAFANA_EXTERNAL_URL,
    KEY_FILE,
    OTEL_COLLECTOR_OTLP_HTTP_URL,
    SESSIONS_FILE,
    STATE_FILE,
    VM_RUNTIME_ENV_FILE,
    ensure_config_dir,
)
from backend.models import (
    RemediationRecord,
    ScheduleAuditEntry,
    StorageSettings,
    TuningSchedule,
)

logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _secure_write_file(path: Path, content: bytes, mode: int = 0o600) -> None:
    """Atomically write file and enforce strict permissions."""
    ensure_config_dir()
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "wb") as fh:
        fh.write(content)
    try:
        os.chmod(tmp_path, mode)
    except OSError as exc:
        logger.debug("Could not chmod %s: %s", tmp_path, exc)
    os.replace(tmp_path, path)


class SessionStore:
    """Persists registered BIG-IP sessions with Fernet-encrypted passwords at rest.

    Auth tokens (X-F5-Auth-Token) are NEVER persisted to disk; they live strictly
    in memory inside BigIpClient instances.
    """

    def __init__(
        self,
        sessions_file: Path = SESSIONS_FILE,
        key_file: Path = KEY_FILE,
        state_file: Path = STATE_FILE,
    ) -> None:
        self.sessions_file = sessions_file
        self.key_file = key_file
        self.state_file = state_file
        self._lock = threading.RLock()
        self._fernet = self._init_fernet()
        self._sessions: dict[str, dict[str, Any]] = {}
        self._state: dict[str, Any] = self._default_state()
        self._load_all()

    def _init_fernet(self) -> Fernet:
        ensure_config_dir()
        env_key = os.environ.get("BIGIP_SESSION_ENCRYPTION_KEY", "").strip()
        if env_key:
            return Fernet(env_key.encode("utf-8"))

        if self.key_file.exists():
            key_bytes = self.key_file.read_bytes().strip()
            try:
                os.chmod(self.key_file, 0o600)
            except OSError:
                pass
            return Fernet(key_bytes)

        new_key = Fernet.generate_key()
        _secure_write_file(self.key_file, new_key, mode=0o600)
        logger.info("Generated new Fernet session encryption key at %s", self.key_file)
        return Fernet(new_key)

    def _default_state(self) -> dict[str, Any]:
        return {
            "enrollments": {},  # {bigip_id: ["/Common/vip_1", ...]}
            "remediations": [],  # list of RemediationRecord dicts
            "schedules": [],  # list of TuningSchedule dicts
            "schedule_audit": [],  # list of ScheduleAuditEntry dicts
            "storage_settings": StorageSettings(
                retention_period=DEFAULT_RETENTION_PERIOD,
                max_storage_gb=DEFAULT_MAX_STORAGE_GB,
                poll_interval_seconds=DEFAULT_POLL_INTERVAL_SECONDS,
                dedup_min_scrape_interval=DEFAULT_DEDUP_MIN_SCRAPE_INTERVAL,
                otel_endpoint=OTEL_COLLECTOR_OTLP_HTTP_URL,
                grafana_external_url=GRAFANA_EXTERNAL_URL,
                auto_prune_enabled=True,
            ).model_dump(),
            "storage_enforcement_log": [],
            "last_storage_enforced_at": None,
        }

    def _load_all(self) -> None:
        with self._lock:
            if self.sessions_file.exists():
                try:
                    raw = json.loads(self.sessions_file.read_text(encoding="utf-8"))
                    if isinstance(raw, dict):
                        self._sessions = raw
                    elif isinstance(raw, list):
                        self._sessions = {item["id"]: item for item in raw if "id" in item}
                except Exception as exc:
                    logger.error("Failed reading %s: %s", self.sessions_file, exc)

            if self.state_file.exists():
                try:
                    loaded = json.loads(self.state_file.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        merged = self._default_state()
                        merged.update(loaded)
                        self._state = merged
                except Exception as exc:
                    logger.error("Failed reading %s: %s", self.state_file, exc)

    def _save_sessions(self) -> None:
        payload = json.dumps(self._sessions, indent=2).encode("utf-8")
        _secure_write_file(self.sessions_file, payload, mode=0o600)

    def _save_state(self) -> None:
        payload = json.dumps(self._state, indent=2).encode("utf-8")
        _secure_write_file(self.state_file, payload, mode=0o600)

    def encrypt_secret(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt_secret(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Unable to decrypt stored BIG-IP session password; key mismatch.") from exc

    def upsert_session(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        verify_ssl: bool = False,
        enable_tmctl: bool = False,
        demo_mode: bool = False,
        label: str | None = None,
        hostname: str | None = None,
        version: str | None = None,
        platform: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            existing_id: str | None = None
            for sid, record in self._sessions.items():
                if record.get("host") == host and int(record.get("port", 443)) == int(port):
                    existing_id = sid
                    break

            session_id = existing_id or f"bigip-{uuid.uuid4().hex[:10]}"
            encrypted_pw = self.encrypt_secret(password)
            record = {
                "id": session_id,
                "host": host,
                "port": port,
                "username": username,
                "encrypted_password": encrypted_pw,
                "verify_ssl": verify_ssl,
                "enable_tmctl": enable_tmctl,
                "demo_mode": demo_mode,
                "label": label or hostname or host,
                "hostname": hostname,
                "version": version,
                "platform": platform,
                "updated_at": _utc_now_iso(),
            }
            self._sessions[session_id] = record
            self._save_sessions()
            return record

    def list_sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(v) for v in self._sessions.values()]

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            rec = self._sessions.get(session_id)
            return dict(rec) if rec else None

    def get_decrypted_credentials(self, session_id: str) -> tuple[str, str]:
        with self._lock:
            rec = self._sessions.get(session_id)
            if not rec:
                raise KeyError(f"BIG-IP session {session_id} not found")
            return rec["username"], self.decrypt_secret(rec["encrypted_password"])

    def remove_session(self, session_id: str) -> bool:
        with self._lock:
            existed = session_id in self._sessions
            self._sessions.pop(session_id, None)
            self._state.get("enrollments", {}).pop(session_id, None)
            if existed:
                self._save_sessions()
                self._save_state()
            return existed

    # --- Enrollment management ---
    def get_enrolled_vs(self, session_id: str) -> list[str] | None:
        with self._lock:
            enrolled = self._state.get("enrollments", {}).get(session_id)
            return list(enrolled) if enrolled is not None else None

    def set_enrolled_vs(self, session_id: str, vs_full_paths: list[str]) -> list[str]:
        with self._lock:
            deduped = sorted(set(vs_full_paths))
            self._state.setdefault("enrollments", {})[session_id] = deduped
            self._save_state()
            return deduped

    # --- Remediation history & snapshots ---
    def add_remediation_record(self, record: RemediationRecord) -> None:
        with self._lock:
            records: list[dict[str, Any]] = self._state.setdefault("remediations", [])
            records.insert(0, record.model_dump())
            # Keep bounded history (up to 500 records)
            del records[500:]
            self._save_state()

    def update_remediation_record(self, record: RemediationRecord) -> None:
        with self._lock:
            records: list[dict[str, Any]] = self._state.setdefault("remediations", [])
            for idx, existing in enumerate(records):
                if existing.get("change_id") == record.change_id:
                    records[idx] = record.model_dump()
                    self._save_state()
                    return
            records.insert(0, record.model_dump())
            self._save_state()

    def get_remediation_record(self, change_id: str) -> RemediationRecord | None:
        with self._lock:
            for item in self._state.get("remediations", []):
                if item.get("change_id") == change_id:
                    return RemediationRecord(**item)
            return None

    def list_remediation_records(self, limit: int = 100) -> list[RemediationRecord]:
        with self._lock:
            return [RemediationRecord(**item) for item in self._state.get("remediations", [])[:limit]]

    # --- Schedules & audit trail ---
    def list_schedules(self) -> list[TuningSchedule]:
        with self._lock:
            return [TuningSchedule(**item) for item in self._state.get("schedules", [])]

    def upsert_schedule(self, schedule: TuningSchedule) -> TuningSchedule:
        with self._lock:
            schedules: list[dict[str, Any]] = self._state.setdefault("schedules", [])
            for idx, existing in enumerate(schedules):
                if existing.get("id") == schedule.id:
                    schedules[idx] = schedule.model_dump()
                    self._save_state()
                    return schedule
            schedules.append(schedule.model_dump())
            self._save_state()
            return schedule

    def delete_schedule(self, schedule_id: str) -> bool:
        with self._lock:
            schedules: list[dict[str, Any]] = self._state.setdefault("schedules", [])
            before = len(schedules)
            self._state["schedules"] = [s for s in schedules if s.get("id") != schedule_id]
            if len(self._state["schedules"]) != before:
                self._save_state()
                return True
            return False

    def append_schedule_audit(self, entry: ScheduleAuditEntry) -> None:
        with self._lock:
            audit: list[dict[str, Any]] = self._state.setdefault("schedule_audit", [])
            audit.insert(0, entry.model_dump())
            del audit[250:]
            self._save_state()

    def list_schedule_audit(self, limit: int = 50) -> list[ScheduleAuditEntry]:
        with self._lock:
            return [ScheduleAuditEntry(**item) for item in self._state.get("schedule_audit", [])[:limit]]

    # --- Storage & Telemetry settings ---
    def get_storage_settings(self) -> StorageSettings:
        with self._lock:
            raw = self._state.get("storage_settings") or {}
            return StorageSettings(**{**self._default_state()["storage_settings"], **raw})

    def update_storage_settings(self, settings: StorageSettings) -> StorageSettings:
        with self._lock:
            self._state["storage_settings"] = settings.model_dump()
            self._save_state()
            # Also write shared VictoriaMetrics runtime env file so container restarts honor updated flags
            env_lines = (
                f"VM_RETENTION_PERIOD={settings.retention_period}\n"
                f"VM_DEDUP_INTERVAL={settings.dedup_min_scrape_interval}\n"
                f"VM_MAX_STORAGE_GB={settings.max_storage_gb}\n"
            ).encode("utf-8")
            try:
                _secure_write_file(VM_RUNTIME_ENV_FILE, env_lines, mode=0o640)
            except OSError as exc:
                logger.debug("Unable to write %s: %s", VM_RUNTIME_ENV_FILE, exc)
            return settings

    def record_storage_enforcement(self, actions: list[str]) -> None:
        with self._lock:
            now = _utc_now_iso()
            self._state["last_storage_enforced_at"] = now
            if actions:
                log_entries: list[str] = self._state.setdefault("storage_enforcement_log", [])
                for act in actions:
                    log_entries.insert(0, f"[{now}] {act}")
                del log_entries[50:]
            self._save_state()

    def get_storage_enforcement_meta(self) -> tuple[str | None, list[str]]:
        with self._lock:
            return (
                self._state.get("last_storage_enforced_at"),
                list(self._state.get("storage_enforcement_log", [])[:15]),
            )

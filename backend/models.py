"""Pydantic data models for API requests, responses, and persisted state."""

from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field


ProtocolType = Literal["tcp", "udp", "http"]
ProfileContext = Literal["clientside", "serverside", "all"]
ConfidenceScore = Literal["High", "Medium", "Low"]
ScheduleMode = Literal["recommend_only", "auto_remediate"]
DiffCategory = Literal["telemetry", "dependency", "hygiene", "security"]


class ConnectBigIpRequest(BaseModel):
    host: str = Field(..., min_length=1, description="BIG-IP management hostname or IP")
    port: int = Field(default=443, ge=1, le=65535)
    username: str = Field(default="admin", min_length=1)
    password: str = Field(..., min_length=1)
    verify_ssl: bool = Field(default=False)
    enable_tmctl: bool = Field(
        default=False,
        description="Optionally collect supplemental tcp_stat/tmm_stat via iControl bash tmctl",
    )
    demo_mode: bool = Field(
        default=False,
        description="Simulated lab BIG-IP mode for offline evaluation and testing",
    )
    label: str | None = Field(default=None, description="Optional friendly device label")


class AttachedProfileRef(BaseModel):
    name: str
    partition: str = "Common"
    full_path: str
    protocol: ProtocolType
    context: ProfileContext = "all"
    defaults_from: str | None = None
    is_system_default: bool = False


class VirtualServerItem(BaseModel):
    name: str
    partition: str = "Common"
    full_path: str
    destination: str = ""
    ip_protocol: str = "tcp"
    pool: str | None = None
    enabled: bool = True
    availability_state: str = "available"
    enrolled: bool = True
    profiles: list[AttachedProfileRef] = Field(default_factory=list)
    has_clientssl: bool = False
    has_serverssl: bool = False
    has_oneconnect: bool = False
    has_apm: bool = False
    has_asm: bool = False
    has_fastl4: bool = False
    irules: list[str] = Field(default_factory=list)
    snat_type: str = "none"


class BigIpDeviceSummary(BaseModel):
    id: str
    host: str
    port: int = 443
    username: str
    label: str | None = None
    verify_ssl: bool = False
    enable_tmctl: bool = False
    demo_mode: bool = False
    connected: bool = False
    hostname: str | None = None
    version: str | None = None
    platform: str | None = None
    last_poll_at: str | None = None
    last_error: str | None = None
    token_expires_at: str | None = None
    virtual_servers: list[VirtualServerItem] = Field(default_factory=list)
    enrolled_count: int = 0


class EnrollmentUpdateRequest(BaseModel):
    enrolled_virtual_servers: list[str] = Field(
        ..., description="List of Virtual Server full paths (e.g. /Common/vip_web) to monitor and tune"
    )


class AnalysisRequest(BaseModel):
    bigip_ids: list[str] = Field(default_factory=list, description="Target BIG-IP session IDs (empty = all)")
    virtual_servers: list[str] = Field(
        default_factory=list, description="Target VS full paths (empty = all enrolled)"
    )
    protocols: list[ProtocolType] = Field(default_factory=lambda: ["tcp", "udp", "http"])
    window: str = Field(default="24h", pattern=r"^\d+(m|h|d|w)$")


class ParameterDiff(BaseModel):
    parameter: str
    gui_name: str | None = None
    section: str | None = None
    current_value: Any
    recommended_value: Any
    unit: str | None = None
    rationale: str
    category: DiffCategory = "telemetry"
    safe_auto_apply: bool = True


class TuningRecommendation(BaseModel):
    id: str
    bigip_id: str
    bigip_host: str
    virtual_server: str
    partition: str
    protocol: ProtocolType
    context: Literal["clientside", "serverside"]
    profile_name: str
    profile_full_path: str
    is_system_default_profile: bool
    recommended_parent_profile: str | None = None
    target_profile_action: Literal["update_custom_profile", "create_and_attach_child_profile"]
    suggested_profile_name: str
    parameter_diffs: list[ParameterDiff]
    advisories: list[str] = Field(default_factory=list)
    settings_evaluated: int = 0
    supporting_evidence: str
    metrics_snapshot: dict[str, float] = Field(default_factory=dict)
    f5_kb_id: str
    f5_kb_title: str
    f5_kb_url: str
    confidence: ConfidenceScore
    impact: ConfidenceScore
    safe_auto_apply: bool = True
    generated_at: str


class AnalysisRunResponse(BaseModel):
    run_id: str
    window: str
    analyzed_at: str
    bigip_count: int
    virtual_server_count: int
    recommendations: list[TuningRecommendation]
    telemetry_source: str


class RemediationApplyRequest(BaseModel):
    recommendations: list[TuningRecommendation]
    operator_note: str | None = None


class RemediationRecord(BaseModel):
    change_id: str
    applied_at: str
    status: Literal["applied", "rolled_back", "failed"]
    bigip_id: str
    bigip_host: str
    virtual_server: str
    partition: str
    protocol: ProtocolType
    context: Literal["clientside", "serverside"]
    original_profile_full_path: str
    applied_profile_full_path: str
    created_child_profile: bool = False
    parameter_changes: dict[str, dict[str, Any]] = Field(default_factory=dict)
    pre_snapshot: dict[str, Any] = Field(default_factory=dict)
    f5_kb_id: str = ""
    operator_note: str | None = None
    rolled_back_at: str | None = None
    error_message: str | None = None


class ScheduleCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    schedule_type: Literal["interval", "cron"] = "interval"
    interval_hours: int = Field(default=6, ge=1, le=168)
    cron_expression: str | None = Field(
        default=None,
        description="5-field cron expression (min hour day month dow) when schedule_type=cron",
    )
    bigip_ids: list[str] = Field(default_factory=list)
    virtual_servers: list[str] = Field(default_factory=list)
    protocols: list[ProtocolType] = Field(default_factory=lambda: ["tcp", "udp", "http"])
    analysis_window: str = Field(default="6h", pattern=r"^\d+(m|h|d|w)$")
    mode: ScheduleMode = "recommend_only"
    min_confidence: ConfidenceScore = "High"
    enabled: bool = True


class ScheduleUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    schedule_type: Literal["interval", "cron"] | None = None
    interval_hours: int | None = Field(default=None, ge=1, le=168)
    cron_expression: str | None = None
    bigip_ids: list[str] | None = None
    virtual_servers: list[str] | None = None
    protocols: list[ProtocolType] | None = None
    analysis_window: str | None = Field(default=None, pattern=r"^\d+(m|h|d|w)$")
    mode: ScheduleMode | None = None
    min_confidence: ConfidenceScore | None = None
    enabled: bool | None = None


class TuningSchedule(ScheduleCreateRequest):
    id: str
    created_at: str
    last_run_at: str | None = None
    next_run_at: str | None = None
    last_recommendations_count: int = 0
    last_applied_count: int = 0


class ScheduleAuditEntry(BaseModel):
    timestamp: str
    schedule_id: str
    schedule_name: str
    mode: ScheduleMode
    recommendations_found: int
    remediations_applied: int
    summary: str


class StorageSettings(BaseModel):
    retention_period: str = Field(default="30d", pattern=r"^\d+(d|w|m|y)$")
    max_storage_gb: float = Field(default=10.0, ge=0.25, le=10000.0)
    poll_interval_seconds: int = Field(default=30, ge=5, le=3600)
    dedup_min_scrape_interval: str = Field(default="15s", pattern=r"^\d+(s|m)$")
    otel_endpoint: str = Field(default="http://localhost:4318/v1/metrics")
    grafana_external_url: str = Field(default="http://localhost:3000")
    auto_prune_enabled: bool = True


class StorageStatusResponse(BaseModel):
    settings: StorageSettings
    used_bytes: int
    used_mb: float
    max_gb: float
    utilization_pct: float
    active_series: int = 0
    vm_healthy: bool = False
    otel_healthy: bool = False
    last_enforced_at: str | None = None
    enforcement_actions: list[str] = Field(default_factory=list)

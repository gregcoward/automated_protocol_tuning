"""Safe iControl REST Remediator — creates child profiles instead of mutating system defaults."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from backend.bigip_client import normalize_profile_attachment, split_full_path
from backend.models import ProtocolType, RemediationRecord, TuningRecommendation

if TYPE_CHECKING:
    from backend.bigip_client import BigIpClient

logger = logging.getLogger(__name__)


def _get_nested_val(data: dict[str, Any], dotted_key: str, default: Any = None) -> Any:
    cur: Any = data
    for part in dotted_key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


class ProfileRemediator:
    """
    Applies TuningRecommendations to a BIG-IP via iControl REST.

    Rules:
    - Never PATCH a system-default profile directly (BigIpClient.patch_profile enforces this).
    - Always create (or update) a child profile inheriting from the target parent, then swap the VS attachment.
    - Preserves 'all' context on HTTP/UDP profiles and splits/coalesces 'all' context cleanly on TCP profiles.
    - Stores a pre-snapshot so rollback can restore previous state safely even out-of-order.
    """

    def apply(
        self,
        client: "BigIpClient",
        rec: TuningRecommendation,
        operator_note: str | None = None,
    ) -> RemediationRecord:
        """Apply a single TuningRecommendation and return a RemediationRecord."""
        now = datetime.now(timezone.utc).isoformat()
        change_id = str(uuid.uuid4())

        params = {diff.parameter: diff.recommended_value for diff in rec.parameter_diffs}
        pre_snapshot: dict[str, Any] = {}
        applied_full_path = rec.profile_full_path
        created_child = False

        try:
            try:
                pre_snapshot = client.get_profile_config(rec.protocol, rec.profile_full_path)
            except Exception:
                pre_snapshot = {}

            if rec.target_profile_action == "create_and_attach_child_profile":
                defaults_from = rec.recommended_parent_profile or rec.profile_full_path
                child_name = rec.suggested_profile_name
                partition = rec.partition

                orig_ctx = self._create_and_attach_child(
                    client=client,
                    protocol=rec.protocol,
                    partition=partition,
                    child_name=child_name,
                    defaults_from=defaults_from,
                    params=params,
                    vs_full_path=rec.virtual_server,
                    context=rec.context,
                    replace_full_path=rec.profile_full_path,
                )
                pre_snapshot["__original_vs_context__"] = orig_ctx
                applied_full_path = f"/{partition}/{child_name}"
                created_child = True
            else:
                nested = self._flatten_params_dict(params)
                # Mirror maxRequests if legacy top-level key also exists in custom HTTP profile
                if rec.protocol == "http" and "enforcement.maxRequests" in params and "maxRequests" in pre_snapshot:
                    nested["maxRequests"] = params["enforcement.maxRequests"]
                client.patch_profile(rec.protocol, rec.profile_full_path, nested)

        except Exception as exc:
            logger.error("Remediation failed for rec_id=%s: %s", rec.id, exc)
            return RemediationRecord(
                change_id=change_id,
                applied_at=now,
                status="failed",
                bigip_id=rec.bigip_id,
                bigip_host=rec.bigip_host,
                virtual_server=rec.virtual_server,
                partition=rec.partition,
                protocol=rec.protocol,
                context=rec.context,
                original_profile_full_path=rec.profile_full_path,
                applied_profile_full_path=rec.profile_full_path,
                created_child_profile=False,
                parameter_changes={
                    d.parameter: {"before": d.current_value, "after": d.recommended_value}
                    for d in rec.parameter_diffs
                },
                pre_snapshot=pre_snapshot,
                f5_kb_id=rec.f5_kb_id,
                operator_note=operator_note,
                error_message=str(exc),
            )

        return RemediationRecord(
            change_id=change_id,
            applied_at=now,
            status="applied",
            bigip_id=rec.bigip_id,
            bigip_host=rec.bigip_host,
            virtual_server=rec.virtual_server,
            partition=rec.partition,
            protocol=rec.protocol,
            context=rec.context,
            original_profile_full_path=rec.profile_full_path,
            applied_profile_full_path=applied_full_path,
            created_child_profile=created_child,
            parameter_changes={
                d.parameter: {"before": d.current_value, "after": d.recommended_value}
                for d in rec.parameter_diffs
            },
            pre_snapshot=pre_snapshot,
            f5_kb_id=rec.f5_kb_id,
            operator_note=operator_note,
        )

    def rollback(
        self,
        client: "BigIpClient",
        record: RemediationRecord,
    ) -> RemediationRecord:
        """Roll back a previously applied RemediationRecord."""
        now = datetime.now(timezone.utc).isoformat()

        try:
            if record.created_child_profile:
                orig_vs_ctx = str((record.pre_snapshot or {}).get("__original_vs_context__", ""))
                self._rollback_vs_profile(
                    client=client,
                    protocol=record.protocol,
                    vs_full_path=record.virtual_server,
                    context=record.context,
                    applied_full_path=record.applied_profile_full_path,
                    original_full_path=record.original_profile_full_path,
                    original_vs_context=orig_vs_ctx,
                )
                try:
                    client.delete_profile(record.protocol, record.applied_profile_full_path)
                except Exception as exc:
                    logger.warning("Could not delete child profile during rollback: %s", exc)
            else:
                restore_params: dict[str, Any] = {}
                for param, before_after in record.parameter_changes.items():
                    fallback_before = before_after.get("before")
                    restore_params[param] = (
                        _get_nested_val(record.pre_snapshot, param, fallback_before)
                        if record.pre_snapshot
                        else fallback_before
                    )
                nested = self._flatten_params_dict(restore_params)
                if (
                    record.protocol == "http"
                    and "enforcement.maxRequests" in restore_params
                    and record.pre_snapshot
                    and "maxRequests" in record.pre_snapshot
                ):
                    nested["maxRequests"] = restore_params["enforcement.maxRequests"]
                client.patch_profile(record.protocol, record.original_profile_full_path, nested)

        except Exception as exc:
            logger.error("Rollback failed for change_id=%s: %s", record.change_id, exc)
            record.status = "failed"
            record.error_message = f"Rollback error: {exc}"
            return record

        record.status = "rolled_back"
        record.rolled_back_at = now
        record.error_message = None
        return record

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _create_and_attach_child(
        self,
        client: "BigIpClient",
        protocol: ProtocolType,
        partition: str,
        child_name: str,
        defaults_from: str,
        params: dict[str, Any],
        vs_full_path: str,
        context: str,
        replace_full_path: str,
    ) -> str:
        """Create (or update if existing) a child profile and attach it cleanly to the VS."""
        nested_params = self._flatten_params_dict(params)
        new_full_path = f"/{partition}/{child_name}"

        if client.profile_exists(protocol, new_full_path):
            patch_body = dict(nested_params)
            patch_body["defaultsFrom"] = defaults_from
            client.patch_profile(protocol, new_full_path, patch_body)
        else:
            payload = dict(nested_params)
            payload["name"] = child_name
            payload["partition"] = partition
            payload["defaultsFrom"] = defaults_from
            client.create_profile(protocol, payload)

        return self._swap_vs_profile(
            client=client,
            protocol=protocol,
            vs_full_path=vs_full_path,
            context=context,
            old_full_path=replace_full_path,
            new_full_path=new_full_path,
        )

    def _swap_vs_profile(
        self,
        client: "BigIpClient",
        protocol: ProtocolType,
        vs_full_path: str,
        context: str,
        old_full_path: str,
        new_full_path: str,
    ) -> str:
        """Replace old_full_path with new_full_path on a Virtual Server, respecting context semantics."""
        raw_profiles = client.get_virtual_server_raw_profiles(vs_full_path)
        new_part, new_name = split_full_path(new_full_path)
        old_part, old_name = split_full_path(old_full_path)

        updated: list[dict[str, Any]] = []
        swapped = False
        original_vs_ctx = context

        for raw_entry in raw_profiles:
            entry = normalize_profile_attachment(raw_entry)
            entry_fp = entry["fullPath"]
            entry_ctx = entry["context"]

            if not swapped and entry_fp in (old_full_path, new_full_path):
                if protocol in ("http", "udp"):
                    # HTTP and UDP profiles attach with context='all' (preserve existing context)
                    original_vs_ctx = entry_ctx
                    updated.append(
                        {
                            "name": new_name,
                            "partition": new_part,
                            "fullPath": new_full_path,
                            "context": entry_ctx,
                        }
                    )
                    swapped = True
                    continue

                # TCP profile attachment: match exact side or split 'all' cleanly into clientside + serverside
                if entry_ctx == context:
                    original_vs_ctx = entry_ctx
                    updated.append(
                        {
                            "name": new_name,
                            "partition": new_part,
                            "fullPath": new_full_path,
                            "context": context,
                        }
                    )
                    swapped = True
                    continue

                if entry_ctx == "all":
                    original_vs_ctx = "all"
                    opposite_ctx = "serverside" if context == "clientside" else "clientside"
                    updated.append(
                        {
                            "name": new_name,
                            "partition": new_part,
                            "fullPath": new_full_path,
                            "context": context,
                        }
                    )
                    updated.append(
                        {
                            "name": old_name,
                            "partition": old_part,
                            "fullPath": old_full_path,
                            "context": opposite_ctx,
                        }
                    )
                    swapped = True
                    continue

            updated.append(entry)

        if not swapped:
            attach_ctx = "all" if protocol in ("http", "udp") else context
            updated.append(
                {
                    "name": new_name,
                    "partition": new_part,
                    "fullPath": new_full_path,
                    "context": attach_ctx,
                }
            )

        client.update_virtual_server_profiles(vs_full_path, updated)
        return original_vs_ctx

    def _rollback_vs_profile(
        self,
        client: "BigIpClient",
        protocol: ProtocolType,
        vs_full_path: str,
        context: str,
        applied_full_path: str,
        original_full_path: str,
        original_vs_context: str,
    ) -> None:
        """Restore original_full_path on VS and coalesce split TCP 'all' attachments if applicable."""
        raw_profiles = client.get_virtual_server_raw_profiles(vs_full_path)
        orig_part, orig_name = split_full_path(original_full_path)

        updated: list[dict[str, Any]] = []
        restored = False
        for raw_entry in raw_profiles:
            entry = normalize_profile_attachment(raw_entry)
            if not restored and entry["fullPath"] == applied_full_path:
                if protocol in ("http", "udp") or entry["context"] in (context, "all"):
                    updated.append(
                        {
                            "name": orig_name,
                            "partition": orig_part,
                            "fullPath": original_full_path,
                            "context": entry["context"],
                        }
                    )
                    restored = True
                    continue
            updated.append(entry)

        # If TCP was originally attached with context='all' and both sides now point to original_full_path, coalesce
        if protocol == "tcp" and original_vs_context == "all":
            matching = [e for e in updated if e["fullPath"] == original_full_path]
            contexts = {e["context"] for e in matching}
            if {"clientside", "serverside"}.issubset(contexts):
                coalesced = [e for e in updated if e["fullPath"] != original_full_path]
                coalesced.append(
                    {
                        "name": orig_name,
                        "partition": orig_part,
                        "fullPath": original_full_path,
                        "context": "all",
                    }
                )
                updated = coalesced

        client.update_virtual_server_profiles(vs_full_path, updated)

    @staticmethod
    def _flatten_params_dict(params: dict[str, Any]) -> dict[str, Any]:
        """
        Convert dotted-key params into nested dicts for iControl REST PATCH bodies.
        e.g. {"enforcement.maxHeaderSize": 65536} -> {"enforcement": {"maxHeaderSize": 65536}}
        """
        result: dict[str, Any] = {}
        for key, value in params.items():
            parts = key.split(".", 1)
            if len(parts) == 2:
                top, rest = parts
                if top not in result or not isinstance(result[top], dict):
                    result[top] = {}
                nested = ProfileRemediator._flatten_params_dict({rest: value})
                result[top].update(nested)
            else:
                result[key] = value
        return result

"""Safe iControl REST Remediator — creates child profiles instead of mutating system defaults."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from backend.models import RemediationRecord, TuningRecommendation

if TYPE_CHECKING:
    from backend.bigip_client import BigIpClient

logger = logging.getLogger(__name__)


class ProfileRemediator:
    """
    Applies TuningRecommendations to a BIG-IP via iControl REST.

    Rules:
    - Never PATCH a system-default profile directly (BigIpClient.patch_profile enforces this).
    - Always create a child profile inheriting from the target, then swap the VS attachment.
    - Stores a pre-snapshot so rollback can restore previous state.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

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
            # Always capture the current profile state before touching anything
            try:
                pre_snapshot = client.get_profile_config(rec.protocol, rec.profile_full_path)
            except Exception:
                pre_snapshot = {}

            if rec.target_profile_action == "create_and_attach_child_profile":
                defaults_from = rec.recommended_parent_profile or rec.profile_full_path
                child_name = rec.suggested_profile_name
                partition = rec.partition

                self._create_and_attach_child(
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
                applied_full_path = f"/{partition}/{child_name}"
                created_child = True

            else:
                # update_custom_profile — PATCH in place (never a system default)
                nested = self._flatten_params_dict(params)
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
                # Swap the VS back to the original profile; orphan child is left in place
                self._swap_vs_profile(
                    client=client,
                    protocol=record.protocol,
                    vs_full_path=record.virtual_server,
                    context=record.context,
                    old_full_path=record.applied_profile_full_path,
                    new_full_path=record.original_profile_full_path,
                )
                # Attempt to delete the child profile; non-fatal if it fails
                try:
                    client.request(
                        "DELETE",
                        f"/mgmt/tm/ltm/profile/{record.protocol}/"
                        + _full_path_to_rest_id(record.applied_profile_full_path),
                    )
                except Exception as exc:
                    logger.warning("Could not delete orphan child profile during rollback: %s", exc)
            else:
                # Restore previous parameter values
                restore_params: dict[str, Any] = {}
                for param, before_after in record.parameter_changes.items():
                    restore_params[param] = (
                        record.pre_snapshot.get(param, before_after["before"])
                        if record.pre_snapshot
                        else before_after["before"]
                    )
                nested = self._flatten_params_dict(restore_params)
                client.patch_profile(record.protocol, record.original_profile_full_path, nested)

        except Exception as exc:
            logger.error("Rollback failed for change_id=%s: %s", record.change_id, exc)
            record.status = "failed"
            record.error_message = f"Rollback error: {exc}"
            return record

        record.status = "rolled_back"
        record.rolled_back_at = now
        return record

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _create_and_attach_child(
        self,
        client: "BigIpClient",
        protocol: str,
        partition: str,
        child_name: str,
        defaults_from: str,
        params: dict[str, Any],
        vs_full_path: str,
        context: str,
        replace_full_path: str,
    ) -> None:
        """Create a child profile inheriting from defaults_from, apply params, then attach to VS."""
        payload = self._flatten_params_dict(params)
        payload["name"] = child_name
        payload["partition"] = partition
        payload["defaultsFrom"] = defaults_from

        client.create_profile(protocol, payload)

        new_full_path = f"/{partition}/{child_name}"
        self._swap_vs_profile(
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
        protocol: str,
        vs_full_path: str,
        context: str,
        old_full_path: str,
        new_full_path: str,
    ) -> None:
        """Replace old_full_path with new_full_path in a VS's profile list."""
        raw_profiles = client.get_virtual_server_raw_profiles(vs_full_path)

        updated = []
        swapped = False
        for entry in raw_profiles:
            entry_fp = entry.get("fullPath") or f"/{entry.get('partition', 'Common')}/{entry['name']}"
            if entry_fp == old_full_path:
                updated.append({"name": new_full_path, "context": context})
                swapped = True
            else:
                updated.append(entry)

        if not swapped:
            updated.append({"name": new_full_path, "context": context})

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


def _full_path_to_rest_id(full_path: str) -> str:
    """Convert /Partition/name → ~Partition~name for iControl REST URLs."""
    return full_path.lstrip("/").replace("/", "~")

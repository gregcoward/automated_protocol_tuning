"""End-to-end unit & API tests for BIG-IP Protocol Performance Tuner."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

# Point config dir to an isolated temporary directory before importing run_server
_TMP_DIR = tempfile.TemporaryDirectory()
os.environ["TUNER_CONFIG_DIR"] = _TMP_DIR.name

from fastapi.testclient import TestClient

from backend.bigip_client import BigIpClient, _default_http_profile_dict, _default_tcp_profile_dict, _default_udp_profile_dict
from backend.optimizer.analyzer import ProtocolAnalyzer
from backend.optimizer.knowledge_base import KNOWLEDGE_BASE
from backend.optimizer.remediator import ProfileRemediator
from backend.optimizer.settings_catalog import ALL_PROFILE_SETTINGS, HTTP_SETTINGS, TCP_SETTINGS, UDP_SETTINGS
from backend.otel_exporter import OtelMetricsExporter
from backend.vm_client import VictoriaMetricsClient
import run_server


class TestCatalogAndOptimizer(unittest.TestCase):
    def test_catalog_completeness_and_kb_links(self) -> None:
        self.assertGreaterEqual(len(TCP_SETTINGS), 76)
        self.assertEqual(len(UDP_SETTINGS), 9)
        self.assertGreaterEqual(len(HTTP_SETTINGS), 50)
        self.assertGreaterEqual(len(ALL_PROFILE_SETTINGS), 135)
        for spec in ALL_PROFILE_SETTINGS:
            self.assertIn(
                spec.f5_kb_id,
                KNOWLEDGE_BASE,
                f"Missing KB {spec.f5_kb_id} for {spec.protocol}:{spec.rest_key}",
            )

    def test_demo_analysis_remediation_and_rollback(self) -> None:
        client = BigIpClient(session_id="test-demo", host="10.0.0.10", demo_mode=True)
        client.authenticate()
        otel = OtelMetricsExporter(endpoint="http://127.0.0.1:59999/v1/metrics")
        vm = VictoriaMetricsClient(base_url="http://127.0.0.1:59998")
        analyzer = ProtocolAnalyzer(vm_client=vm, otel_exporter=otel)

        recs, vs_count, src = analyzer.analyze_device(
            client=client,
            enrolled_paths=None,
            target_vs_filter=None,
            protocols={"tcp", "udp", "http"},
            window="1h",
        )
        self.assertEqual(vs_count, 3)
        self.assertEqual(src, "live_poll_buffer")
        self.assertGreaterEqual(len(recs), 4)

        remediator = ProfileRemediator()
        applied_records = []
        for rec in recs:
            self.assertGreater(rec.settings_evaluated, 0)
            record = remediator.apply(client, rec, operator_note="unit-test")
            self.assertEqual(record.status, "applied", record.error_message)
            applied_records.append(record)

        # Ensure subsequent discovery & telemetry polling succeed cleanly after profile swaps
        discovered = client.discover_virtual_servers()
        self.assertEqual(len(discovered), 3)
        samples = client.poll_protocol_telemetry()
        self.assertGreater(len(samples), 0)

        # Verify HTTP profile attachment preserved context='all'
        ecomm_profs = client.get_virtual_server_raw_profiles("/Common/vip_ecommerce_https")
        http_entries = [p for p in ecomm_profs if "http" in p["name"]]
        self.assertTrue(all(p["context"] == "all" for p in http_entries))

        # Roll back all changes in reverse order and verify clean restoration
        for record in reversed(applied_records):
            rb = remediator.rollback(client, record)
            self.assertEqual(rb.status, "rolled_back", rb.error_message)

        restored_ecomm = {p["fullPath"] for p in client.get_virtual_server_raw_profiles("/Common/vip_ecommerce_https")}
        self.assertIn("/Common/tcp", restored_ecomm)
        self.assertIn("/Common/http", restored_ecomm)

    def test_tcp_all_context_split_and_coalesce_on_rollback(self) -> None:
        client = BigIpClient(session_id="test-split", host="10.0.0.11", demo_mode=True)
        client.authenticate()
        assert client._simulator is not None
        # Configure a Virtual Server with a single TCP profile attached with context='all'
        client._simulator.virtual_servers["/Common/vip_ecommerce_https"]["profiles"] = [
            {"name": "tcp", "partition": "Common", "fullPath": "/Common/tcp", "context": "all"},
        ]

        otel = OtelMetricsExporter(endpoint="http://127.0.0.1:59999/v1/metrics")
        vm = VictoriaMetricsClient(base_url="http://127.0.0.1:59998")
        analyzer = ProtocolAnalyzer(vm_client=vm, otel_exporter=otel)
        recs, _, _ = analyzer.analyze_device(
            client=client,
            enrolled_paths=["/Common/vip_ecommerce_https"],
            target_vs_filter=None,
            protocols={"tcp"},
            window="1h",
        )
        cli_rec = next(r for r in recs if r.context == "clientside")
        remediator = ProfileRemediator()
        rec_applied = remediator.apply(client, cli_rec)
        self.assertEqual(rec_applied.status, "applied")

        profs_after = client.get_virtual_server_raw_profiles("/Common/vip_ecommerce_https")
        by_ctx = {p["context"]: p["fullPath"] for p in profs_after}
        self.assertEqual(by_ctx["clientside"], rec_applied.applied_profile_full_path)
        self.assertEqual(by_ctx["serverside"], "/Common/tcp")

        rb = remediator.rollback(client, rec_applied)
        self.assertEqual(rb.status, "rolled_back")
        profs_restored = client.get_virtual_server_raw_profiles("/Common/vip_ecommerce_https")
        self.assertEqual(len(profs_restored), 1)
        self.assertEqual(profs_restored[0]["fullPath"], "/Common/tcp")
        self.assertEqual(profs_restored[0]["context"], "all")

    def test_comprehensive_tcp_mptcp_udp_http_rules(self) -> None:
        client = BigIpClient(session_id="test-rules", host="10.0.0.12", demo_mode=True)
        client.authenticate()
        assert client._simulator is not None

        # Inject a custom TCP profile with MPTCP enabled + multiple hygiene/dependency issues
        mp_prof = _default_tcp_profile_dict("tcp_mptcp_custom", "/Common/tcp")
        mp_prof.update(
            {
                "mptcp": "enabled",
                "mptcpFallback": "reset",
                "mptcpFastjoin": "disabled",
                "mptcpSubflowmax": 0,
                "mptcpRxmitmin": 1000,
                "mptcpMakeafterbreak": "enabled",
                "mptcpJoin": "disabled",
                "verifiedAccept": "enabled",
                "selectiveNack": "enabled",
                "earlyRetransmit": "disabled",
                "limitedTransmit": "disabled",
                "enhancedLossRecovery": "disabled",
                "zeroWindowTimeout": "indefinite",
                "synCookieWhitelist": "enabled",
            }
        )
        client._simulator.profiles["tcp"]["/Common/tcp_mptcp_custom"] = mp_prof

        # Inject custom HTTP profile with HSTS preload, LWS wrap, unknownMethod=reject without PATCH, sFlow
        http_prof = _default_http_profile_dict("http_edge_custom", "/Common/http")
        http_prof["headerInsert"] = "X-Custom-Security-Trace-Identifier: " + ("A" * 90)
        http_prof["lwsSeparator"] = "sp"
        http_prof["redirectRewrite"] = "all"
        http_prof["enforcement"]["unknownMethod"] = "reject"
        http_prof["enforcement"]["allowWsHeaderName"] = "enabled"
        http_prof["hsts"] = {
            "mode": "enabled",
            "maximumAge": 86400,
            "includeSubdomains": "disabled",
            "preload": "enabled",
        }
        http_prof["sflow"] = {
            "pollInterval": 2,
            "pollIntervalGlobal": "no",
            "samplingRate": 16,
            "samplingRateGlobal": "no",
        }
        client._simulator.profiles["http"]["/Common/http_edge_custom"] = http_prof

        # Inject stateful QUIC UDP VIP on :443 with bufferMaxPackets > 0
        udp_prof = _default_udp_profile_dict("udp_quic_custom", "/Common/udp")
        udp_prof["bufferMaxPackets"] = 32
        udp_prof["idleTimeout"] = "indefinite"
        client._simulator.profiles["udp"]["/Common/udp_quic_custom"] = udp_prof

        client._simulator.virtual_servers["/Common/vip_ecommerce_https"]["profiles"] = [
            {"name": "tcp_mptcp_custom", "partition": "Common", "fullPath": "/Common/tcp_mptcp_custom", "context": "clientside"},
            {"name": "f5-tcp-lan", "partition": "Common", "fullPath": "/Common/f5-tcp-lan", "context": "serverside"},
            {"name": "http_edge_custom", "partition": "Common", "fullPath": "/Common/http_edge_custom", "context": "all"},
            {"name": "clientssl", "partition": "Common", "fullPath": "/Common/clientssl", "context": "clientside"},
        ]
        client._simulator.virtual_servers["/Common/vip_telemetry_udp_ingest"]["destination"] = "/Common/10.20.10.88:443"
        client._simulator.virtual_servers["/Common/vip_telemetry_udp_ingest"]["profiles"] = [
            {"name": "udp_quic_custom", "partition": "Common", "fullPath": "/Common/udp_quic_custom", "context": "all"},
        ]

        otel = OtelMetricsExporter(endpoint="http://127.0.0.1:59999/v1/metrics")
        vm = VictoriaMetricsClient(base_url="http://127.0.0.1:59998")
        analyzer = ProtocolAnalyzer(vm_client=vm, otel_exporter=otel)
        recs, _, _ = analyzer.analyze_device(
            client=client,
            enrolled_paths=["/Common/vip_ecommerce_https", "/Common/vip_telemetry_udp_ingest"],
            target_vs_filter=None,
            protocols={"tcp", "udp", "http"},
            window="1h",
        )

        tcp_rec = next(r for r in recs if r.protocol == "tcp" and r.context == "clientside")
        tcp_params = {d.parameter: d.recommended_value for d in tcp_rec.parameter_diffs}
        self.assertEqual(tcp_params["mptcpFallback"], "accept")
        self.assertEqual(tcp_params["mptcpSubflowmax"], 6)
        self.assertEqual(tcp_params["mptcpJoin"], "enabled")
        self.assertEqual(tcp_params["verifiedAccept"], "disabled")
        self.assertEqual(tcp_params["selectiveNack"], "disabled")
        self.assertEqual(tcp_params["zeroWindowTimeout"], 20000)
        self.assertEqual(tcp_params["synCookieWhitelist"], "disabled")
        self.assertFalse(tcp_rec.safe_auto_apply)

        http_rec = next(r for r in recs if r.protocol == "http")
        http_params = {d.parameter: d.recommended_value for d in http_rec.parameter_diffs}
        self.assertEqual(http_params["lwsWidth"], 1024)
        self.assertEqual(http_params["redirectRewrite"], "matching")
        self.assertEqual(http_params["enforcement.allowWsHeaderName"], "disabled")
        self.assertIn("PATCH", http_params["enforcement.knownMethods"])
        self.assertEqual(http_params["hsts.maximumAge"], 31536000)
        self.assertEqual(http_params["hsts.includeSubdomains"], "enabled")
        self.assertEqual(http_params["sflow.pollInterval"], 10)
        self.assertGreater(len(http_rec.advisories), 0)

        udp_rec = next(r for r in recs if r.protocol == "udp")
        udp_params = {d.parameter: d.recommended_value for d in udp_rec.parameter_diffs}
        # Stateful port :443 should NOT enable datagramLoadBalancing, and SHOULD fix bufferMaxPackets + bufferMaxBytes
        self.assertNotIn("datagramLoadBalancing", udp_params)
        self.assertEqual(udp_params["bufferMaxPackets"], 0)
        self.assertGreaterEqual(udp_params["bufferMaxBytes"], 2097152)
        self.assertEqual(udp_params["idleTimeout"], 30)


class TestFastApiEndpoints(unittest.TestCase):
    def test_api_lifecycle(self) -> None:
        with TestClient(run_server.app) as api_client:
            # Health & catalogs
            r = api_client.get("/api/health")
            self.assertEqual(r.status_code, 200)
            r_cat = api_client.get("/api/profile-settings")
            self.assertEqual(r_cat.status_code, 200)
            self.assertGreaterEqual(len(r_cat.json()), 135)

            # Connect demo BIG-IP
            r_conn = api_client.post(
                "/api/connect",
                json={
                    "host": "192.0.2.10",
                    "port": 443,
                    "username": "admin",
                    "password": "secret",
                    "demo_mode": True,
                    "label": "Demo Lab",
                },
            )
            self.assertEqual(r_conn.status_code, 200, r_conn.text)
            bigip_id = r_conn.json()["id"]

            # Filtered analysis (verifies virtual_servers filter works)
            r_an = api_client.post(
                "/api/analyze/run",
                json={
                    "bigip_ids": [bigip_id],
                    "virtual_servers": ["/Common/vip_telemetry_udp_ingest"],
                    "protocols": ["tcp", "udp", "http"],
                    "window": "1h",
                },
            )
            self.assertEqual(r_an.status_code, 200, r_an.text)
            body = r_an.json()
            self.assertEqual(body["virtual_server_count"], 1)
            self.assertEqual(len(body["recommendations"]), 1)
            self.assertEqual(body["recommendations"][0]["protocol"], "udp")

            # Apply & Rollback via API
            r_app = api_client.post(
                "/api/remediate/apply",
                json={"recommendations": body["recommendations"], "operator_note": "api test"},
            )
            self.assertEqual(r_app.status_code, 200)
            self.assertEqual(r_app.json()["applied_count"], 1)
            self.assertEqual(r_app.json()["errors"], [])

            hist = api_client.get("/api/remediate/history").json()
            self.assertEqual(len(hist), 1)
            change_id = hist[0]["change_id"]

            r_rb = api_client.post(f"/api/remediate/rollback/{change_id}")
            self.assertEqual(r_rb.status_code, 200, r_rb.text)
            self.assertEqual(r_rb.json()["status"], "rolled_back")

            # Cron schedule validation (standard 5-field min hour day month dow)
            r_sched = api_client.post(
                "/api/schedules",
                json={
                    "name": "Nightly 02:30 UTC",
                    "schedule_type": "cron",
                    "cron_expression": "30 2 * * 1-5",
                    "protocols": ["tcp", "http"],
                    "analysis_window": "6h",
                    "mode": "recommend_only",
                    "min_confidence": "High",
                    "enabled": True,
                },
            )
            self.assertEqual(r_sched.status_code, 200, r_sched.text)
            sched_id = r_sched.json()["id"]

            # Invalid cron rejected on PATCH
            r_bad_patch = api_client.patch(f"/api/schedules/{sched_id}", json={"cron_expression": "bad cron"})
            self.assertEqual(r_bad_patch.status_code, 422)

            api_client.delete(f"/api/schedules/{sched_id}")
            r_del = api_client.delete(f"/api/session/{bigip_id}")
            self.assertEqual(r_del.status_code, 200)


if __name__ == "__main__":
    unittest.main()

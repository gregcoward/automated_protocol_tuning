"""F5 TMOS LTM Protocol Tuning Knowledge Base grounded in my.f5.com K-articles."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from backend.models import ConfidenceScore, ProtocolType


@dataclass(frozen=True)
class F5KnowledgeEntry:
    kb_id: str
    title: str
    url: str
    protocol: ProtocolType
    context: str
    parameters: list[str]
    trigger_condition: str
    recommendation_summary: str
    default_impact: ConfidenceScore


KNOWLEDGE_BASE: dict[str, F5KnowledgeEntry] = {
    "K75593415": F5KnowledgeEntry(
        kb_id="K75593415",
        title="Overview of the F5 progressive and WAN/LAN optimized TCP profiles (f5-tcp-wan, f5-tcp-lan, f5-tcp-mobile)",
        url="https://my.f5.com/manage/s/article/K75593415",
        protocol="tcp",
        context="both",
        parameters=["defaultsFrom", "sendBufferSize", "receiveWindowSize", "proxyBufferHigh", "proxyBufferLow"],
        trigger_condition="Virtual Server uses legacy /Common/tcp profile with >25 Mbps throughput or >25 ms WAN RTT.",
        recommendation_summary=(
            "Adopt split-TCP profile architecture: inherit client-side profile from /Common/f5-tcp-wan "
            "(or /Common/f5-tcp-progressive) and server-side profile from /Common/f5-tcp-lan."
        ),
        default_impact="High",
    ),
    "K02412420": F5KnowledgeEntry(
        kb_id="K02412420",
        title="Overview of TCP congestion control algorithms in BIG-IP LTM (BBR, CUBIC, Woodside)",
        url="https://my.f5.com/manage/s/article/K02412420",
        protocol="tcp",
        context="clientside",
        parameters=["congestionControl", "pktLossIgnoreRate", "pktLossIgnoreBurst"],
        trigger_condition="TCP retransmission rate > 2.0% with elevated RTT (>35 ms) or RTT variance (>12 ms).",
        recommendation_summary=(
            "Switch congestionControl to 'bbr' on WAN/mobile client-side profiles to model bottleneck bandwidth "
            "and propagation RTT instead of collapsing cwnd on random packet loss."
        ),
        default_impact="High",
    ),
    "K3422": F5KnowledgeEntry(
        kb_id="K3422",
        title="Overview of content spooling and TCP proxy buffer tuning (proxyBufferHigh, sendBufferSize, receiveWindowSize)",
        url="https://my.f5.com/manage/s/article/K3422",
        protocol="tcp",
        context="both",
        parameters=["sendBufferSize", "receiveWindowSize", "proxyBufferHigh", "proxyBufferLow"],
        trigger_condition="TCP buffer exhaustion waits > 0, zero-window events > 0, or BDP exceeds current sendBufferSize.",
        recommendation_summary=(
            "Right-size sendBufferSize and receiveWindowSize to >= 2x Bandwidth-Delay Product (up to 262144-524288 B) "
            "and align proxyBufferHigh >= sendBufferSize with proxyBufferLow at 75% of proxyBufferHigh."
        ),
        default_impact="High",
    ),
    "K15812": F5KnowledgeEntry(
        kb_id="K15812",
        title="Overview of Nagle's algorithm and Delayed ACKs interaction on interactive TCP workloads",
        url="https://my.f5.com/manage/s/article/K15812",
        protocol="tcp",
        context="both",
        parameters=["nagle", "delayedAcks", "fastOpen"],
        trigger_condition="Small average segment payload (<650 B) with Nagle enabled alongside Delayed ACKs causing 40-200 ms stalls.",
        recommendation_summary=(
            "Set nagle to 'disabled' (for low-latency APIs) or 'progressive', and enable TCP Fast Open where supported."
        ),
        default_impact="High",
    ),
    "K7606": F5KnowledgeEntry(
        kb_id="K7606",
        title="Overview of BIG-IP idle timeouts, TCP keep-alives, and SYN retransmission thresholds",
        url="https://my.f5.com/manage/s/article/K7606",
        protocol="tcp",
        context="both",
        parameters=["idleTimeout", "keepAliveInterval", "synMaxRetrans"],
        trigger_condition="Elevated connection resets, excessive idle connection accumulation, or embryonic SYN backlog.",
        recommendation_summary=(
            "Align TCP idleTimeout (180-300s) and keepAliveInterval (300-600s) to reclaim dead peers cleanly, "
            "and cap synMaxRetrans to 2-3 under SYN churn."
        ),
        default_impact="Medium",
    ),
    "K3605": F5KnowledgeEntry(
        kb_id="K3605",
        title="Configuring UDP Datagram Load Balancing (datagramLoadBalancing) for high-rate stateless flows",
        url="https://my.f5.com/manage/s/article/K3605",
        protocol="udp",
        context="clientside",
        parameters=["datagramLoadBalancing"],
        trigger_condition="UDP datagrams-per-connection ratio > 250 with UDP packet drops or buffer overflows.",
        recommendation_summary=(
            "Enable datagramLoadBalancing ('enabled') on the UDP profile so individual datagrams distribute "
            "evenly across TMM threads and pool members instead of pinning long-lived source tuples."
        ),
        default_impact="High",
    ),
    "K3667": F5KnowledgeEntry(
        kb_id="K3667",
        title="Tuning UDP profile idleTimeout, allowNoPayload, and proxyMss for ephemeral port efficiency",
        url="https://my.f5.com/manage/s/article/K3667",
        protocol="udp",
        context="clientside",
        parameters=["idleTimeout", "proxyMss", "ipTtl", "allowNoPayload"],
        trigger_condition="UDP ephemeral connection table > 8,000 entries with default 60s+ idleTimeout.",
        recommendation_summary=(
            "Reduce UDP idleTimeout to 15-30s for high-churn request/response UDP traffic (DNS/telemetry/QUIC) "
            "to prevent ephemeral port exhaustion and lower TMM connection table memory."
        ),
        default_impact="Medium",
    ),
    "K7208": F5KnowledgeEntry(
        kb_id="K7208",
        title="Optimizing HTTP Keep-Alive connection reuse (maxRequests and oneconnectTransformations)",
        url="https://my.f5.com/manage/s/article/K7208",
        protocol="http",
        context="both",
        parameters=["maxRequests", "oneconnectTransformations"],
        trigger_condition="HTTP keep-alive requests per connection < 10 or restrictive maxRequests (1-100) causing backend TCP/TLS churn.",
        recommendation_summary=(
            "Set maxRequests to 0 (unlimited) or >= 1000 and enable oneconnectTransformations ('enabled') "
            "to maximize L7 keep-alive connection pooling."
        ),
        default_impact="High",
    ),
    "K13525": F5KnowledgeEntry(
        kb_id="K13525",
        title="Configuring HTTP profile enforcement limits (maxHeaderSize, maxHeaderCount) and pipelining hardening",
        url="https://my.f5.com/manage/s/article/K13525",
        protocol="http",
        context="clientside",
        parameters=["enforcement.maxHeaderSize", "enforcement.maxHeaderCount", "pipelining", "insertXforwardedFor"],
        trigger_condition="HTTP header size/count drops > 0 (modern OIDC/JWT headers > 32 KB) or HTTP/1.1 pipelining enabled.",
        recommendation_summary=(
            "Increase enforcement.maxHeaderSize to 65536 B when header drops occur, disable legacy HTTP/1.1 pipelining "
            "in favor of HTTP/2 multiplexing (/Common/http2), and enable insertXforwardedFor for client IP visibility."
        ),
        default_impact="High",
    ),
    "K15434": F5KnowledgeEntry(
        kb_id="K15434",
        title="Overview of HTTP Compression, Web Acceleration (RAM Cache), and HTTP/2 Gateway offload",
        url="https://my.f5.com/manage/s/article/K15434",
        protocol="http",
        context="clientside",
        parameters=["insertXforwardedFor"],
        trigger_condition="Outbound HTTP throughput > 50 Mbps with low compression ratio (<1.3x) or high concurrent streams per client.",
        recommendation_summary=(
            "Pair HTTP profile with /Common/httpcompression and /Common/webacceleration profiles for payload offload, "
            "and attach /Common/http2 on WAN HTTPS Virtual Servers."
        ),
        default_impact="Medium",
    ),
}


TCP_BASE_TEMPLATES: dict[str, dict[str, Any]] = {
    "/Common/f5-tcp-wan": {
        "description": "Optimized for high-latency (>25ms), lossy WAN client connections",
        "sendBufferSize": 262144,
        "receiveWindowSize": 131072,
        "proxyBufferLow": 196608,
        "proxyBufferHigh": 262144,
        "congestionControl": "cubic",
        "nagle": "progressive",
    },
    "/Common/f5-tcp-lan": {
        "description": "Optimized for low-latency (<5ms), high-bandwidth LAN server-side pools",
        "sendBufferSize": 131072,
        "receiveWindowSize": 131072,
        "proxyBufferLow": 98304,
        "proxyBufferHigh": 131072,
        "congestionControl": "woodside",
        "nagle": "disabled",
    },
    "/Common/f5-tcp-mobile": {
        "description": "Optimized for cellular/wireless links with variable RTT and sporadic non-congestive loss",
        "sendBufferSize": 262144,
        "receiveWindowSize": 131072,
        "congestionControl": "bbr",
        "pktLossIgnoreRate": 5000,
        "pktLossIgnoreBurst": 4,
    },
    "/Common/f5-tcp-progressive": {
        "description": "Adaptive baseline profile dynamically scaling buffers across mixed WAN/LAN topologies",
        "sendBufferSize": 131072,
        "receiveWindowSize": 131072,
        "congestionControl": "cubic",
        "nagle": "progressive",
    },
}


def list_knowledge_base() -> list[dict[str, Any]]:
    return [asdict(entry) for entry in KNOWLEDGE_BASE.values()]

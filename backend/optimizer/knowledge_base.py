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
        parameters=[
            "defaultsFrom", "sendBufferSize", "receiveWindowSize", "proxyBufferHigh",
            "proxyBufferLow", "initCwnd", "initRwnd", "dsack",
        ],
        trigger_condition="Virtual Server uses legacy /Common/tcp profile with >25 Mbps throughput or >20 ms WAN RTT.",
        recommendation_summary=(
            "Adopt split-TCP profile architecture: inherit client-side profile from /Common/f5-tcp-wan "
            "(or /Common/f5-tcp-progressive) and server-side profile from /Common/f5-tcp-lan."
        ),
        default_impact="High",
    ),
    "K02412420": F5KnowledgeEntry(
        kb_id="K02412420",
        title="Overview of TCP congestion control algorithms in BIG-IP LTM (BBR, CUBIC, Woodside, CDG, CHD)",
        url="https://my.f5.com/manage/s/article/K02412420",
        protocol="tcp",
        context="both",
        parameters=["congestionControl", "delayWindowControl", "pktLossIgnoreRate", "pktLossIgnoreBurst"],
        trigger_condition="TCP retransmission rate >= 1.5% with elevated RTT (>25 ms) or variance (>10 ms), or legacy CC.",
        recommendation_summary=(
            "Use 'bbr' on lossy/variable-RTT WAN client profiles, 'cubic' on clean high-BDP WAN links, "
            "and 'woodside' on low-latency LAN server-side profiles; disable redundant delayWindowControl/pktLossIgnore* under BBR."
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
            "Right-size sendBufferSize and receiveWindowSize above 2x Bandwidth-Delay Product "
            "and align proxyBufferHigh >= sendBufferSize with proxyBufferLow near 75% of proxyBufferHigh."
        ),
        default_impact="High",
    ),
    "K74421054": F5KnowledgeEntry(
        kb_id="K74421054",
        title="Configuring automatic TCP buffer tuning (autoSendBufferSize, autoReceiveWindowSize, autoProxyBufferSize) and Rate Pacing",
        url="https://my.f5.com/manage/s/article/K74421054",
        protocol="tcp",
        context="clientside",
        parameters=["autoProxyBufferSize", "autoReceiveWindowSize", "autoSendBufferSize", "ratePace", "ratePaceMaxRate"],
        trigger_condition="Mixed WAN/LAN client RTT variance or high concurrent connections where static buffers waste memory.",
        recommendation_summary=(
            "Enable dynamic auto-buffer sizing (autoSendBufferSize, autoReceiveWindowSize, autoProxyBufferSize) "
            "and ratePace='enabled' to dynamically right-size per-flow buffers and smooth micro-bursts."
        ),
        default_impact="High",
    ),
    "K15812": F5KnowledgeEntry(
        kb_id="K15812",
        title="Overview of Nagle's algorithm, Delayed ACKs, Acknowledge on Push, and TCP Fast Open on interactive workloads",
        url="https://my.f5.com/manage/s/article/K15812",
        protocol="tcp",
        context="both",
        parameters=["nagle", "delayedAcks", "ackOnPush", "fastOpen", "fastOpenCookieExpiration"],
        trigger_condition="Small average segment payload (<680 B) with Nagle enabled alongside Delayed ACKs causing 40-200 ms stalls.",
        recommendation_summary=(
            "Set nagle to 'disabled' (for interactive APIs) or 'auto' (for mixed WAN web), ensure ackOnPush='enabled', "
            "and enable client-side TCP Fast Open with sane cookie expiration."
        ),
        default_impact="High",
    ),
    "K7606": F5KnowledgeEntry(
        kb_id="K7606",
        title="Overview of BIG-IP TCP Timer Management, Keep-Alives, RTO floors, and Retransmission thresholds",
        url="https://my.f5.com/manage/s/article/K7606",
        protocol="tcp",
        context="both",
        parameters=[
            "idleTimeout", "keepAliveInterval", "minimumRto", "synRtoBase", "synMaxRetrans", "maxRetrans",
            "closeWaitTimeout", "finWaitTimeout", "finWait_2Timeout", "timeWaitTimeout", "timeWaitRecycle", "resetOnTimeout",
        ],
        trigger_condition="High connection table occupancy, dead-peer accumulation, slow SYN/RTO recovery, or SNAT port pressure.",
        recommendation_summary=(
            "Align keepAliveInterval < idleTimeout on long-lived flows, lower minimumRto (200-300 ms) and synRtoBase (500-1000 ms), "
            "keep resetOnTimeout enabled on serverside, and bound FIN/CLOSE/TIME-WAIT timers."
        ),
        default_impact="Medium",
    ),
    "K14806": F5KnowledgeEntry(
        kb_id="K14806",
        title="Mitigating Slow-Read DoS and managing TCP Zero Window Timeout (zeroWindowTimeout)",
        url="https://my.f5.com/manage/s/article/K14806",
        protocol="tcp",
        context="both",
        parameters=["zeroWindowTimeout"],
        trigger_condition="Client-side zeroWindowTimeout set to indefinite, or elevated zero-window resets on legitimate slow receivers.",
        recommendation_summary=(
            "Avoid indefinite zeroWindowTimeout on client-side VIPs (use 20000 ms default to prevent Slow-Read buffer exhaustion); "
            "raise to 30000-60000 ms only on trusted internal batch receivers."
        ),
        default_impact="Medium",
    ),
    "K7535": F5KnowledgeEntry(
        kb_id="K7535",
        title="Overview of the BIG-IP LTM TCP profile (Connection Setup, Data Transfer, Loss Recovery, and Options)",
        url="https://my.f5.com/manage/s/article/K7535",
        protocol="tcp",
        context="both",
        parameters=[
            "abc", "selectiveAcks", "selectiveNack", "earlyRetransmit", "enhancedLossRecovery",
            "limitedTransmit", "tailLossProbe", "rexmtThresh", "timestamps", "slowStart",
            "cmetricsCache", "cmetricsCacheTimeout", "deferredAccept", "verifiedAccept",
            "proxyMss", "proxyOptions", "pushFlag", "maxSegmentSize", "ipDfMode", "ipTtlMode",
            "ecn", "md5Signature", "ipTosToClient", "linkQosToClient",
        ],
        trigger_condition="Custom TCP profile overrides core RFC loss-recovery/congestion features or introduces VS feature conflicts.",
        recommendation_summary=(
            "Keep ABC, SACK, Timestamps, Slow-Start, Early Retransmit, Limited Transmit, Enhanced Loss Recovery, and Tail Loss Probe enabled; "
            "keep Selective NACK disabled; guard Verified Accept against iRules/APM conflicts; use pushFlag='auto' on high-PPS egress."
        ),
        default_impact="High",
    ),
    "K14776": F5KnowledgeEntry(
        kb_id="K14776",
        title="Overview of SYN Cookie protection and SYN Cookie White List on BIG-IP LTM",
        url="https://my.f5.com/manage/s/article/K14776",
        protocol="tcp",
        context="clientside",
        parameters=["synCookieEnable", "synCookieWhitelist"],
        trigger_condition="SYN Cookie protection disabled under embryonic load, or SYN Cookie White List enabled on non-nPath VIPs.",
        recommendation_summary=(
            "Keep SYN Challenge Handling enabled on internet-facing VIPs, and restrict synCookieWhitelist strictly "
            "to asymmetric nPath/DSR deployments paired with Challenge and Remember."
        ),
        default_impact="Medium",
    ),
    "K15992": F5KnowledgeEntry(
        kb_id="K15992",
        title="Overview of Multipath TCP (MPTCP) profile settings and mobile subflow optimization",
        url="https://my.f5.com/manage/s/article/K15992",
        protocol="tcp",
        context="clientside",
        parameters=[
            "mptcp", "mptcpFallback", "mptcpFastjoin", "mptcpCsum", "mptcpCsumVerify",
            "mptcpJoinMax", "mptcpSubflowmax", "mptcpRtomax", "mptcpRxmitmin",
            "mptcpIdleTimeout", "mptcpTimeout", "mptcpMakeafterbreak", "mptcpJoin", "mptcpNojoindssack",
        ],
        trigger_condition="MPTCP enabled on mobile VIPs with default reset fallback/slow subflow timers, or passthrough without fastL4.",
        recommendation_summary=(
            "When MPTCP is enabled, set mptcpFallback to 'accept' (not 'reset'), enable mptcpFastjoin, bound mptcpSubflowmax (4-6), "
            "lower mptcpRxmitmin (250-300 ms), and never use mptcp='passthrough' without a matching fastL4 listener."
        ),
        default_impact="Medium",
    ),
    "K7537": F5KnowledgeEntry(
        kb_id="K7537",
        title="Overview of the BIG-IP LTM UDP profile (Buffers, MSS, TTL, and QoS)",
        url="https://my.f5.com/manage/s/article/K7537",
        protocol="udp",
        context="clientside",
        parameters=["bufferMaxBytes", "bufferMaxPackets", "proxyMss", "ipTtlMode", "ipTosToClient", "linkQosToClient"],
        trigger_condition="UDP ingress buffer overflows (bufOverflow > 0) or restrictive bufferMaxPackets cap causing packet drops.",
        recommendation_summary=(
            "Scale bufferMaxBytes (2-4 MB) for bursty UDP streams when datagramLoadBalancing cannot be enabled, "
            "keep bufferMaxPackets=0 (byte-limited), and preserve DSCP markings (mimic/pass-through) on real-time media VIPs."
        ),
        default_impact="High",
    ),
    "K3605": F5KnowledgeEntry(
        kb_id="K3605",
        title="Configuring UDP Datagram Load Balancing (datagramLoadBalancing) for high-rate stateless flows",
        url="https://my.f5.com/manage/s/article/K3605",
        protocol="udp",
        context="clientside",
        parameters=["datagramLoadBalancing"],
        trigger_condition="UDP datagrams-per-connection ratio >= 250 with UDP packet drops or buffer overflows on stateless UDP.",
        recommendation_summary=(
            "Enable datagramLoadBalancing ('enabled') on stateless UDP profiles (Syslog, DNS, telemetry) so individual datagrams "
            "distribute across all TMMs and pool members; require operator confirmation on QUIC/DTLS/VPN ports."
        ),
        default_impact="High",
    ),
    "K3667": F5KnowledgeEntry(
        kb_id="K3667",
        title="Tuning UDP profile idleTimeout for ephemeral port and connection table efficiency",
        url="https://my.f5.com/manage/s/article/K3667",
        protocol="udp",
        context="clientside",
        parameters=["idleTimeout"],
        trigger_condition="UDP ephemeral connection table >= 8,000 entries with 60s+ or indefinite idleTimeout.",
        recommendation_summary=(
            "Reduce UDP idleTimeout to 5-15s for high-churn request/response UDP traffic (DNS/telemetry) "
            "to prevent ephemeral port exhaustion and lower TMM connection table memory."
        ),
        default_impact="Medium",
    ),
    "K48620311": F5KnowledgeEntry(
        kb_id="K48620311",
        title="UDP profile drops zero-length payload datagrams when Allow No Payload is disabled",
        url="https://my.f5.com/manage/s/article/K48620311",
        protocol="udp",
        context="clientside",
        parameters=["allowNoPayload"],
        trigger_condition="UDP drops observed without buffer overflows on tiny/empty datagrams (health checks or NAT keepalives).",
        recommendation_summary=(
            "Enable allowNoPayload when legitimate 0-byte UDP probes or keepalives are dropped by the UDP profile."
        ),
        default_impact="Medium",
    ),
    "K7208": F5KnowledgeEntry(
        kb_id="K7208",
        title="Optimizing HTTP Keep-Alive connection reuse (enforcement.maxRequests, oneconnectTransformations, pipeline)",
        url="https://my.f5.com/manage/s/article/K7208",
        protocol="http",
        context="clientside",
        parameters=["enforcement.maxRequests", "oneconnectTransformations", "enforcement.pipeline"],
        trigger_condition="HTTP keep-alive requests per connection < 10, restrictive maxRequests, or HTTP/1.1 pipelining issues.",
        recommendation_summary=(
            "Set enforcement.maxRequests to 0 (unlimited), enable oneconnectTransformations paired with a OneConnect profile, "
            "and set enforcement.pipeline to 'reject' when no legacy pipelining clients exist."
        ),
        default_impact="High",
    ),
    "K59622503": F5KnowledgeEntry(
        kb_id="K59622503",
        title="Configuring OneConnect Status Reuse (oneconnectStatusCodes) for REST APIs and caching origins",
        url="https://my.f5.com/manage/s/article/K59622503",
        protocol="http",
        context="clientside",
        parameters=["oneconnectStatusCodes"],
        trigger_condition="Elevated server connection closes on OneConnect-enabled VIPs serving 201/204/301/302/304 responses.",
        recommendation_summary=(
            "Expand oneconnectStatusCodes from '200 206' to '200 201 204 206 301 302 304' so valid API/cache responses "
            "return backend sockets cleanly to the OneConnect reuse pool."
        ),
        default_impact="Medium",
    ),
    "K48382192": F5KnowledgeEntry(
        kb_id="K48382192",
        title="Overview of HTTP Request and Response Chunking modes (sustain, rechunk, unchunk) in BIG-IP 15.x+",
        url="https://my.f5.com/manage/s/article/K48382192",
        protocol="http",
        context="clientside",
        parameters=["requestChunking", "responseChunking"],
        trigger_condition="HTTP profile configured with responseChunking='unchunk' or requestChunking='unchunk'.",
        recommendation_summary=(
            "Use 'sustain' for requestChunking and responseChunking; 'unchunk' buffers entire payloads in TMM memory "
            "and forces 'Connection: close', breaking HTTP Keep-Alive connection reuse."
        ),
        default_impact="High",
    ),
    "K13525": F5KnowledgeEntry(
        kb_id="K13525",
        title="Configuring HTTP profile Enforcement limits, RFC compliance, and client IP visibility",
        url="https://my.f5.com/manage/s/article/K13525",
        protocol="http",
        context="clientside",
        parameters=[
            "enforcement.maxHeaderSize", "enforcement.maxHeaderCount", "enforcement.rfcCompliance",
            "enforcement.allowWsHeaderName", "enforcement.truncatedRedirects",
            "enforcement.oversizeClientHeaders", "enforcement.oversizeServerHeaders",
            "enforcement.excessClientHeaders", "enforcement.excessServerHeaders",
            "enforcement.unknownMethod", "enforcement.knownMethods", "insertXforwardedFor",
        ],
        trigger_condition="HTTP header size/count drops > 0, pass-through enforcement bypasses, or RFC smuggling exposure.",
        recommendation_summary=(
            "Right-size maxHeaderSize (65536+) and maxHeaderCount (128+) when drops occur, never use 'pass-through' on "
            "oversize/excess/unknown enforcement actions, disable allowWsHeaderName, and ensure PATCH is in knownMethods if unknownMethod='reject'."
        ),
        default_impact="High",
    ),
    "K40243113": F5KnowledgeEntry(
        kb_id="K40243113",
        title="Overview of the BIG-IP LTM HTTP profile (Headers, LWS folding, Redirect Rewrite, Explicit Proxy, sFlow)",
        url="https://my.f5.com/manage/s/article/K40243113",
        protocol="http",
        context="clientside",
        parameters=[
            "redirectRewrite", "lwsWidth", "lwsSeparator", "headerInsert", "headerErase",
            "responseHeadersPermitted", "fallbackHost", "fallbackStatusCodes", "acceptXff",
            "xffAlternativeNames", "viaRequest", "viaResponse", "viaHostName", "encryptCookies",
            "serverAgentName", "sflow.pollInterval", "sflow.samplingRate", "explicitProxy.dnsResolver",
        ],
        trigger_condition="LWS header wrapping risks (lwsWidth=80 with headerInsert), unsafe redirectRewrite='all', or orphan settings.",
        recommendation_summary=(
            "Prevent RFC 7230 obs-fold 400 errors on inserted headers (lwsSeparator='none' or lwsWidth>=1024), prefer "
            "redirectRewrite='matching' over 'all', avoid aggressive sFlow sampling (<128) on high-PPS VIPs, and validate Explicit Proxy dependencies."
        ),
        default_impact="Medium",
    ),
    "K68657325": F5KnowledgeEntry(
        kb_id="K68657325",
        title="Configuring HTTP Strict Transport Security (HSTS) on an HTTP profile",
        url="https://my.f5.com/manage/s/article/K68657325",
        protocol="http",
        context="clientside",
        parameters=["hsts.mode", "hsts.maximumAge", "hsts.includeSubdomains", "hsts.preload"],
        trigger_condition="HSTS preload enabled with maximumAge < 31536000 (1 year), or HSTS enabled on non-TLS Virtual Server.",
        recommendation_summary=(
            "Ensure HSTS is enabled only on ClientSSL-backed HTTPS Virtual Servers, and set hsts.maximumAge >= 31536000 "
            "with includeSubdomains='enabled' whenever hsts.preload='enabled'."
        ),
        default_impact="Medium",
    ),
    "K15434": F5KnowledgeEntry(
        kb_id="K15434",
        title="Overview of HTTP Compression, Web Acceleration (RAM Cache), and HTTP/2 Gateway offload",
        url="https://my.f5.com/manage/s/article/K15434",
        protocol="http",
        context="clientside",
        parameters=["responseChunking"],
        trigger_condition="Outbound HTTP throughput > 50 Mbps with low compression ratio (<1.25x).",
        recommendation_summary=(
            "Pair HTTP profile with /Common/httpcompression and /Common/webacceleration profiles for payload offload, "
            "and attach /Common/http2 on WAN HTTPS Virtual Servers."
        ),
        default_impact="Medium",
    ),
}


TCP_BASE_TEMPLATES: dict[str, dict[str, Any]] = {
    "/Common/f5-tcp-wan": {
        "description": "Optimized for high-latency (>20ms), high-BDP WAN client connections",
        "sendBufferSize": 262144,
        "receiveWindowSize": 131072,
        "proxyBufferLow": 196608,
        "proxyBufferHigh": 262144,
        "congestionControl": "cubic",
        "nagle": "auto",
        "initCwnd": 16,
        "dsack": "enabled",
    },
    "/Common/f5-tcp-lan": {
        "description": "Optimized for low-latency (<5ms), high-bandwidth LAN server-side pools",
        "sendBufferSize": 131072,
        "receiveWindowSize": 131072,
        "proxyBufferLow": 98304,
        "proxyBufferHigh": 131072,
        "congestionControl": "woodside",
        "nagle": "disabled",
        "minimumRto": 200,
        "synRtoBase": 500,
    },
    "/Common/f5-tcp-mobile": {
        "description": "Optimized for cellular/wireless links with variable RTT and sporadic non-congestive loss",
        "sendBufferSize": 262144,
        "receiveWindowSize": 131072,
        "congestionControl": "bbr",
        "ratePace": "enabled",
        "initCwnd": 16,
    },
    "/Common/f5-tcp-progressive": {
        "description": "Adaptive baseline profile dynamically scaling buffers across mixed WAN/LAN topologies",
        "autoProxyBufferSize": "enabled",
        "autoSendBufferSize": "enabled",
        "autoReceiveWindowSize": "enabled",
        "congestionControl": "cubic",
        "nagle": "auto",
        "ratePace": "enabled",
    },
}


def list_knowledge_base() -> list[dict[str, Any]]:
    return [asdict(entry) for entry in KNOWLEDGE_BASE.values()]

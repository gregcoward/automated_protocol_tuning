"""Complete canonical catalog of F5 BIG-IP LTM TCP, UDP, and HTTP profile settings.

Maps 1-to-1 with all settings across:
  - TCP_Profile_Settings.docx  (76 settings across 8 sections)
  - UDP_Profile_Settings.docx  (9 settings + IPv4/IPv6 TTL sub-values)
  - HTTP_Profile_Settings.docx (50 settings across 5 sections)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from backend.models import ProtocolType


@dataclass(frozen=True)
class ProfileSettingSpec:
    protocol: ProtocolType
    section: str
    gui_name: str
    rest_key: str
    default_value: Any
    allowed_values: str
    context: str  # "clientside", "serverside", "both"
    evaluation_mode: str  # "telemetry", "dependency", "hygiene", "policy"
    safe_auto_apply: bool
    f5_kb_id: str
    description: str
    interactions: str = ""


# ---------------------------------------------------------------------------
# TCP Profile Settings (76 settings across 8 sections)
# ---------------------------------------------------------------------------
TCP_SETTINGS: tuple[ProfileSettingSpec, ...] = (
    # 1. Timer Management (10)
    ProfileSettingSpec(
        "tcp", "Timer Management", "Close Wait", "closeWaitTimeout", 5,
        "immediate (0) | 1..86400s | indefinite", "both", "hygiene", True, "K7606",
        "Length of time a TCP connection remains in CLOSE-WAIT/LAST-ACK before closing.",
        "Indefinite or >30s leaks sockets under peer crashes during teardown.",
    ),
    ProfileSettingSpec(
        "tcp", "Timer Management", "Fin Wait 1", "finWaitTimeout", 5,
        "immediate (0) | 1..86400s | indefinite", "both", "telemetry", True, "K7606",
        "Length of time a TCP connection remains in FIN-WAIT-1 or CLOSING before quitting.",
        "Short values reclaim SNAT ephemeral ports rapidly when peers vanish without ACKing FIN.",
    ),
    ProfileSettingSpec(
        "tcp", "Timer Management", "Fin Wait 2", "finWait_2Timeout", 300,
        "1..86400s | indefinite", "both", "telemetry", False, "K7606",
        "Length of time a TCP connection remains in FIN-WAIT-2 waiting for peer FIN.",
        "High values (300s/indefinite) accumulate half-closed flows on high-concurrency VIPs.",
    ),
    ProfileSettingSpec(
        "tcp", "Timer Management", "Idle Timeout", "idleTimeout", 300,
        "1..86400s | indefinite", "both", "telemetry", False, "K7606",
        "Seconds an established connection may remain idle before deletion.",
        "Must exceed keepAliveInterval if keep-alives are expected to fire; interacts with resetOnTimeout.",
    ),
    ProfileSettingSpec(
        "tcp", "Timer Management", "Keep Alive Interval", "keepAliveInterval", 1800,
        "1..86400s | indefinite", "both", "dependency", True, "K7606",
        "Interval at which TMM probes idle connections to verify peer liveness.",
        "Ineffective unless keepAliveInterval < idleTimeout (default 1800s > 300s never fires).",
    ),
    ProfileSettingSpec(
        "tcp", "Timer Management", "Minimum RTO", "minimumRto", 1000,
        "10..5000 ms", "both", "telemetry", True, "K7606",
        "Floor wait time (ms) before RTO retransmission fires.",
        "Automatically drops to 203 ms if pktLossIgnoreRate/Burst > 0, and 200 ms if mptcp=enabled.",
    ),
    ProfileSettingSpec(
        "tcp", "Timer Management", "Reset on Timeout", "resetOnTimeout", "enabled",
        "enabled | disabled", "both", "hygiene", False, "K7606",
        "Sends TCP RST to peers when idleTimeout expires instead of silent flow deletion.",
        "Disabling on serverside leaves half-open zombie sockets on backend pool members.",
    ),
    ProfileSettingSpec(
        "tcp", "Timer Management", "Time Wait", "timeWaitTimeout", 2000,
        "immediate (0) | 1..600000 ms | indefinite", "both", "telemetry", True, "K7606",
        "Duration (ms) a closed connection stays in TIME-WAIT before CLOSED.",
        "Works with timeWaitRecycle; high values exhaust SNAT ports at high connection rates.",
    ),
    ProfileSettingSpec(
        "tcp", "Timer Management", "Time Wait Recycle", "timeWaitRecycle", "enabled",
        "enabled | disabled", "both", "hygiene", True, "K7606",
        "Immediately reuses a TIME-WAIT connection slot upon receiving a new SYN.",
        "Prevents SNAT ephemeral port exhaustion on high-CPS backend pools.",
    ),
    ProfileSettingSpec(
        "tcp", "Timer Management", "Zero Window Timeout", "zeroWindowTimeout", 20000,
        "1000..4294967295 ms | indefinite", "both", "telemetry", False, "K14806",
        "Timeout (ms) for terminating connections stalled on an effective zero transmit window.",
        "Indefinite on clientside exposes proxy buffers to Slow-Read DoS attacks.",
    ),
    # 2. Memory Management (7)
    ProfileSettingSpec(
        "tcp", "Memory Management", "Auto Proxy Buffer", "autoProxyBufferSize", "disabled",
        "enabled | disabled", "both", "telemetry", True, "K74421054",
        "Dynamically tunes proxy buffer thresholds using live network measurements.",
        "Adapts content spooling watermarks across mixed LAN/WAN client populations.",
    ),
    ProfileSettingSpec(
        "tcp", "Memory Management", "Auto Receive Window", "autoReceiveWindowSize", "disabled",
        "enabled | disabled", "both", "telemetry", True, "K74421054",
        "Dynamically scales advertised receive window using live bandwidth/RTT measurements.",
        "Requires receiveWindowSize > 65535 for RFC 1323 window scaling headroom.",
    ),
    ProfileSettingSpec(
        "tcp", "Memory Management", "Auto Send Buffer", "autoSendBufferSize", "disabled",
        "enabled | disabled", "both", "telemetry", True, "K74421054",
        "Dynamically scales socket send buffer per flow from measured BDP.",
        "Prevents static memory over-allocation on idle flows while allowing high-BDP bursts.",
    ),
    ProfileSettingSpec(
        "tcp", "Memory Management", "Proxy Buffer High", "proxyBufferHigh", 131072,
        "bytes (> proxyBufferLow, >= sendBufferSize)", "both", "telemetry", True, "K3422",
        "Proxy buffer byte watermark at which opposite-side receive window closes.",
        "Must be > proxyBufferLow and >= sendBufferSize to avoid premature spooling stalls.",
    ),
    ProfileSettingSpec(
        "tcp", "Memory Management", "Proxy Buffer Low", "proxyBufferLow", 98304,
        "bytes (< proxyBufferHigh)", "both", "telemetry", True, "K3422",
        "Proxy buffer byte watermark at which opposite-side receive window reopens.",
        "Keep near 75% of proxyBufferHigh; values >90% cause rapid window oscillation.",
    ),
    ProfileSettingSpec(
        "tcp", "Memory Management", "Receive Window", "receiveWindowSize", 65535,
        "2048..4294967295 bytes", "both", "telemetry", True, "K3422",
        "Maximum advertised TCP RECEIVE window size; >65535 enables RFC 1323 Window Scaling.",
        "Caps initRwnd * MSS and absorbs high-BDP bursts without zero-window stalls.",
    ),
    ProfileSettingSpec(
        "tcp", "Memory Management", "Send Buffer", "sendBufferSize", 131072,
        "4096..4294967295 bytes", "both", "telemetry", True, "K3422",
        "Maximum TCP SEND socket buffer size; >65535 enables RFC 1323 Window Scaling.",
        "Must be >= 2x BDP for full link utilization and <= proxyBufferHigh.",
    ),
    # 3. Connection Setup (6)
    ProfileSettingSpec(
        "tcp", "Connection Setup", "Deferred Accept", "deferredAccept", "disabled",
        "enabled | disabled", "clientside", "telemetry", False, "K7535",
        "Defers L7 connection context allocation until client sends payload data after 3WHS.",
        "Mitigates 3WHS DoS; safe only on client-speaks-first protocols (HTTP/HTTPS).",
    ),
    ProfileSettingSpec(
        "tcp", "Connection Setup", "Fast Open", "fastOpen", "enabled",
        "enabled | disabled", "clientside", "telemetry", True, "K15812",
        "Supports TCP Fast Open (RFC 7413) allowing repeat clients to send payload in SYN.",
        "Client-side only (no effect on server-side); governed by fastOpenCookieExpiration.",
    ),
    ProfileSettingSpec(
        "tcp", "Connection Setup", "Fast Open Cookie Expiration", "fastOpenCookieExpiration", 21600,
        "0 (default) | 1..1000000s", "clientside", "hygiene", True, "K15812",
        "Lifetime in seconds of TCP Fast Open cookies issued to clients.",
        "Active only when fastOpen=enabled; values <300s defeat TFO cache hit ratio.",
    ),
    ProfileSettingSpec(
        "tcp", "Connection Setup", "Proxy Maximum Segment", "proxyMss", "enabled",
        "enabled | disabled", "both", "dependency", False, "K7535",
        "Advertises the client's MSS on the server-side connection.",
        "Requires proxyMss=enabled on the server-side TCP profile as well; ignored under MRF.",
    ),
    ProfileSettingSpec(
        "tcp", "Connection Setup", "Proxy Options", "proxyOptions", "enabled",
        "enabled | disabled", "both", "dependency", False, "K7535",
        "Advertises TCP options (such as timestamps) to server only when client negotiated them.",
        "On split WAN/LAN VIPs, can strip server-side timestamps if WAN client omits them.",
    ),
    ProfileSettingSpec(
        "tcp", "Connection Setup", "Verified Accept", "verifiedAccept", "disabled",
        "enabled | disabled", "clientside", "dependency", False, "K7535",
        "Completes backend SYN handshake before replying SYN-ACK to client.",
        "Incompatible with APM; reorders iRule events (SERVER_CONNECTED fires before HTTP_REQUEST).",
    ),
    # 4. Data Transfer (10)
    ProfileSettingSpec(
        "tcp", "Data Transfer", "Acknowledge on Push", "ackOnPush", "enabled",
        "enabled | disabled", "both", "hygiene", True, "K15812",
        "Immediately ACKs segments with PSH set, improving Windows/macOS small-buffer writes.",
        "Mitigates delayedAcks stalls for peers setting PSH on application write boundaries.",
    ),
    ProfileSettingSpec(
        "tcp", "Data Transfer", "Delayed Acks", "delayedAcks", "enabled",
        "enabled | disabled", "both", "telemetry", False, "K15812",
        "Coalesces bare ACKs (<1 ACK per segment) to reduce packet overhead.",
        "Interacts poorly with Nagle=enabled on small interactive request/response streams.",
    ),
    ProfileSettingSpec(
        "tcp", "Data Transfer", "Don't Fragment Flag (DF)", "ipDfMode", "pmtu",
        "pmtu | preserve | set | clear", "both", "hygiene", False, "K7535",
        "Controls IP header Don't Fragment bit on outgoing TCP packets.",
        "Depends on tm.pathmtudiscovery when set to pmtu; 'set' risks blackholes if ICMP blocked.",
    ),
    ProfileSettingSpec(
        "tcp", "Data Transfer", "Initial Receive Window Size", "initRwnd", 10,
        "0..64 (x MSS)", "both", "telemetry", True, "K75593415",
        "Initial receive window multiplier (in MSS segments) advertised at connection start.",
        "Bounded by receiveWindowSize; higher values (16) accelerate immediate client uploads.",
    ),
    ProfileSettingSpec(
        "tcp", "Data Transfer", "Max Segment Size (MSS)", "maxSegmentSize", 1460,
        "0 (from MTU) | 536..9172 bytes", "both", "hygiene", False, "K7535",
        "Largest payload bytes accepted in a single TCP segment excluding IP/TCP headers.",
        "Multiplies initCwnd and initRwnd; values > MTU-40 cause IP fragmentation/drops.",
    ),
    ProfileSettingSpec(
        "tcp", "Data Transfer", "Nagle's Algorithm", "nagle", "disabled",
        "disabled | enabled | auto", "both", "telemetry", True, "K15812",
        "Buffers sub-MSS segments until in-flight data is ACKed (or dynamically in 'auto' mode).",
        "Enabling degrades interactive/API latency by 40-200ms when paired with Delayed ACKs.",
    ),
    ProfileSettingSpec(
        "tcp", "Data Transfer", "PUSH Flag", "pushFlag", "default",
        "default | none | one | auto", "both", "telemetry", True, "K7535",
        "Controls how TMM sets the TCP PSH bit on outgoing segments to regulate peer ACK rate.",
        "'auto' sets PSH once per RTT, near zero rwnd, or on response completion to lower ACK CPU.",
    ),
    ProfileSettingSpec(
        "tcp", "Data Transfer", "Time To Live (TTL)", "ipTtlMode", "proxy",
        "proxy | preserve | decrement | set", "both", "policy", False, "K7535",
        "Governs outgoing IP header TTL mode (255/64 in proxy mode).",
        "Controls whether ipTtlV4 and ipTtlV6 explicit values are applied ('set' mode).",
    ),
    ProfileSettingSpec(
        "tcp", "Data Transfer", "Time To Live (TTL) v4", "ipTtlV4", 255,
        "1..255", "both", "dependency", False, "K7535",
        "Outgoing IPv4 TTL value when ipTtlMode is 'set'.",
        "Ignored unless ipTtlMode='set'; values <32 risk premature WAN hop expiration.",
    ),
    ProfileSettingSpec(
        "tcp", "Data Transfer", "Time To Live (TTL) v6", "ipTtlV6", 64,
        "1..255", "both", "dependency", False, "K7535",
        "Outgoing IPv6 Hop Limit when ipTtlMode is 'set'.",
        "Ignored unless ipTtlMode='set'; values <32 risk premature WAN hop expiration.",
    ),
    # 5. Congestion Control (13)
    ProfileSettingSpec(
        "tcp", "Congestion Control", "Appropriate Byte Counting (RFC 3465)", "abc", "enabled",
        "enabled | disabled", "both", "hygiene", True, "K7535",
        "Grows cwnd based on acknowledged byte count rather than ACK packet count.",
        "F5 recommends enabled; disabling stalls cwnd growth when ACKs are delayed or lost.",
    ),
    ProfileSettingSpec(
        "tcp", "Congestion Control", "Congestion Metrics Cache", "cmetricsCache", "enabled",
        "enabled | disabled", "both", "dependency", True, "K7535",
        "Caches RTT/ssthresh metrics per peer IP to accelerate subsequent slow-start ramps.",
        "Ignored when slowStart=disabled; can skew metrics behind shared CGNAT/proxy IPs.",
    ),
    ProfileSettingSpec(
        "tcp", "Congestion Control", "Congestion Metrics Cache Timeout", "cmetricsCacheTimeout", 0,
        "0 (db default) | 1..86400s", "both", "telemetry", True, "K7535",
        "Validity duration in seconds of cached congestion metrics.",
        "Active only when cmetricsCache=enabled and slowStart=enabled.",
    ),
    ProfileSettingSpec(
        "tcp", "Congestion Control", "Congestion Control", "congestionControl", "high-speed",
        "none | bbr | cdg | chd | cubic | high-speed | illinois | new-reno | reno | scalable | vegas | westwood | woodside",
        "both", "telemetry", True, "K02412420",
        "Algorithm governing TCP congestion window sizing and loss/delay response.",
        "BBR models bottleneck BDP/RTT natively; interacts with ratePace, delayWindowControl, and pktLossIgnore*.",
    ),
    ProfileSettingSpec(
        "tcp", "Congestion Control", "Delay Window Control", "delayWindowControl", "disabled",
        "enabled | disabled", "both", "dependency", True, "K02412420",
        "Uses queuing delay estimates alongside loss-based CC to bound transmit window.",
        "Redundant/conflicting when delay-aware CC (bbr, cdg, chd, vegas) is already selected.",
    ),
    ProfileSettingSpec(
        "tcp", "Congestion Control", "Explicit Congestion Notification", "ecn", "enabled",
        "enabled | disabled", "clientside", "policy", False, "K7535",
        "Uses CWR/ECE TCP flags to signal congestion without dropping packets.",
        "Effective on client-side only; spoofed CWR from middleboxes can throttle cwnd.",
    ),
    ProfileSettingSpec(
        "tcp", "Congestion Control", "Initial Congestion Window Size", "initCwnd", 10,
        "0..64 (x MSS)", "both", "telemetry", True, "K75593415",
        "Initial cwnd multiplier (in MSS segments) at handshake completion.",
        "Requires sendBufferSize >= initCwnd * MSS and benefits from ratePace=enabled.",
    ),
    ProfileSettingSpec(
        "tcp", "Congestion Control", "Packet Loss Ignore Burst", "pktLossIgnoreBurst", 0,
        "0..32", "clientside", "dependency", False, "K02412420",
        "Probability control for ignoring burst packet losses under pktLossIgnoreRate.",
        "Non-zero values automatically drop minimumRto to 203 ms; unnecessary with BBR.",
    ),
    ProfileSettingSpec(
        "tcp", "Congestion Control", "Packet Loss Ignore Rate", "pktLossIgnoreRate", 0,
        "0..1000000 (per million pkts)", "clientside", "dependency", False, "K02412420",
        "Threshold of lost packets per million ignored before loss-based CC backs off.",
        "Non-zero values drop minimumRto to 203 ms; reset to 0 when switching to BBR.",
    ),
    ProfileSettingSpec(
        "tcp", "Congestion Control", "Rate Pace", "ratePace", "enabled",
        "enabled | disabled", "both", "telemetry", True, "K74421054",
        "Paces egress segments across RTT to prevent micro-burst queue drops on WAN/mobile.",
        "Prerequisite for ratePaceMaxRate; smooths large initCwnd bursts.",
    ),
    ProfileSettingSpec(
        "tcp", "Congestion Control", "Rate Pace Maximum Rate", "ratePaceMaxRate", 0,
        "0 (unlimited) | bytes/sec", "both", "dependency", False, "K74421054",
        "Per-connection ceiling (bytes/sec) for TCP rate pacing.",
        "Inactive unless ratePace=enabled; low values cap single-flow throughput.",
    ),
    ProfileSettingSpec(
        "tcp", "Congestion Control", "Slow Start", "slowStart", "enabled",
        "enabled | disabled", "both", "hygiene", True, "K7535",
        "Uses RFC 3390 Slow-Start ramp instead of transmitting immediately at max window.",
        "Disabling causes cmetricsCache to be ignored and bursts at max window on WAN.",
    ),
    ProfileSettingSpec(
        "tcp", "Congestion Control", "Timestamps Extension for High Performance (RFC 1323)", "timestamps", "enabled",
        "enabled | disabled", "both", "dependency", True, "K7535",
        "Enables RFC 1323 TCP timestamps for precise RTT measurement and PAWS protection.",
        "Essential for BBR, auto-buffer sizing, and high-speed (>1 Gbps) sequence wrap safety.",
    ),
    # 6. Loss Detection and Recovery (11)
    ProfileSettingSpec(
        "tcp", "Loss Detection and Recovery", "D-SACK (RFC 2883)", "dsack", "disabled",
        "enabled | disabled", "both", "telemetry", True, "K75593415",
        "Reports duplicate SACK blocks so sender detects spurious retransmits/reordering.",
        "Requires selectiveAcks=enabled; adds minor SACK block processing overhead.",
    ),
    ProfileSettingSpec(
        "tcp", "Loss Detection and Recovery", "Early Retransmit", "earlyRetransmit", "enabled",
        "enabled | disabled", "both", "hygiene", True, "K7535",
        "RFC 5827 fast recovery with fewer than 3 dupACKs when flight is small/window-limited.",
        "Complements tailLossProbe on short HTTP/API responses.",
    ),
    ProfileSettingSpec(
        "tcp", "Loss Detection and Recovery", "Enhanced Loss Recovery", "enhancedLossRecovery", "enabled",
        "enabled | disabled", "both", "dependency", True, "K7535",
        "Retransmits lost segments multiple times during recovery to avoid RTO stalls.",
        "Can ONLY be used when selectiveAcks=enabled.",
    ),
    ProfileSettingSpec(
        "tcp", "Loss Detection and Recovery",
        "Initial Retransmission Timeout Base Multiplier for SYN Retransmission", "synRtoBase", 3000,
        "100..5000 ms", "both", "telemetry", True, "K7606",
        "Initial RTO base multiplier (ms) for unanswered SYN/SYN-ACK retransmissions.",
        "Default 3000 ms stalls lost handshakes for 3s; scales across synMaxRetrans.",
    ),
    ProfileSettingSpec(
        "tcp", "Loss Detection and Recovery", "Limited Transmit Recovery", "limitedTransmit", "enabled",
        "enabled | disabled", "both", "hygiene", True, "K7535",
        "RFC 3042 — transmits new segment on initial dupACKs to sustain ACK clock.",
        "Accelerates entry into Fast Retransmit on small congestion windows.",
    ),
    ProfileSettingSpec(
        "tcp", "Loss Detection and Recovery", "Maximum Segment Retransmissions", "maxRetrans", 8,
        "1..32", "both", "hygiene", True, "K7606",
        "Maximum consecutive RTO resends of a data segment before aborting connection.",
        "Values <4 cause premature WAN drops; >12 hold dead peers open excessively.",
    ),
    ProfileSettingSpec(
        "tcp", "Loss Detection and Recovery", "Maximum Syn Retransmissions", "synMaxRetrans", 3,
        "1..10", "both", "telemetry", True, "K7606",
        "Maximum unanswered SYN packet retries before handshake failure.",
        "Interacts with synRtoBase; lower values speed backend pool member failover.",
    ),
    ProfileSettingSpec(
        "tcp", "Loss Detection and Recovery", "Retransmit Threshold", "rexmtThresh", 3,
        "3..255 dupACKs", "both", "hygiene", True, "K7535",
        "Duplicate ACK count required to trigger Fast Recovery.",
        "Values >4 delay loss recovery unless multipath reordering requires higher tolerance.",
    ),
    ProfileSettingSpec(
        "tcp", "Loss Detection and Recovery", "Selective ACKs", "selectiveAcks", "enabled",
        "enabled | disabled", "both", "dependency", True, "K7535",
        "Negotiates RFC 2018 SACK to recover multiple lost packets per RTT.",
        "Required by enhancedLossRecovery and dsack; F5 strongly recommends enabled.",
    ),
    ProfileSettingSpec(
        "tcp", "Loss Detection and Recovery", "Selective NACK", "selectiveNack", "disabled",
        "enabled | disabled", "both", "hygiene", True, "K7535",
        "Negotiates SNACK between legacy WAN Optimization Modules.",
        "F5 explicitly recommends keeping this disabled.",
    ),
    ProfileSettingSpec(
        "tcp", "Loss Detection and Recovery", "Tail Loss Probe", "tailLossProbe", "enabled",
        "enabled | disabled", "both", "hygiene", True, "K7535",
        "Sends probe segment on trailing flight silence to convert RTOs into fast recovery.",
        "Crucial for tail-latency on short request/response transactions.",
    ),
    # 7. Security And Quality of Service (6)
    ProfileSettingSpec(
        "tcp", "Security And Quality of Service", "SYN Challenge Handling", "synCookieEnable", "enabled",
        "Nominal (enabled) | Challenge and Remember | Disable Challenges (disabled)",
        "clientside", "dependency", False, "K14776",
        "Controls embryonic connection SYN cookie protection when no DoS profile is attached.",
        "'Challenge and Remember' disables hardware SYN acceleration and feeds synCookieWhitelist.",
    ),
    ProfileSettingSpec(
        "tcp", "Security And Quality of Service", "SYN Cookie White List", "synCookieWhitelist", "disabled",
        "enabled | disabled", "clientside", "dependency", False, "K14776",
        "Uses RST-retry client IP whitelisting for asymmetric nPath (DSR) routing.",
        "Requires 'Challenge and Remember'; sends disruptive RSTs if enabled on standard L7 VIPs.",
    ),
    ProfileSettingSpec(
        "tcp", "Security And Quality of Service", "MD5 Signature", "md5Signature", "disabled",
        "enabled | disabled", "both", "dependency", False, "K7535",
        "Enables RFC 2385 TCP-MD5 header authentication (used for BGP peering).",
        "Requires md5SignaturePassphrase; consumes 18B TCP option space and disables TFO/PVA.",
    ),
    ProfileSettingSpec(
        "tcp", "Security And Quality of Service", "MD5 Signature Passphrase", "md5SignaturePassphrase", "",
        "string (1..80 chars)", "both", "policy", False, "K7535",
        "Shared secret passphrase for RFC 2385 TCP-MD5 signatures.",
        "Mandatory when md5Signature=enabled.",
    ),
    ProfileSettingSpec(
        "tcp", "Security And Quality of Service", "IP ToS", "ipTosToClient", "0",
        "0..255 | pass-through | mimic", "clientside", "policy", False, "K7535",
        "L3 Type of Service / DSCP value written into client-bound TCP packets.",
        "'0' overwrites incoming markings; 'mimic' copies peer incoming ToS.",
    ),
    ProfileSettingSpec(
        "tcp", "Security And Quality of Service", "Link QoS", "linkQosToClient", "0",
        "0..7 | pass-through", "clientside", "policy", False, "K7535",
        "L2 802.1p QoS priority inserted in client-bound Ethernet frames.",
        "Network QoS policy setting.",
    ),
    # 8. Multipath TCP (MPTCP) (14 in GUI incl. MPTCP Join & Make After Break -> 76 total)
    ProfileSettingSpec(
        "tcp", "Multipath TCP (MPTCP)", "Multipath TCP", "mptcp", "disabled",
        "disabled | enabled | passthrough", "clientside", "dependency", False, "K15992",
        "Accepts multiple client subflows (Wi-Fi + cellular) into one server TCP stream.",
        "Drops minimumRto to 200 ms; 'passthrough' blocks traffic if no fastL4 listener matches!",
    ),
    ProfileSettingSpec(
        "tcp", "Multipath TCP (MPTCP)", "MPTCP Checksum", "mptcpCsum", "disabled",
        "enabled | disabled", "clientside", "dependency", False, "K15992",
        "Calculates DSS payload checksums on MPTCP subflows to detect middlebox mutation.",
        "Active only when mptcp=enabled; pair with mptcpCsumVerify.",
    ),
    ProfileSettingSpec(
        "tcp", "Multipath TCP (MPTCP)", "MPTCP Checksum Verify", "mptcpCsumVerify", "disabled",
        "enabled | disabled", "clientside", "dependency", True, "K15992",
        "Verifies incoming MPTCP DSS checksums.",
        "Should match mptcpCsum when mptcp=enabled.",
    ),
    ProfileSettingSpec(
        "tcp", "Multipath TCP (MPTCP)", "MPTCP Fallback", "mptcpFallback", "reset",
        "reset | retransmit | active-accept | accept", "clientside", "hygiene", True, "K15992",
        "Action when middlebox interference forces MPTCP to fall back to regular TCP.",
        "Default 'reset' aborts the flow; 'accept' or 'retransmit' preserves session continuity.",
    ),
    ProfileSettingSpec(
        "tcp", "Multipath TCP (MPTCP)", "MPTCP Fast Join", "mptcpFastjoin", "disabled",
        "enabled | disabled", "clientside", "telemetry", True, "K15992",
        "Permits payload data on MP_JOIN_SYN to save 1 RTT when adding subflows.",
        "Active when mptcp=enabled.",
    ),
    ProfileSettingSpec(
        "tcp", "Multipath TCP (MPTCP)", "MPTCP Join Max", "mptcpJoinMax", 5,
        "1..20", "clientside", "dependency", True, "K15992",
        "Maximum subflow join attempts permitted per MPTCP session.",
        "Should be >= mptcpSubflowmax - 1 and bounded to prevent join floods.",
    ),
    ProfileSettingSpec(
        "tcp", "Multipath TCP (MPTCP)", "MPTCP Make After Break", "mptcpMakeafterbreak", "disabled",
        "enabled | disabled", "clientside", "dependency", False, "K15992",
        "Supports seamless subflow establishment after all prior subflows break.",
        "Pairs with mptcpJoin and mptcpTimeout for mobile dead-zone survival.",
    ),
    ProfileSettingSpec(
        "tcp", "Multipath TCP (MPTCP)", "MPTCP Idle Timeout", "mptcpIdleTimeout", 300,
        "1..86400s", "clientside", "dependency", True, "K15992",
        "Seconds an MPTCP session may remain idle before deletion.",
        "Align >= TCP idleTimeout when mptcp=enabled.",
    ),
    ProfileSettingSpec(
        "tcp", "Multipath TCP (MPTCP)", "MPTCP Join", "mptcpJoin", "disabled",
        "enabled | disabled", "clientside", "dependency", False, "K15992",
        "Allows subsequent subflow joins even after original TCP subflow has closed.",
        "Bounded by mptcpTimeout; pairs with mptcpMakeafterbreak.",
    ),
    ProfileSettingSpec(
        "tcp", "Multipath TCP (MPTCP)", "MPTCP No Join DSS ACK", "mptcpNojoindssack", "disabled",
        "enabled | disabled", "clientside", "hygiene", False, "K15992",
        "Suppresses DSS option on MP_JOIN ACK.",
        "Keep disabled unless specific peer interoperability requires it.",
    ),
    ProfileSettingSpec(
        "tcp", "Multipath TCP (MPTCP)", "MPTCP RTO Max", "mptcpRtomax", 5,
        "1..10", "clientside", "telemetry", True, "K15992",
        "RTO count before marking an individual MPTCP subflow dead.",
        "Lower values (3-4) speed failover from degraded Wi-Fi to cellular.",
    ),
    ProfileSettingSpec(
        "tcp", "Multipath TCP (MPTCP)", "MPTCP Retransmit Min", "mptcpRxmitmin", 1000,
        "100..5000 ms", "clientside", "telemetry", True, "K15992",
        "Minimum retransmission timer (ms) for MPTCP subflows.",
        "Lowering from 1000 ms to 250-300 ms accelerates cross-subflow loss recovery.",
    ),
    ProfileSettingSpec(
        "tcp", "Multipath TCP (MPTCP)", "MPTCP Subflow Max", "mptcpSubflowmax", 6,
        "0 (unlimited) | 1..20", "clientside", "hygiene", True, "K15992",
        "Maximum concurrent MPTCP subflows per session.",
        "Avoid 0 (unlimited) to prevent per-client subflow memory exhaustion.",
    ),
    ProfileSettingSpec(
        "tcp", "Multipath TCP (MPTCP)", "MPTCP Timeout", "mptcpTimeout", 3600,
        "60..518400s", "clientside", "telemetry", True, "K15992",
        "Timeout (s) to discard long-lived MPTCP sessions with no active subflows.",
        "Cap <=1800s on high-concurrency VIPs to bound session table memory.",
    ),
)


# ---------------------------------------------------------------------------
# UDP Profile Settings (9 GUI settings + conditional TTL v4/v6)
# ---------------------------------------------------------------------------
UDP_SETTINGS: tuple[ProfileSettingSpec, ...] = (
    ProfileSettingSpec(
        "udp", "General", "Proxy Maximum Segment", "proxyMss", "enabled",
        "enabled | disabled", "clientside", "hygiene", True, "K7537",
        "Attempts to advertise matching MSS across client/server sides when MTU permits.",
        "Requires server-side profile support and adequate VLAN MTU.",
    ),
    ProfileSettingSpec(
        "udp", "General", "Idle Timeout", "idleTimeout", 60,
        "immediate | 1..86400s | indefinite", "clientside", "telemetry", True, "K3667",
        "Seconds a UDP connection table entry stays idle before deletion.",
        "High values (>=60s or indefinite) exhaust ephemeral ports under high QPS.",
    ),
    ProfileSettingSpec(
        "udp", "General", "IP ToS", "ipTosToClient", "0",
        "0..255 | pass-through | mimic", "clientside", "policy", False, "K7537",
        "L3 Type of Service / DSCP assigned to egress UDP datagrams.",
        "Default 0 zeroes DSCP; use mimic/pass-through for VoIP/RTP media VIPs.",
    ),
    ProfileSettingSpec(
        "udp", "General", "Link QoS", "linkQosToClient", "0",
        "0..7 | pass-through", "clientside", "policy", False, "K7537",
        "L2 802.1p QoS priority assigned to egress UDP datagrams.",
        "Network QoS policy setting.",
    ),
    ProfileSettingSpec(
        "udp", "General", "Datagram LB", "datagramLoadBalancing", "disabled",
        "enabled | disabled", "clientside", "telemetry", False, "K3605",
        "Load-balances UDP traffic packet-by-packet across TMMs and pool members.",
        "Ideal for stateless syslog/DNS/telemetry; breaks stateful DTLS/QUIC/VPN sessions.",
    ),
    ProfileSettingSpec(
        "udp", "General", "Allow No Payload", "allowNoPayload", "disabled",
        "enabled | disabled", "clientside", "telemetry", False, "K48620311",
        "Permits header-only (0-byte payload) UDP datagrams instead of dropping them.",
        "Required for 0-byte UDP health probes (nc -uz) or empty NAT keepalive pings.",
    ),
    ProfileSettingSpec(
        "udp", "General", "TTL Mode", "ipTtlMode", "proxy",
        "proxy | preserve | decrement | set", "clientside", "hygiene", False, "K7537",
        "Controls outgoing UDP IP TTL mode (255 IPv4 / 64 IPv6 in proxy mode).",
        "When 'set', applies ipTtlV4 and ipTtlV6.",
    ),
    ProfileSettingSpec(
        "udp", "General", "Max Buffer Bytes", "bufferMaxBytes", 655350,
        "1000..16777215 bytes", "clientside", "telemetry", True, "K7537",
        "Ingress per-flow UDP byte buffer limit before datagrams are dropped.",
        "Constrained jointly by bufferMaxPackets; scale up for bursty stateful UDP streams.",
    ),
    ProfileSettingSpec(
        "udp", "General", "Max Buffer Packets", "bufferMaxPackets", 0,
        "0 (unlimited) | 1..255 packets", "clientside", "telemetry", True, "K7537",
        "Ingress per-flow UDP packet count limit (0 means byte-limited only).",
        "Non-zero values drop small-datagram bursts well before bufferMaxBytes is reached.",
    ),
)


# ---------------------------------------------------------------------------
# HTTP Profile Settings (50 settings across 5 sections)
# ---------------------------------------------------------------------------
HTTP_SETTINGS: tuple[ProfileSettingSpec, ...] = (
    # 1. General (21)
    ProfileSettingSpec(
        "http", "General", "Basic Auth Realm", "basicAuthRealm", "none",
        "string", "clientside", "policy", False, "K40243113",
        "Realm string returned in WWW-Authenticate when LTM basic auth fails.",
    ),
    ProfileSettingSpec(
        "http", "General", "Fallback Host", "fallbackHost", "none",
        "URL string", "clientside", "dependency", False, "K40243113",
        "Target URL sent via HTTP 302 redirect when all pool nodes are down.",
        "Required for fallbackStatusCodes to take effect; unsuitable for JSON/REST APIs.",
    ),
    ProfileSettingSpec(
        "http", "General", "Fallback on Error Codes", "fallbackStatusCodes", "none",
        "space-separated status codes / ranges (e.g. 500 502)", "clientside", "dependency", False, "K40243113",
        "Backend error status codes that trigger 302 redirect to fallbackHost.",
        "Dead configuration if fallbackHost is empty.",
    ),
    ProfileSettingSpec(
        "http", "General", "Request Header Erase", "headerErase", "none",
        "header name", "clientside", "dependency", False, "K40243113",
        "Name of a single client request header stripped prior to forwarding.",
        "Pairs with insertXforwardedFor on untrusted VIPs to strip spoofed XFF headers.",
    ),
    ProfileSettingSpec(
        "http", "General", "Request Header Insert", "headerInsert", "none",
        "header: value", "clientside", "dependency", False, "K40243113",
        "Static header inserted into HTTP requests if not already present.",
        "Long inserted headers wrap at lwsWidth unless lwsWidth is raised or lwsSeparator=none.",
    ),
    ProfileSettingSpec(
        "http", "General", "Response Headers Allowed", "responseHeadersPermitted", "none",
        "space-separated header names", "clientside", "dependency", False, "K40243113",
        "Strict allowlist of backend response headers permitted through LTM.",
        "If non-empty, strips unlisted headers (can strip HSTS, Set-Cookie, or CORS headers).",
    ),
    ProfileSettingSpec(
        "http", "General", "Request Chunking", "requestChunking", "sustain",
        "unchunk | rechunk | sustain", "clientside", "hygiene", True, "K48382192",
        "Controls handling of Transfer-Encoding: chunked client requests.",
        "'unchunk' buffers entire upload body in TMM memory; 'sustain' preserves zero-copy streaming.",
    ),
    ProfileSettingSpec(
        "http", "General", "Response Chunking", "responseChunking", "sustain",
        "unchunk | rechunk | sustain", "clientside", "telemetry", True, "K48382192",
        "Controls handling of chunked server responses.",
        "CRITICAL: 'unchunk' buffers full response AND forces Connection: close, killing Keep-Alive!",
    ),
    ProfileSettingSpec(
        "http", "General", "OneConnect Transformations", "oneconnectTransformations", "enabled",
        "enabled | disabled", "clientside", "telemetry", True, "K7208",
        "Rewrites Connection headers to keep HTTP/1.1 connections open for pooling.",
        "Applicable ONLY when a OneConnect profile/pool is attached to the Virtual Server.",
    ),
    ProfileSettingSpec(
        "http", "General", "OneConnect Status Reuse", "oneconnectStatusCodes", "200 206",
        "space-separated HTTP status codes", "clientside", "telemetry", True, "K59622503",
        "HTTP response codes eligible to return backend connections to the OneConnect pool.",
        "REST APIs returning 201/204/304 tear down backend sockets unless listed here.",
    ),
    ProfileSettingSpec(
        "http", "General", "Redirect Rewrite", "redirectRewrite", "none",
        "none | all | matching | nodes", "clientside", "dependency", False, "K40243113",
        "Rewrites http:// Location URIs to https:// on 3xx redirects when SSL is offloaded.",
        "'all' breaks external 3rd-party/OAuth redirects; 'matching' or 'nodes' is safer.",
    ),
    ProfileSettingSpec(
        "http", "General", "Encrypt Cookies", "encryptCookies", "none",
        "space-separated cookie names", "clientside", "dependency", False, "K40243113",
        "Cookie names symmetrically encrypted by LTM on egress and decrypted on ingress.",
        "Requires encryptCookieSecret passphrase.",
    ),
    ProfileSettingSpec(
        "http", "General", "Cookie Encryption Passphrase", "encryptCookieSecret", "",
        "passphrase string", "clientside", "policy", False, "K40243113",
        "Passphrase used to encrypt cookies listed in encryptCookies.",
        "Must match across HA pairs; never auto-mutated.",
    ),
    ProfileSettingSpec(
        "http", "General", "Insert X-Forwarded-For", "insertXforwardedFor", "disabled",
        "enabled | disabled", "clientside", "hygiene", False, "K13525",
        "Appends client IP in X-Forwarded-For request header for SNAT/OneConnect visibility.",
        "Pair with headerErase or acceptXff policy on public VIPs to prevent XFF spoofing.",
    ),
    ProfileSettingSpec(
        "http", "General", "LWS Maximum Columns", "lwsWidth", 80,
        "integer columns (default 80)", "clientside", "dependency", True, "K40243113",
        "Maximum line width when LTM inserts HTTP headers before inserting lwsSeparator.",
        "RFC 7230 deprecated obs-fold line wrapping; wrapping long inserted headers causes 400 errors on modern backends.",
    ),
    ProfileSettingSpec(
        "http", "General", "LWS Separator", "lwsSeparator", "none",
        "none | cr | lf | sp | \\r\\n", "clientside", "hygiene", True, "K40243113",
        "Linear whitespace separator inserted when inserted headers exceed lwsWidth.",
        "Bare CR/LF violates RFC 7230 framing and triggers smuggling blocks.",
    ),
    ProfileSettingSpec(
        "http", "General", "Maximum Requests", "enforcement.maxRequests", 0,
        "0 (unlimited) | 1..4294967295", "clientside", "telemetry", True, "K7208",
        "Maximum HTTP requests accepted per persistent client connection (0 = unlimited).",
        "Low caps (<250) force frequent TCP/TLS re-handshakes.",
    ),
    ProfileSettingSpec(
        "http", "General", "Send Proxy Via Header in Request", "viaRequest", "preserve",
        "remove | preserve | append", "clientside", "dependency", False, "K40243113",
        "Controls Via header handling on requests forwarded to origin servers.",
        "'append' uses viaHostName.",
    ),
    ProfileSettingSpec(
        "http", "General", "Send Proxy Via Header in Response", "viaResponse", "preserve",
        "remove | preserve | append", "clientside", "dependency", False, "K40243113",
        "Controls Via header handling on responses returned to clients.",
        "'remove' prevents leaking internal proxy topology.",
    ),
    ProfileSettingSpec(
        "http", "General", "Send Proxy Via Header Host Name", "viaHostName", "none",
        "hostname string", "clientside", "dependency", False, "K40243113",
        "Comment/hostname appended when viaRequest or viaResponse is set to 'append'.",
    ),
    ProfileSettingSpec(
        "http", "General", "Accept XFF", "acceptXff", "disabled",
        "enabled | disabled", "clientside", "dependency", False, "K40243113",
        "Trusts client IP from incoming X-Forwarded-For headers for stats/security.",
        "Enable only behind trusted upstream CDNs/proxies; governs xffAlternativeNames.",
    ),
    ProfileSettingSpec(
        "http", "General", "XFF Alternative Names", "xffAlternativeNames", "none",
        "space-separated header names", "clientside", "dependency", False, "K40243113",
        "Custom client-IP headers (e.g. True-Client-IP, CF-Connecting-IP) recognized as XFF.",
        "Dead configuration if acceptXff=disabled and no consumer reads alternative XFF.",
    ),
    ProfileSettingSpec(
        "http", "General", "Server Agent Name", "serverAgentName", "BigIP",
        "string (empty suppresses Server header)", "clientside", "policy", False, "K40243113",
        "Server token emitted in LTM-generated HTTP responses.",
    ),
    # 2. Enforcement (12)
    ProfileSettingSpec(
        "http", "Enforcement", "Enforce RFC Compliance", "enforcement.rfcCompliance", "disabled",
        "enabled | disabled", "clientside", "hygiene", False, "K13525",
        "Rejects non-RFC-compliant HTTP framing (e.g. dual CL+TE smuggling attempts).",
        "Resets malformed legacy clients; recommended on public VIPs without ASM/AWAF.",
    ),
    ProfileSettingSpec(
        "http", "Enforcement", "Allow Space Header Name", "enforcement.allowWsHeaderName", "disabled",
        "enabled | disabled", "clientside", "hygiene", False, "K13525",
        "Allows whitespace characters inside HTTP header names.",
        "Keep disabled to prevent HTTP Request Smuggling across backend parsers.",
    ),
    ProfileSettingSpec(
        "http", "Enforcement", "Allow Truncated Redirect", "enforcement.truncatedRedirects", "disabled",
        "enabled | disabled", "clientside", "hygiene", False, "K13525",
        "Switches to pass-through on malformed 3xx redirects missing trailing CRLF.",
        "Keep disabled so malformed responses do not bypass L7 inspection.",
    ),
    ProfileSettingSpec(
        "http", "Enforcement", "Maximum Header Size", "enforcement.maxHeaderSize", 32768,
        "1024..4294967295 bytes", "clientside", "telemetry", True, "K13525",
        "Maximum combined byte size of all HTTP request headers including request line.",
        "Exceeding triggers oversizeClientHeaders (default RST); raise to 65536+ for OIDC/JWTs.",
    ),
    ProfileSettingSpec(
        "http", "Enforcement", "Oversize Client Headers", "enforcement.oversizeClientHeaders", "reject",
        "reject | pass-through", "clientside", "hygiene", False, "K13525",
        "Action when client request headers exceed maxHeaderSize.",
        "'pass-through' disables L7 HTTP inspection/iRules/WAF for the connection!",
    ),
    ProfileSettingSpec(
        "http", "Enforcement", "Oversize Server Headers", "enforcement.oversizeServerHeaders", "reject",
        "reject | pass-through", "clientside", "hygiene", False, "K13525",
        "Action when server response headers exceed maxHeaderSize.",
        "'pass-through' disables L7 HTTP inspection; keep 'reject' and size maxHeaderSize properly.",
    ),
    ProfileSettingSpec(
        "http", "Enforcement", "Maximum Header Count", "enforcement.maxHeaderCount", 64,
        "16..4096 headers", "clientside", "telemetry", True, "K13525",
        "Maximum number of HTTP headers allowed per request/response.",
        "Raise to 128 when microservice/CDN tracing headers trip maxHeaderCountExceeded.",
    ),
    ProfileSettingSpec(
        "http", "Enforcement", "Excess Client Headers", "enforcement.excessClientHeaders", "reject",
        "reject | pass-through", "clientside", "hygiene", False, "K13525",
        "Action when client header count exceeds maxHeaderCount.",
        "'pass-through' bypasses L7 inspection; keep 'reject'.",
    ),
    ProfileSettingSpec(
        "http", "Enforcement", "Excess Server Headers", "enforcement.excessServerHeaders", "reject",
        "reject | pass-through", "clientside", "hygiene", False, "K13525",
        "Action when server header count exceeds maxHeaderCount.",
        "'pass-through' bypasses L7 inspection; keep 'reject'.",
    ),
    ProfileSettingSpec(
        "http", "Enforcement", "Pipeline Action", "enforcement.pipeline", "allow",
        "allow | reject | pass-through", "clientside", "telemetry", False, "K7208",
        "Controls HTTP/1.1 request pipelining.",
        "'pass-through' disables HTTP filter on pipelined data; 'reject' blocks HoL/desync when no legacy clients pipeline.",
    ),
    ProfileSettingSpec(
        "http", "Enforcement", "Unknown Method", "enforcement.unknownMethod", "allow",
        "allow | reject | pass-through", "clientside", "dependency", False, "K13525",
        "Action when an HTTP method not in knownMethods is parsed.",
        "If set to 'reject', ensure 'PATCH' is added to knownMethods for REST APIs! Never use 'pass-through'.",
    ),
    ProfileSettingSpec(
        "http", "Enforcement", "Known Method", "enforcement.knownMethods",
        "CONNECT DELETE GET HEAD LOCK OPTIONS POST PROPFIND PUT TRACE UNLOCK",
        "list of HTTP method strings", "clientside", "dependency", False, "K13525",
        "List of HTTP methods recognized for L7 optimization.",
        "Default list omits PATCH and includes TRACE; interacts directly with unknownMethod.",
    ),
    # 3. Explicit Proxy (11 — active only when proxyType='explicit')
    ProfileSettingSpec(
        "http", "Explicit Proxy", "DNS Resolver", "explicitProxy.dnsResolver", "none",
        "/Partition/resolver_name", "clientside", "dependency", False, "K40243113",
        "DNS Resolver object used by explicit forward-proxy VIPs.",
        "Mandatory when proxyType='explicit'.",
    ),
    ProfileSettingSpec(
        "http", "Explicit Proxy", "IPv6", "explicitProxy.ipv6", "disabled",
        "enabled | disabled", "clientside", "policy", False, "K40243113",
        "Controls IPv6 vs IPv4 DNS lookup preference for explicit proxy URIs.",
    ),
    ProfileSettingSpec(
        "http", "Explicit Proxy", "Route Domain", "explicitProxy.routeDomain", "0",
        "route domain ID/path", "clientside", "dependency", False, "K40243113",
        "Route domain used for outbound explicit proxy connections.",
    ),
    ProfileSettingSpec(
        "http", "Explicit Proxy", "Tunnel Name", "explicitProxy.tunnelName", "none",
        "tunnel path", "clientside", "dependency", False, "K40243113",
        "Tunnel carrying outbound proxy CONNECT traffic to internal listener VIPs.",
        "Required when defaultConnectHandling='deny' or tunnelOnAnyRequest='enabled'.",
    ),
    ProfileSettingSpec(
        "http", "Explicit Proxy", "Host Names", "explicitProxy.hostNames", "none",
        "list of hostnames", "clientside", "policy", False, "K40243113",
        "Hosts excluded from explicit forward proxying.",
    ),
    ProfileSettingSpec(
        "http", "Explicit Proxy", "Use Tunnel On Any Request Method", "explicitProxy.tunnelOnAnyRequest", "disabled",
        "enabled | disabled", "clientside", "dependency", False, "K40243113",
        "Routes non-CONNECT explicit proxy requests through the configured TCP tunnel.",
    ),
    ProfileSettingSpec(
        "http", "Explicit Proxy", "Default Connect Handling", "explicitProxy.defaultConnectHandling", "deny",
        "allow | deny", "clientside", "dependency", False, "K40243113",
        "Controls whether outbound proxy requests bypass tunnel listener VIPs ('allow' = open egress).",
    ),
    ProfileSettingSpec(
        "http", "Explicit Proxy", "Connection Failed Message", "explicitProxy.connectErrorMessage", "default",
        "string / TCL", "clientside", "policy", False, "K40243113",
        "Error page message returned when outbound proxy connection fails.",
    ),
    ProfileSettingSpec(
        "http", "Explicit Proxy", "DNS Lookup Failed Message", "explicitProxy.dnsErrorMessage", "default",
        "string / TCL", "clientside", "policy", False, "K40243113",
        "Error page message returned when explicit proxy DNS lookup fails.",
    ),
    ProfileSettingSpec(
        "http", "Explicit Proxy", "Bad Request Message", "explicitProxy.badRequestMessage", "default",
        "string / TCL", "clientside", "policy", False, "K40243113",
        "Error page message returned on malformed explicit proxy request.",
    ),
    ProfileSettingSpec(
        "http", "Explicit Proxy", "Bad Response Message", "explicitProxy.badResponseMessage", "default",
        "string / TCL", "clientside", "policy", False, "K40243113",
        "Error page message returned on invalid upstream response.",
    ),
    # 4. sFlow (2)
    ProfileSettingSpec(
        "http", "sFlow", "Polling Interval", "sflow.pollInterval", 10,
        "global | 1..86400s", "clientside", "hygiene", True, "K40243113",
        "Maximum interval in seconds between HTTP sFlow counter pollings.",
        "Very short custom intervals (<5s) add control-plane polling load across many VIPs.",
    ),
    ProfileSettingSpec(
        "http", "sFlow", "Sampling Rate", "sflow.samplingRate", 1024,
        "global | 1..102400 packets", "clientside", "telemetry", True, "K40243113",
        "Packet ratio for generating random HTTP sFlow samples (1 in N).",
        "Aggressive custom rates (<128) on high-PPS VIPs spike TMM CPU.",
    ),
    # 5. HTTP Strict Transport Security (4)
    ProfileSettingSpec(
        "http", "HTTP Strict Transport Security", "Mode", "hsts.mode", "disabled",
        "enabled | disabled", "clientside", "dependency", False, "K68657325",
        "Injects Strict-Transport-Security response header.",
        "Effective ONLY on HTTPS VIPs with ClientSSL; enabling defaults includeSubdomains=enabled!",
    ),
    ProfileSettingSpec(
        "http", "HTTP Strict Transport Security", "Maximum Age", "hsts.maximumAge", 16070400,
        "0..2147483647 seconds", "clientside", "dependency", True, "K68657325",
        "max-age directive (seconds) instructing browsers to enforce HTTPS.",
        "0 revokes HSTS; hsts.preload=enabled requires maximumAge >= 31536000 (1 year).",
    ),
    ProfileSettingSpec(
        "http", "HTTP Strict Transport Security", "Include Subdomains", "hsts.includeSubdomains", "enabled",
        "enabled | disabled", "clientside", "dependency", False, "K68657325",
        "Applies HSTS policy to all subdomains of the host.",
        "Required when hsts.preload=enabled; breaks plain-HTTP legacy subdomains if enabled prematurely.",
    ),
    ProfileSettingSpec(
        "http", "HTTP Strict Transport Security", "Preload", "hsts.preload", "disabled",
        "enabled | disabled", "clientside", "dependency", False, "K68657325",
        "Appends 'preload' directive for browser HSTS preload lists.",
        "Requires hsts.mode=enabled, includeSubdomains=enabled, and maximumAge >= 31536000.",
    ),
)

ALL_PROFILE_SETTINGS: tuple[ProfileSettingSpec, ...] = TCP_SETTINGS + UDP_SETTINGS + HTTP_SETTINGS

SETTINGS_BY_PROTOCOL: dict[ProtocolType, tuple[ProfileSettingSpec, ...]] = {
    "tcp": TCP_SETTINGS,
    "udp": UDP_SETTINGS,
    "http": HTTP_SETTINGS,
}

SETTINGS_BY_REST_KEY: dict[tuple[ProtocolType, str], ProfileSettingSpec] = {
    (s.protocol, s.rest_key): s for s in ALL_PROFILE_SETTINGS
}


def list_profile_settings(protocol: ProtocolType | None = None) -> list[dict[str, Any]]:
    items = SETTINGS_BY_PROTOCOL[protocol] if protocol else ALL_PROFILE_SETTINGS
    return [asdict(s) for s in items]

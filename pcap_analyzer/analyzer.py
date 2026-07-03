from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
import ipaddress
from pathlib import Path

from .parser import ParsedPacket, parse_packet, read_packets


RISKY_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    110: "POP3",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
}


@dataclass(frozen=True)
class SuspiciousFinding:
    severity: str
    title: str
    details: str
    evidence: dict[str, object]


@dataclass(frozen=True)
class FlowSummary:
    flow: str
    protocol: str
    packets: int
    bytes: int
    first_timestamp: float | None
    last_timestamp: float | None
    duration_seconds: float


@dataclass(frozen=True)
class AnalysisFilters:
    host: str | None = None
    protocol: str | None = None
    port: int | None = None


@dataclass(frozen=True)
class AnalysisResult:
    file: str
    filters: dict[str, object]
    packet_count: int
    byte_count: int
    duration_seconds: float
    risk_score: int
    risk_level: str
    first_timestamp: float | None
    last_timestamp: float | None
    protocols: list[tuple[str, int]]
    top_talkers: list[tuple[str, int]]
    top_connections: list[tuple[str, int]]
    top_flows: list[FlowSummary]
    suspicious: list[SuspiciousFinding]

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["protocols"] = [{"protocol": name, "packets": count} for name, count in self.protocols]
        data["top_talkers"] = [{"host": host, "packets": count} for host, count in self.top_talkers]
        data["top_connections"] = [{"connection": conn, "packets": count} for conn, count in self.top_connections]
        data["top_flows"] = [asdict(flow) for flow in self.top_flows]
        return data


def analyze_file(path: str | Path, limit: int = 10) -> AnalysisResult:
    packets = [parse_packet(raw) for raw in read_packets(path)]
    return analyze_packets(path, packets, limit=limit)


def analyze_filtered_file(
    path: str | Path,
    limit: int = 10,
    host: str | None = None,
    protocol: str | None = None,
    port: int | None = None,
) -> AnalysisResult:
    filters = AnalysisFilters(host=host, protocol=protocol, port=port)
    packets = [packet for packet in (parse_packet(raw) for raw in read_packets(path)) if _matches_filters(packet, filters)]
    return analyze_packets(path, packets, limit=limit, filters=filters)


def analyze_packets(
    path: str | Path,
    packets: list[ParsedPacket],
    limit: int = 10,
    filters: AnalysisFilters | None = None,
) -> AnalysisResult:
    timestamps = [packet.timestamp for packet in packets if packet.timestamp > 0]

    protocol_counts = Counter(packet.protocol_label for packet in packets)
    talkers: Counter[str] = Counter()
    connections: Counter[str] = Counter()
    flow_packets: dict[tuple[str, str, str], list[ParsedPacket]] = defaultdict(list)
    for packet in packets:
        if packet.src_ip:
            talkers[packet.src_ip] += 1
        if packet.dst_ip:
            talkers[packet.dst_ip] += 1
        connection = _connection_label(packet)
        if connection:
            connections[connection] += 1
        flow_key = _flow_key(packet)
        if flow_key:
            flow_packets[flow_key].append(packet)

    suspicious = _find_suspicious(packets, limit)
    risk_score = _risk_score(suspicious)
    top_flows = _summarize_flows(flow_packets, limit)

    return AnalysisResult(
        file=str(path),
        filters=_filters_to_dict(filters),
        packet_count=len(packets),
        byte_count=sum(packet.length for packet in packets),
        duration_seconds=(max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 0.0,
        risk_score=risk_score,
        risk_level=_risk_level(risk_score),
        first_timestamp=min(timestamps) if timestamps else None,
        last_timestamp=max(timestamps) if timestamps else None,
        protocols=protocol_counts.most_common(limit),
        top_talkers=talkers.most_common(limit),
        top_connections=connections.most_common(limit),
        top_flows=top_flows,
        suspicious=suspicious,
    )


def _matches_filters(packet: ParsedPacket, filters: AnalysisFilters) -> bool:
    if filters.host and filters.host not in {packet.src_ip, packet.dst_ip}:
        return False
    if filters.port and filters.port not in {packet.src_port, packet.dst_port}:
        return False
    if filters.protocol:
        expected = filters.protocol.upper()
        labels = {
            packet.protocol_label.upper(),
            (packet.transport or "").upper(),
            (packet.application or "").upper(),
            (packet.l2_protocol or "").upper(),
        }
        if expected not in labels:
            return False
    return True


def _filters_to_dict(filters: AnalysisFilters | None) -> dict[str, object]:
    if filters is None:
        return {}
    data: dict[str, object] = {}
    if filters.host:
        data["host"] = filters.host
    if filters.protocol:
        data["protocol"] = filters.protocol
    if filters.port:
        data["port"] = filters.port
    return data


def _find_suspicious(packets: list[ParsedPacket], limit: int) -> list[SuspiciousFinding]:
    findings: list[SuspiciousFinding] = []
    ports_by_src: dict[str, set[int]] = defaultdict(set)
    hosts_by_src: dict[str, set[str]] = defaultdict(set)
    risky_hits: Counter[tuple[str, str, int, str]] = Counter()
    syn_without_ack: Counter[str] = Counter()
    dns_hosts: Counter[str] = Counter()

    for packet in packets:
        if not packet.src_ip or not packet.dst_ip:
            continue

        if packet.dst_port:
            ports_by_src[packet.src_ip].add(packet.dst_port)
            hosts_by_src[packet.src_ip].add(packet.dst_ip)

        if packet.dst_port in RISKY_PORTS:
            risky_hits[(packet.src_ip, packet.dst_ip, packet.dst_port, RISKY_PORTS[packet.dst_port])] += 1

        if packet.transport == "TCP" and packet.tcp_flags is not None:
            syn = bool(packet.tcp_flags & 0x02)
            ack = bool(packet.tcp_flags & 0x10)
            if syn and not ack:
                syn_without_ack[packet.src_ip] += 1

        if packet.dst_port == 53:
            dns_hosts[packet.src_ip] += 1

    for src, ports in sorted(ports_by_src.items(), key=lambda item: len(item[1]), reverse=True)[:limit]:
        hosts = hosts_by_src[src]
        if len(ports) >= 20 or (len(ports) >= 10 and len(hosts) >= 5):
            findings.append(
                SuspiciousFinding(
                    "wysokie",
                    "Mozliwe skanowanie portow",
                    f"Host {src} laczyl sie z {len(ports)} portami na {len(hosts)} hostach.",
                    {"src_ip": src, "unique_ports": len(ports), "unique_hosts": len(hosts), "sample_ports": sorted(ports)[:15]},
                )
            )

    for src, count in syn_without_ack.most_common(limit):
        if count >= 30:
            findings.append(
                SuspiciousFinding(
                    "srednie",
                    "Duza liczba pakietow TCP SYN",
                    f"Host {src} wyslal {count} pakietow SYN bez flagi ACK.",
                    {"src_ip": src, "syn_packets": count},
                )
            )

    for (src, dst, port, service), count in risky_hits.most_common(limit):
        if count >= 3 or port in {23, 445, 3389, 5900}:
            findings.append(
                SuspiciousFinding(
                    "srednie",
                    f"Ruch do uslugi podwyzszonego ryzyka: {service}",
                    f"{src} -> {dst}:{port} ({count} pakietow).",
                    {"src_ip": src, "dst_ip": dst, "dst_port": port, "service": service, "packets": count},
                )
            )

    for src, count in dns_hosts.most_common(limit):
        if count >= 100:
            findings.append(
                SuspiciousFinding(
                    "niskie",
                    "Nietypowo duzo zapytan DNS",
                    f"Host {src} wyslal {count} pakietow do portu DNS.",
                    {"src_ip": src, "dns_packets": count},
                )
            )

    external_to_private = Counter(
        (packet.src_ip, packet.dst_ip, packet.dst_port)
        for packet in packets
        if packet.src_ip and packet.dst_ip and packet.dst_port and not _is_private(packet.src_ip) and _is_private(packet.dst_ip)
    )
    for (src, dst, port), count in external_to_private.most_common(limit):
        if count >= 3:
            findings.append(
                SuspiciousFinding(
                    "srednie",
                    "Polaczenie z zewnatrz do adresu prywatnego",
                    f"{src} -> {dst}:{port} ({count} pakietow).",
                    {"src_ip": src, "dst_ip": dst, "dst_port": port, "packets": count},
                )
            )

    return findings[:limit]


def _connection_label(packet: ParsedPacket) -> str | None:
    if not packet.src_ip or not packet.dst_ip:
        return None
    left = f"{packet.src_ip}:{packet.src_port}" if packet.src_port else packet.src_ip
    right = f"{packet.dst_ip}:{packet.dst_port}" if packet.dst_port else packet.dst_ip
    protocol = packet.application or packet.transport or packet.l2_protocol or ""
    return f"{left} -> {right} {protocol}".strip()


def _flow_key(packet: ParsedPacket) -> tuple[str, str, str] | None:
    if not packet.src_ip or not packet.dst_ip:
        return None
    src = f"{packet.src_ip}:{packet.src_port}" if packet.src_port else packet.src_ip
    dst = f"{packet.dst_ip}:{packet.dst_port}" if packet.dst_port else packet.dst_ip
    left, right = sorted((src, dst))
    protocol = packet.application or packet.transport or packet.l2_protocol or "UNKNOWN"
    return left, right, protocol


def _summarize_flows(flow_packets: dict[tuple[str, str, str], list[ParsedPacket]], limit: int) -> list[FlowSummary]:
    flows: list[FlowSummary] = []
    for (left, right, protocol), packets in flow_packets.items():
        timestamps = [packet.timestamp for packet in packets if packet.timestamp > 0]
        first_timestamp = min(timestamps) if timestamps else None
        last_timestamp = max(timestamps) if timestamps else None
        duration = (last_timestamp - first_timestamp) if first_timestamp is not None and last_timestamp is not None else 0.0
        flows.append(
            FlowSummary(
                flow=f"{left} <-> {right}",
                protocol=protocol,
                packets=len(packets),
                bytes=sum(packet.length for packet in packets),
                first_timestamp=first_timestamp,
                last_timestamp=last_timestamp,
                duration_seconds=duration,
            )
        )
    return sorted(flows, key=lambda flow: (flow.packets, flow.bytes), reverse=True)[:limit]


def _is_private(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _risk_score(findings: list[SuspiciousFinding]) -> int:
    weights = {"niskie": 10, "srednie": 25, "wysokie": 70}
    score = sum(weights.get(finding.severity, 15) for finding in findings)
    if len(findings) >= 5:
        score += 10
    return min(score, 100)


def _risk_level(score: int) -> str:
    if score >= 70:
        return "wysokie"
    if score >= 35:
        return "srednie"
    if score > 0:
        return "niskie"
    return "brak"

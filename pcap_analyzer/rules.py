from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import ipaddress

from .parser import ParsedPacket


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
    rule_id: str = "GENERIC"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    description: str


RULES = [
    Rule("PORT_SCAN", "Mozliwe skanowanie portow", "wysokie", "Jeden host odpytuje wiele portow lub wiele hostow."),
    Rule("SYN_FLOOD", "Duza liczba pakietow TCP SYN", "srednie", "Wiele pakietow SYN bez flagi ACK z jednego zrodla."),
    Rule("RISKY_SERVICE", "Ruch do uslugi podwyzszonego ryzyka", "srednie", "Ruch do portow administracyjnych lub podatnych na naduzycia."),
    Rule("DNS_SPIKE", "Nietypowo duzo zapytan DNS", "niskie", "Wysoka liczba pakietow DNS z jednego hosta."),
    Rule("EXTERNAL_TO_PRIVATE", "Polaczenie z zewnatrz do adresu prywatnego", "srednie", "Zewnetrzny adres kieruje ruch do adresu prywatnego."),
    Rule("PACKET_BURST", "Nagly burst pakietow", "srednie", "Duza liczba pakietow w jednej sekundzie."),
    Rule("NULL_SCAN", "Podejrzenie TCP NULL scan", "wysokie", "Pakiety TCP bez ustawionych flag."),
    Rule("XMAS_SCAN", "Podejrzenie TCP Xmas scan", "wysokie", "Pakiety TCP z flagami FIN, PSH i URG."),
    Rule("FIN_SCAN", "Podejrzenie TCP FIN scan", "srednie", "Wiele pakietow TCP FIN bez ACK z jednego zrodla."),
    Rule("SMB_OR_RDP_EXPOSURE", "Ruch do wrazliwej uslugi Windows", "wysokie", "Ruch do SMB lub RDP moze wskazywac na ekspozycje administracyjna."),
]


def detect_suspicious(packets: list[ParsedPacket], limit: int) -> list[SuspiciousFinding]:
    findings: list[SuspiciousFinding] = []
    findings.extend(_port_scan(packets, limit))
    findings.extend(_syn_flood(packets, limit))
    findings.extend(_risky_services(packets, limit))
    findings.extend(_dns_spike(packets, limit))
    findings.extend(_external_to_private(packets, limit))
    findings.extend(_packet_burst(packets))
    findings.extend(_tcp_scan_flags(packets, limit))
    findings.extend(_windows_exposure(packets, limit))
    return findings[:limit]


def _port_scan(packets: list[ParsedPacket], limit: int) -> list[SuspiciousFinding]:
    ports_by_src: dict[str, set[int]] = defaultdict(set)
    hosts_by_src: dict[str, set[str]] = defaultdict(set)
    for packet in packets:
        if packet.src_ip and packet.dst_ip and packet.dst_port:
            ports_by_src[packet.src_ip].add(packet.dst_port)
            hosts_by_src[packet.src_ip].add(packet.dst_ip)

    findings: list[SuspiciousFinding] = []
    for src, ports in sorted(ports_by_src.items(), key=lambda item: len(item[1]), reverse=True)[:limit]:
        hosts = hosts_by_src[src]
        if len(ports) >= 20 or (len(ports) >= 10 and len(hosts) >= 5):
            findings.append(
                SuspiciousFinding(
                    "wysokie",
                    "Mozliwe skanowanie portow",
                    f"Host {src} laczyl sie z {len(ports)} portami na {len(hosts)} hostach.",
                    {"src_ip": src, "unique_ports": len(ports), "unique_hosts": len(hosts), "sample_ports": sorted(ports)[:15]},
                    "PORT_SCAN",
                )
            )
    return findings


def _syn_flood(packets: list[ParsedPacket], limit: int) -> list[SuspiciousFinding]:
    syn_without_ack: Counter[str] = Counter()
    for packet in packets:
        if packet.src_ip and packet.transport == "TCP" and packet.tcp_flags is not None:
            syn = bool(packet.tcp_flags & 0x02)
            ack = bool(packet.tcp_flags & 0x10)
            if syn and not ack:
                syn_without_ack[packet.src_ip] += 1

    findings: list[SuspiciousFinding] = []
    for src, count in syn_without_ack.most_common(limit):
        if count >= 30:
            findings.append(
                SuspiciousFinding(
                    "srednie",
                    "Duza liczba pakietow TCP SYN",
                    f"Host {src} wyslal {count} pakietow SYN bez flagi ACK.",
                    {"src_ip": src, "syn_packets": count},
                    "SYN_FLOOD",
                )
            )
    return findings


def _risky_services(packets: list[ParsedPacket], limit: int) -> list[SuspiciousFinding]:
    risky_hits: Counter[tuple[str, str, int, str]] = Counter()
    for packet in packets:
        if packet.src_ip and packet.dst_ip and packet.dst_port in RISKY_PORTS:
            risky_hits[(packet.src_ip, packet.dst_ip, packet.dst_port, RISKY_PORTS[packet.dst_port])] += 1

    findings: list[SuspiciousFinding] = []
    for (src, dst, port, service), count in risky_hits.most_common(limit):
        if count >= 3 or port in {23, 445, 3389, 5900}:
            findings.append(
                SuspiciousFinding(
                    "srednie",
                    f"Ruch do uslugi podwyzszonego ryzyka: {service}",
                    f"{src} -> {dst}:{port} ({count} pakietow).",
                    {"src_ip": src, "dst_ip": dst, "dst_port": port, "service": service, "packets": count},
                    "RISKY_SERVICE",
                )
            )
    return findings


def _dns_spike(packets: list[ParsedPacket], limit: int) -> list[SuspiciousFinding]:
    dns_hosts: Counter[str] = Counter()
    for packet in packets:
        if packet.src_ip and packet.dst_port == 53:
            dns_hosts[packet.src_ip] += 1

    findings: list[SuspiciousFinding] = []
    for src, count in dns_hosts.most_common(limit):
        if count >= 100:
            findings.append(
                SuspiciousFinding(
                    "niskie",
                    "Nietypowo duzo zapytan DNS",
                    f"Host {src} wyslal {count} pakietow do portu DNS.",
                    {"src_ip": src, "dns_packets": count},
                    "DNS_SPIKE",
                )
            )
    return findings


def _external_to_private(packets: list[ParsedPacket], limit: int) -> list[SuspiciousFinding]:
    external_to_private = Counter(
        (packet.src_ip, packet.dst_ip, packet.dst_port)
        for packet in packets
        if packet.src_ip and packet.dst_ip and packet.dst_port and not _is_private(packet.src_ip) and _is_private(packet.dst_ip)
    )

    findings: list[SuspiciousFinding] = []
    for (src, dst, port), count in external_to_private.most_common(limit):
        if count >= 3:
            findings.append(
                SuspiciousFinding(
                    "srednie",
                    "Polaczenie z zewnatrz do adresu prywatnego",
                    f"{src} -> {dst}:{port} ({count} pakietow).",
                    {"src_ip": src, "dst_ip": dst, "dst_port": port, "packets": count},
                    "EXTERNAL_TO_PRIVATE",
                )
            )
    return findings


def _packet_burst(packets: list[ParsedPacket]) -> list[SuspiciousFinding]:
    packets_per_second: Counter[int] = Counter()
    for packet in packets:
        if packet.src_ip and packet.dst_ip and packet.timestamp > 0:
            packets_per_second[int(packet.timestamp)] += 1
    if not packets_per_second:
        return []
    second, count = packets_per_second.most_common(1)[0]
    threshold = max(50, int(len(packets) * 0.40))
    if count < threshold:
        return []
    return [
        SuspiciousFinding(
            "srednie",
            "Nagly burst pakietow",
            f"W sekundzie {second} wykryto {count} pakietow.",
            {"timestamp_second": second, "packets": count, "threshold": threshold},
            "PACKET_BURST",
        )
    ]


def _tcp_scan_flags(packets: list[ParsedPacket], limit: int) -> list[SuspiciousFinding]:
    null_scan: Counter[str] = Counter()
    xmas_scan: Counter[str] = Counter()
    fin_scan: Counter[str] = Counter()
    for packet in packets:
        if not packet.src_ip or packet.transport != "TCP" or packet.tcp_flags is None:
            continue
        flags = packet.tcp_flags
        if flags == 0:
            null_scan[packet.src_ip] += 1
        if flags & 0x29 == 0x29:
            xmas_scan[packet.src_ip] += 1
        if flags == 0x01:
            fin_scan[packet.src_ip] += 1

    findings: list[SuspiciousFinding] = []
    findings.extend(_flag_findings(null_scan, limit, 3, "wysokie", "Podejrzenie TCP NULL scan", "NULL_SCAN"))
    findings.extend(_flag_findings(xmas_scan, limit, 3, "wysokie", "Podejrzenie TCP Xmas scan", "XMAS_SCAN"))
    findings.extend(_flag_findings(fin_scan, limit, 5, "srednie", "Podejrzenie TCP FIN scan", "FIN_SCAN"))
    return findings


def _flag_findings(
    counter: Counter[str],
    limit: int,
    threshold: int,
    severity: str,
    title: str,
    rule_id: str,
) -> list[SuspiciousFinding]:
    findings: list[SuspiciousFinding] = []
    for src, count in counter.most_common(limit):
        if count >= threshold:
            findings.append(
                SuspiciousFinding(
                    severity,
                    title,
                    f"Host {src} wyslal {count} pakietow pasujacych do reguly {rule_id}.",
                    {"src_ip": src, "packets": count, "threshold": threshold},
                    rule_id,
                )
            )
    return findings


def _windows_exposure(packets: list[ParsedPacket], limit: int) -> list[SuspiciousFinding]:
    hits: Counter[tuple[str, str, int]] = Counter()
    for packet in packets:
        if packet.src_ip and packet.dst_ip and packet.dst_port in {445, 3389}:
            hits[(packet.src_ip, packet.dst_ip, packet.dst_port)] += 1

    findings: list[SuspiciousFinding] = []
    for (src, dst, port), count in hits.most_common(limit):
        if count >= 1:
            service = "SMB" if port == 445 else "RDP"
            findings.append(
                SuspiciousFinding(
                    "wysokie",
                    "Ruch do wrazliwej uslugi Windows",
                    f"{src} -> {dst}:{port} ({service}, {count} pakietow).",
                    {"src_ip": src, "dst_ip": dst, "dst_port": port, "service": service, "packets": count},
                    "SMB_OR_RDP_EXPOSURE",
                )
            )
    return findings


def _is_private(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False

from __future__ import annotations

from dataclasses import asdict, dataclass

from .analyzer import AnalysisResult


@dataclass(frozen=True)
class ComparisonResult:
    base_file: str
    other_file: str
    packet_delta: int
    byte_delta: int
    risk_score_delta: int
    new_hosts: list[str]
    new_protocols: list[str]
    new_ports: list[int]
    new_flows: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def compare_results(base: AnalysisResult, other: AnalysisResult, limit: int = 20) -> ComparisonResult:
    base_hosts = {host for host, _count in base.top_talkers}
    other_hosts = {host for host, _count in other.top_talkers}
    base_protocols = {protocol for protocol, _count in base.protocols}
    other_protocols = {protocol for protocol, _count in other.protocols}
    base_ports = _ports(base)
    other_ports = _ports(other)
    base_flows = {flow.flow for flow in base.top_flows}
    other_flows = {flow.flow for flow in other.top_flows}

    return ComparisonResult(
        base_file=base.file,
        other_file=other.file,
        packet_delta=other.packet_count - base.packet_count,
        byte_delta=other.byte_count - base.byte_count,
        risk_score_delta=other.risk_score - base.risk_score,
        new_hosts=sorted(other_hosts - base_hosts)[:limit],
        new_protocols=sorted(other_protocols - base_protocols)[:limit],
        new_ports=sorted(other_ports - base_ports)[:limit],
        new_flows=sorted(other_flows - base_flows)[:limit],
    )


def _ports(result: AnalysisResult) -> set[int]:
    ports: set[int] = set()
    for packet in result.packets:
        if packet.src_port:
            ports.add(packet.src_port)
        if packet.dst_port:
            ports.add(packet.dst_port)
    return ports

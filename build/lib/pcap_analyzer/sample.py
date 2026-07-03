from __future__ import annotations

import ipaddress
from pathlib import Path
import struct


def generate_sample_pcap(path: str | Path) -> Path:
    output = Path(path)
    frames: list[tuple[float, bytes]] = []

    frames.append((1.000, _tcp_frame("10.0.0.5", "93.184.216.34", 50100, 443)))
    frames.append((1.050, _tcp_frame("93.184.216.34", "10.0.0.5", 443, 50100, flags=0x12)))
    frames.append((1.100, _tcp_frame("10.0.0.5", "93.184.216.34", 50101, 80)))
    frames.append((2.000, _udp_frame("10.0.0.5", "8.8.8.8", 53000, 53)))
    frames.append((2.100, _udp_frame("8.8.8.8", "10.0.0.5", 53, 53000)))

    for index, port in enumerate(range(20, 45)):
        frames.append((3.000 + (index / 1000), _tcp_frame("10.0.0.9", "10.0.0.20", 41000 + index, port)))

    _write_pcap(output, frames)
    return output


def _write_pcap(path: Path, frames: list[tuple[float, bytes]]) -> None:
    header = struct.pack("<IHHiiii", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = []
    for timestamp, frame in frames:
        seconds = int(timestamp)
        micros = int((timestamp - seconds) * 1_000_000)
        records.append(struct.pack("<IIII", seconds, micros, len(frame), len(frame)) + frame)
    path.write_bytes(header + b"".join(records))


def _tcp_frame(src: str, dst: str, sport: int, dport: int, flags: int = 0x02) -> bytes:
    tcp = struct.pack("!HHIIHHHH", sport, dport, 0, 0, (5 << 12) | flags, 8192, 0, 0)
    return _ethernet_ipv4(src, dst, 6, tcp)


def _udp_frame(src: str, dst: str, sport: int, dport: int) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8, 0)
    return _ethernet_ipv4(src, dst, 17, udp)


def _ethernet_ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800)
    total_len = 20 + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        1,
        0,
        64,
        proto,
        0,
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    return eth + ip + payload

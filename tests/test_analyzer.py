from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from pcap_analyzer.analyzer import analyze_file


def ethernet_ipv4_tcp(src: str, dst: str, sport: int, dport: int, flags: int = 0x02) -> bytes:
    import ipaddress

    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800)
    tcp = struct.pack("!HHIIHHHH", sport, dport, 0, 0, (5 << 12) | flags, 8192, 0, 0)
    total_len = 20 + len(tcp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        1,
        0,
        64,
        6,
        0,
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    return eth + ip + tcp


def write_pcap(path: Path, frames: list[bytes]) -> None:
    header = struct.pack("<IHHiiii", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = []
    for index, frame in enumerate(frames):
        records.append(struct.pack("<IIII", index, 0, len(frame), len(frame)) + frame)
    path.write_bytes(header + b"".join(records))


class AnalyzerTests(unittest.TestCase):
    def test_counts_protocols_and_suspicious_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.pcap"
            frames = [ethernet_ipv4_tcp("10.0.0.5", "10.0.0.10", 40000 + port, port) for port in range(1, 22)]
            write_pcap(path, frames)

            result = analyze_file(path)

            self.assertEqual(result.packet_count, 21)
            self.assertEqual(result.protocols[0], ("TCP", 21))
            self.assertTrue(any("skanowanie" in finding.title.lower() for finding in result.suspicious))


if __name__ == "__main__":
    unittest.main()

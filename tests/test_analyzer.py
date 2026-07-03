from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from pcap_analyzer.analyzer import analyze_file, analyze_filtered_file
from pcap_analyzer.csv_export import write_csv_exports
from pcap_analyzer.report import write_html_report


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
            self.assertEqual(result.protocols[0], ("TCP", 19))
            self.assertIn(("FTP", 1), result.protocols)
            self.assertEqual(result.risk_score, 70)
            self.assertEqual(result.risk_level, "wysokie")
            self.assertEqual(result.top_flows[0].packets, 1)
            self.assertTrue(any("skanowanie" in finding.title.lower() for finding in result.suspicious))

    def test_classifies_application_protocols_and_filters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "web.pcap"
            frames = [
                ethernet_ipv4_tcp("10.0.0.5", "93.184.216.34", 50000, 443),
                ethernet_ipv4_tcp("10.0.0.5", "93.184.216.34", 50001, 80),
                ethernet_ipv4_tcp("10.0.0.9", "10.0.0.10", 50002, 22),
            ]
            write_pcap(path, frames)

            result = analyze_file(path)
            filtered = analyze_filtered_file(path, protocol="HTTPS")
            host_filtered = analyze_filtered_file(path, host="10.0.0.9")
            port_filtered = analyze_filtered_file(path, port=80)

            self.assertIn(("HTTPS", 1), result.protocols)
            self.assertIn(("HTTP", 1), result.protocols)
            self.assertEqual(filtered.packet_count, 1)
            self.assertEqual(filtered.protocols, [("HTTPS", 1)])
            self.assertEqual(host_filtered.packet_count, 1)
            self.assertEqual(port_filtered.protocols, [("HTTP", 1)])
            self.assertEqual(result.top_flows[0].flow, "10.0.0.5:50000 <-> 93.184.216.34:443")
            self.assertEqual(result.top_flows[0].protocol, "HTTPS")

    def test_writes_html_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pcap_path = Path(tmp) / "scan.pcap"
            report_path = Path(tmp) / "report.html"
            frames = [ethernet_ipv4_tcp("10.0.0.5", "10.0.0.10", 40000 + port, port) for port in range(1, 22)]
            write_pcap(pcap_path, frames)

            result = analyze_file(pcap_path)
            write_html_report(result, report_path)

            html = report_path.read_text(encoding="utf-8")
            self.assertIn("PCAP Analyzer Report", html)
            self.assertIn("70/100", html)
            self.assertIn("Mozliwe skanowanie portow", html)
            self.assertIn("Najwieksze sesje / flow", html)

    def test_writes_csv_exports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pcap_path = Path(tmp) / "web.pcap"
            csv_dir = Path(tmp) / "csv"
            frames = [ethernet_ipv4_tcp("10.0.0.5", "93.184.216.34", 50000, 443)]
            write_pcap(pcap_path, frames)

            result = analyze_file(pcap_path)
            write_csv_exports(result, csv_dir)

            self.assertTrue((csv_dir / "summary.csv").exists())
            self.assertTrue((csv_dir / "protocols.csv").exists())
            self.assertTrue((csv_dir / "flows.csv").exists())
            self.assertIn("HTTPS", (csv_dir / "protocols.csv").read_text(encoding="utf-8"))
            self.assertIn("93.184.216.34:443", (csv_dir / "flows.csv").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

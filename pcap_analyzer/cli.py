from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .analyzer import analyze_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analizator plikow PCAP/PCAPNG z Wiresharka.")
    parser.add_argument("file", help="Sciezka do pliku .pcap lub .pcapng")
    parser.add_argument("--json", action="store_true", help="Wypisz wynik jako JSON")
    parser.add_argument("--limit", type=int, default=10, help="Limit pozycji w rankingach")
    args = parser.parse_args(argv)

    path = Path(args.file)
    if not path.exists():
        print(f"Blad: plik nie istnieje: {path}", file=sys.stderr)
        return 2

    try:
        result = analyze_file(path, limit=args.limit)
    except ValueError as exc:
        print(f"Blad analizy: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        _print_human(result)
    return 0


def _print_human(result) -> None:
    print("PCAP Analyzer")
    print(f"Plik: {result.file}")
    print(f"Pakiety: {result.packet_count}")
    print(f"Bajty: {result.byte_count}")
    print(f"Czas trwania: {result.duration_seconds:.3f} s")

    print("\nNajczestsze protokoly:")
    for protocol, count in result.protocols:
        print(f"  - {protocol}: {count}")

    print("\nNajaktywniejsze hosty:")
    for host, count in result.top_talkers:
        print(f"  - {host}: {count}")

    print("\nNajczestsze polaczenia:")
    for connection, count in result.top_connections:
        print(f"  - {connection}: {count}")

    print("\nPodejrzane polaczenia:")
    if not result.suspicious:
        print("  - Brak wykrytych anomalii wedlug prostych heurystyk.")
    for finding in result.suspicious:
        print(f"  - [{finding.severity}] {finding.title}: {finding.details}")

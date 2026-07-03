from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .analyzer import analyze_filtered_file
from .csv_export import write_csv_exports
from .report import write_html_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analizator plikow PCAP/PCAPNG z Wiresharka.")
    parser.add_argument("file", help="Sciezka do pliku .pcap lub .pcapng")
    parser.add_argument("--json", action="store_true", help="Wypisz wynik jako JSON")
    parser.add_argument("--html", metavar="REPORT.html", help="Zapisz raport HTML do wskazanego pliku")
    parser.add_argument("--csv", metavar="DIR", help="Zapisz tabele CSV do wskazanego katalogu")
    parser.add_argument("--host", help="Analizuj tylko pakiety z podanym hostem jako zrodlem lub celem")
    parser.add_argument("--protocol", help="Analizuj tylko wybrany protokol, np. TCP, UDP, HTTP, HTTPS, DNS")
    parser.add_argument("--port", type=int, help="Analizuj tylko pakiety z podanym portem zrodlowym lub docelowym")
    parser.add_argument("--limit", type=int, default=10, help="Limit pozycji w rankingach")
    args = parser.parse_args(argv)

    path = Path(args.file)
    if not path.exists():
        print(f"Blad: plik nie istnieje: {path}", file=sys.stderr)
        return 2

    try:
        result = analyze_filtered_file(path, limit=args.limit, host=args.host, protocol=args.protocol, port=args.port)
    except ValueError as exc:
        print(f"Blad analizy: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        _print_human(result)
    if args.html:
        report_path = write_html_report(result, args.html)
        print(f"\nRaport HTML zapisany: {report_path}")
    if args.csv:
        csv_path = write_csv_exports(result, args.csv)
        print(f"\nPliki CSV zapisane w: {csv_path}")
    return 0


def _print_human(result) -> None:
    print("PCAP Analyzer")
    print(f"Plik: {result.file}")
    print(f"Pakiety: {result.packet_count}")
    print(f"Bajty: {result.byte_count}")
    print(f"Czas trwania: {result.duration_seconds:.3f} s")
    print(f"Risk score: {result.risk_score}/100 ({result.risk_level})")
    if result.filters:
        filters = ", ".join(f"{name}={value}" for name, value in result.filters.items())
        print(f"Filtry: {filters}")

    print("\nNajczestsze protokoly:")
    for protocol, count in result.protocols:
        print(f"  - {protocol}: {count}")

    print("\nNajaktywniejsze hosty:")
    for host, count in result.top_talkers:
        print(f"  - {host}: {count}")

    print("\nNajczestsze polaczenia:")
    for connection, count in result.top_connections:
        print(f"  - {connection}: {count}")

    print("\nNajwieksze sesje / flow:")
    if not result.top_flows:
        print("  - Brak danych o sesjach.")
    for flow in result.top_flows:
        print(f"  - {flow.flow} {flow.protocol}: {flow.packets} pakietow, {flow.bytes} bajtow, {flow.duration_seconds:.3f} s")

    print("\nPodejrzane polaczenia:")
    if not result.suspicious:
        print("  - Brak wykrytych anomalii wedlug prostych heurystyk.")
    for finding in result.suspicious:
        print(f"  - [{finding.severity}] {finding.title}: {finding.details}")

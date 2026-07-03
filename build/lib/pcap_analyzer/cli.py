from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .analyzer import analyze_filtered_file
from .compare import compare_results
from .csv_export import write_csv_exports
from .gui import run_gui
from .report import write_html_report
from .sample import generate_sample_pcap


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analizator plikow PCAP/PCAPNG z Wiresharka.")
    parser.add_argument("file", nargs="?", help="Sciezka do pliku .pcap lub .pcapng")
    parser.add_argument("--json", action="store_true", help="Wypisz wynik jako JSON")
    parser.add_argument("--html", metavar="REPORT.html", help="Zapisz raport HTML do wskazanego pliku")
    parser.add_argument("--csv", metavar="DIR", help="Zapisz tabele CSV do wskazanego katalogu")
    parser.add_argument("--compare", metavar="OTHER.pcap", help="Porownaj analizowany plik z drugim plikiem PCAP/PCAPNG")
    parser.add_argument("--generate-sample", metavar="sample.pcap", help="Wygeneruj przykladowy plik PCAP do demonstracji")
    parser.add_argument("--gui", action="store_true", help="Uruchom lokalny interfejs webowy")
    parser.add_argument("--gui-host", default="127.0.0.1", help="Host dla GUI")
    parser.add_argument("--gui-port", type=int, default=8080, help="Port dla GUI")
    parser.add_argument("--summary-only", action="store_true", help="Pokaz tylko podstawowe podsumowanie bez rankingow")
    parser.add_argument("--host", help="Analizuj tylko pakiety z podanym hostem jako zrodlem lub celem")
    parser.add_argument("--protocol", help="Analizuj tylko wybrany protokol, np. TCP, UDP, HTTP, HTTPS, DNS")
    parser.add_argument("--port", type=int, help="Analizuj tylko pakiety z podanym portem zrodlowym lub docelowym")
    parser.add_argument("--limit", type=int, default=10, help="Limit pozycji w rankingach")
    args = parser.parse_args(argv)

    if args.gui:
        run_gui(args.gui_host, args.gui_port)
        return 0

    if args.generate_sample:
        sample_path = generate_sample_pcap(args.generate_sample)
        print(f"Przykladowy PCAP zapisany: {sample_path}")
        if not args.file:
            return 0

    if not args.file:
        parser.error("podaj plik PCAP/PCAPNG albo uzyj --generate-sample")

    path = Path(args.file)
    if not path.exists():
        print(f"Blad: plik nie istnieje: {path}", file=sys.stderr)
        return 2
    if args.compare and not Path(args.compare).exists():
        print(f"Blad: plik do porownania nie istnieje: {args.compare}", file=sys.stderr)
        return 2

    try:
        result = analyze_filtered_file(path, limit=args.limit, host=args.host, protocol=args.protocol, port=args.port)
        comparison = None
        if args.compare:
            other = analyze_filtered_file(args.compare, limit=args.limit, host=args.host, protocol=args.protocol, port=args.port)
            comparison = compare_results(result, other, limit=args.limit)
    except ValueError as exc:
        print(f"Blad analizy: {exc}", file=sys.stderr)
        return 1

    if args.json:
        payload = result.to_dict()
        if comparison:
            payload["comparison"] = comparison.to_dict()
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        _print_human(result, summary_only=args.summary_only)
        if comparison:
            _print_comparison(comparison)
    if args.html:
        report_path = write_html_report(result, args.html)
        print(f"\nRaport HTML zapisany: {report_path}")
    if args.csv:
        csv_path = write_csv_exports(result, args.csv)
        print(f"\nPliki CSV zapisane w: {csv_path}")
    return 0


def _print_human(result, summary_only: bool = False) -> None:
    print("PCAP Analyzer")
    print(f"Plik: {result.file}")
    print(f"Pakiety: {result.packet_count}")
    print(f"Bajty: {result.byte_count}")
    print(f"Czas trwania: {result.duration_seconds:.3f} s")
    print(f"Risk score: {result.risk_score}/100 ({result.risk_level})")
    if result.filters:
        filters = ", ".join(f"{name}={value}" for name, value in result.filters.items())
        print(f"Filtry: {filters}")
    if summary_only:
        return

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
        print(f"  - [{finding.severity}] {finding.rule_id} {finding.title}: {finding.details}")


def _print_comparison(comparison) -> None:
    print("\nPorownanie plikow:")
    print(f"  Plik bazowy: {comparison.base_file}")
    print(f"  Drugi plik: {comparison.other_file}")
    print(f"  Zmiana pakietow: {comparison.packet_delta:+d}")
    print(f"  Zmiana bajtow: {comparison.byte_delta:+d}")
    print(f"  Zmiana risk score: {comparison.risk_score_delta:+d}")
    _print_list("Nowe hosty", comparison.new_hosts)
    _print_list("Nowe protokoly", comparison.new_protocols)
    _print_list("Nowe porty", comparison.new_ports)
    _print_list("Nowe flow", comparison.new_flows)


def _print_list(label: str, values: list[object]) -> None:
    if values:
        print(f"  {label}: {', '.join(str(value) for value in values)}")
    else:
        print(f"  {label}: brak")

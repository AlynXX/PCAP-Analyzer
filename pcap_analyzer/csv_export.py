from __future__ import annotations

import csv
import json
from pathlib import Path

from .analyzer import AnalysisResult


def write_csv_exports(result: AnalysisResult, output_dir: str | Path) -> Path:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    _write_pairs(path / "protocols.csv", ("protocol", "packets"), result.protocols)
    _write_pairs(path / "talkers.csv", ("host", "packets"), result.top_talkers)
    _write_pairs(path / "connections.csv", ("connection", "packets"), result.top_connections)
    _write_flows(path / "flows.csv", result)
    _write_suspicious(path / "suspicious.csv", result)
    _write_summary(path / "summary.csv", result)
    return path


def _write_pairs(path: Path, header: tuple[str, str], rows: list[tuple[str, int]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(header)
        writer.writerows(rows)


def _write_suspicious(path: Path, result: AnalysisResult) -> None:
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["severity", "title", "details", "evidence"])
        writer.writeheader()
        for finding in result.suspicious:
            writer.writerow(
                {
                    "severity": finding.severity,
                    "title": finding.title,
                    "details": finding.details,
                    "evidence": json.dumps(finding.evidence, ensure_ascii=False),
                }
            )


def _write_flows(path: Path, result: AnalysisResult) -> None:
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["flow", "protocol", "packets", "bytes", "first_timestamp", "last_timestamp", "duration_seconds"],
        )
        writer.writeheader()
        for flow in result.top_flows:
            writer.writerow(
                {
                    "flow": flow.flow,
                    "protocol": flow.protocol,
                    "packets": flow.packets,
                    "bytes": flow.bytes,
                    "first_timestamp": flow.first_timestamp,
                    "last_timestamp": flow.last_timestamp,
                    "duration_seconds": f"{flow.duration_seconds:.3f}",
                }
            )


def _write_summary(path: Path, result: AnalysisResult) -> None:
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["metric", "value"])
        writer.writerow(["file", result.file])
        writer.writerow(["packet_count", result.packet_count])
        writer.writerow(["byte_count", result.byte_count])
        writer.writerow(["duration_seconds", f"{result.duration_seconds:.3f}"])
        writer.writerow(["risk_score", result.risk_score])
        writer.writerow(["risk_level", result.risk_level])
        for name, value in result.filters.items():
            writer.writerow([f"filter_{name}", value])

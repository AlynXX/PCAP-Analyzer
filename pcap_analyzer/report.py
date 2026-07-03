from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path

from .analyzer import AnalysisResult


def write_html_report(result: AnalysisResult, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.write_text(render_html_report(result), encoding="utf-8")
    return path


def render_html_report(result: AnalysisResult) -> str:
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!doctype html>
<html lang="pl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PCAP Analyzer Report</title>
  <style>
    :root {{
      --bg: #f6f8fb;
      --panel: #ffffff;
      --text: #18212f;
      --muted: #647084;
      --line: #dde4ee;
      --accent: #2563eb;
      --low: #16a34a;
      --medium: #d97706;
      --high: #dc2626;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.45;
    }}
    main {{
      width: min(1120px, calc(100% - 32px));
      margin: 32px auto;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      gap: 24px;
      align-items: flex-start;
      margin-bottom: 24px;
    }}
    h1, h2 {{ margin: 0; }}
    h1 {{ font-size: 32px; }}
    h2 {{ font-size: 20px; margin-bottom: 14px; }}
    .muted {{ color: var(--muted); }}
    .risk {{
      min-width: 220px;
      padding: 18px;
      border-radius: 8px;
      background: var(--panel);
      border: 1px solid var(--line);
      text-align: center;
    }}
    .risk-score {{
      font-size: 44px;
      font-weight: 700;
      color: {escape(_risk_color(result.risk_level))};
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 18px;
    }}
    .metric, section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
    }}
    .metric strong {{
      display: block;
      font-size: 24px;
      margin-top: 6px;
    }}
    section {{ margin-top: 18px; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    th, td {{
      padding: 10px 8px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }}
    th {{ color: var(--muted); font-weight: 700; }}
    tr:last-child td {{ border-bottom: 0; }}
    .badge {{
      display: inline-block;
      padding: 3px 8px;
      border-radius: 999px;
      color: #fff;
      font-size: 12px;
      font-weight: 700;
    }}
    .badge.niskie {{ background: var(--low); }}
    .badge.srednie {{ background: var(--medium); }}
    .badge.wysokie {{ background: var(--high); }}
    .badge.brak {{ background: var(--muted); }}
    .two-col {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
    }}
    @media (max-width: 820px) {{
      header, .two-col {{ grid-template-columns: 1fr; display: grid; }}
      .grid {{ grid-template-columns: repeat(2, 1fr); }}
      .risk {{ text-align: left; }}
    }}
    @media (max-width: 520px) {{
      .grid {{ grid-template-columns: 1fr; }}
      main {{ width: min(100% - 20px, 1120px); margin: 16px auto; }}
      table {{ font-size: 13px; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>PCAP Analyzer Report</h1>
        <p class="muted">Plik: {escape(result.file)}<br>Wygenerowano: {escape(generated_at)}</p>
        {_filters_summary(result)}
      </div>
      <div class="risk">
        <div class="muted">Risk score</div>
        <div class="risk-score">{result.risk_score}/100</div>
        <span class="badge {escape(result.risk_level)}">{escape(result.risk_level)}</span>
      </div>
    </header>

    <div class="grid">
      {_metric("Pakiety", str(result.packet_count))}
      {_metric("Bajty", str(result.byte_count))}
      {_metric("Czas trwania", f"{result.duration_seconds:.3f} s")}
      {_metric("Alerty", str(len(result.suspicious)))}
    </div>

    <section>
      <h2>Podejrzane polaczenia</h2>
      {_findings_table(result)}
    </section>

    <div class="two-col">
      <section>
        <h2>Najczestsze protokoly</h2>
        {_pairs_table("Protokol", "Pakiety", result.protocols)}
      </section>
      <section>
        <h2>Najaktywniejsze hosty</h2>
        {_pairs_table("Host", "Pakiety", result.top_talkers)}
      </section>
    </div>

    <section>
      <h2>Najczestsze polaczenia</h2>
      {_pairs_table("Polaczenie", "Pakiety", result.top_connections)}
    </section>

    <section>
      <h2>Najwieksze sesje / flow</h2>
      {_flows_table(result)}
    </section>
  </main>
</body>
</html>
"""


def _metric(label: str, value: str) -> str:
    return f'<div class="metric"><span class="muted">{escape(label)}</span><strong>{escape(value)}</strong></div>'


def _filters_summary(result: AnalysisResult) -> str:
    if not result.filters:
        return ""
    filters = ", ".join(f"{name}={value}" for name, value in result.filters.items())
    return f'<p class="muted">Filtry: {escape(filters)}</p>'


def _pairs_table(left_label: str, right_label: str, rows: list[tuple[str, int]]) -> str:
    if not rows:
        return '<p class="muted">Brak danych.</p>'
    body = "\n".join(f"<tr><td>{escape(str(left))}</td><td>{count}</td></tr>" for left, count in rows)
    return f"<table><thead><tr><th>{escape(left_label)}</th><th>{escape(right_label)}</th></tr></thead><tbody>{body}</tbody></table>"


def _findings_table(result: AnalysisResult) -> str:
    if not result.suspicious:
        return '<p class="muted">Brak wykrytych anomalii wedlug prostych heurystyk.</p>'
    rows = []
    for finding in result.suspicious:
        rows.append(
            "<tr>"
            f'<td><span class="badge {escape(finding.severity)}">{escape(finding.severity)}</span></td>'
            f"<td>{escape(finding.title)}</td>"
            f"<td>{escape(finding.details)}</td>"
            "</tr>"
        )
    return "<table><thead><tr><th>Poziom</th><th>Alert</th><th>Szczegoly</th></tr></thead><tbody>" + "\n".join(rows) + "</tbody></table>"


def _flows_table(result: AnalysisResult) -> str:
    if not result.top_flows:
        return '<p class="muted">Brak danych o sesjach.</p>'
    rows = []
    for flow in result.top_flows:
        rows.append(
            "<tr>"
            f"<td>{escape(flow.flow)}</td>"
            f"<td>{escape(flow.protocol)}</td>"
            f"<td>{flow.packets}</td>"
            f"<td>{flow.bytes}</td>"
            f"<td>{flow.duration_seconds:.3f} s</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Flow</th><th>Protokol</th><th>Pakiety</th><th>Bajty</th><th>Czas</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def _risk_color(level: str) -> str:
    if level == "wysokie":
        return "#dc2626"
    if level == "srednie":
        return "#d97706"
    if level == "niskie":
        return "#16a34a"
    return "#647084"

from __future__ import annotations

from dataclasses import dataclass
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
from typing import Any
from urllib.parse import parse_qs, urlparse
import uuid
import zipfile

from .analyzer import analyze_filtered_file
from .csv_export import write_csv_exports
from .report import render_html_report


@dataclass
class GuiArtifact:
    result_json: str
    csv_zip: bytes


ARTIFACTS: dict[str, GuiArtifact] = {}


def run_gui(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = ThreadingHTTPServer((host, port), GuiRequestHandler)
    print(f"PCAP Analyzer GUI: http://{host}:{port}")
    print("Nacisnij Ctrl+C, aby zatrzymac serwer.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nZatrzymano GUI.")
    finally:
        server.server_close()


class GuiRequestHandler(BaseHTTPRequestHandler):
    server_version = "PCAPAnalyzerGUI/0.1"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(render_upload_page())
            return
        if parsed.path == "/download/json":
            artifact = _artifact_from_query(parsed.query)
            if artifact is None:
                self.send_error(404, "Nie znaleziono wyniku analizy.")
                return
            self._send_bytes(artifact.result_json.encode("utf-8"), "application/json", "analysis.json")
            return
        if parsed.path == "/download/csv":
            artifact = _artifact_from_query(parsed.query)
            if artifact is None:
                self.send_error(404, "Nie znaleziono wyniku analizy.")
                return
            self._send_bytes(artifact.csv_zip, "application/zip", "pcap_analyzer_csv.zip")
            return
        self.send_error(404, "Nie znaleziono strony.")

    def do_POST(self) -> None:
        if self.path != "/analyze":
            self.send_error(404, "Nie znaleziono strony.")
            return
        try:
            form = parse_multipart(self.headers.get("Content-Type", ""), self.rfile.read(_content_length(self.headers)))
            upload = form.get("pcap")
            if not isinstance(upload, tuple) or not upload[1]:
                self._send_html(render_upload_page("Wybierz plik PCAP/PCAPNG do analizy."), status=400)
                return

            filename, content = upload
            host = _text_value(form.get("host")) or None
            protocol = _text_value(form.get("protocol")) or None
            port = _int_value(form.get("port"))
            limit = _int_value(form.get("limit")) or 10

            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                pcap_path = tmp_path / _safe_filename(filename)
                pcap_path.write_bytes(content)
                result = analyze_filtered_file(pcap_path, limit=limit, host=host, protocol=protocol, port=port)
                artifact_id = uuid.uuid4().hex
                ARTIFACTS[artifact_id] = GuiArtifact(
                    result_json=json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
                    csv_zip=_csv_zip(result, tmp_path),
                )
                self._send_html(render_result_page(render_html_report(result), artifact_id))
        except ValueError as exc:
            self._send_html(render_upload_page(f"Blad analizy: {escape(str(exc))}"), status=400)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_html(self, html: str, status: int = 200) -> None:
        data = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_bytes(self, data: bytes, content_type: str, filename: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def render_upload_page(error: str | None = None) -> str:
    error_html = f'<div class="error">{error}</div>' if error else ""
    return f"""<!doctype html>
<html lang="pl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PCAP Analyzer GUI</title>
  <style>
    body {{ margin: 0; font-family: Arial, Helvetica, sans-serif; background: #f6f8fb; color: #18212f; }}
    main {{ width: min(760px, calc(100% - 32px)); margin: 40px auto; }}
    form {{ background: #fff; border: 1px solid #dde4ee; border-radius: 8px; padding: 20px; }}
    h1 {{ margin: 0 0 10px; }}
    label {{ display: block; margin-top: 14px; font-weight: 700; }}
    input {{ width: 100%; margin-top: 6px; padding: 10px; border: 1px solid #cdd6e3; border-radius: 6px; }}
    button {{ margin-top: 18px; padding: 10px 16px; border: 0; border-radius: 6px; background: #2563eb; color: white; font-weight: 700; cursor: pointer; }}
    .row {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; }}
    .muted {{ color: #647084; }}
    .error {{ background: #fee2e2; border: 1px solid #fecaca; color: #991b1b; border-radius: 6px; padding: 10px; margin: 16px 0; }}
    @media (max-width: 640px) {{ .row {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <main>
    <h1>PCAP Analyzer</h1>
    <p class="muted">Wgraj plik z Wiresharka, ustaw opcjonalne filtry i wygeneruj raport.</p>
    {error_html}
    <form action="/analyze" method="post" enctype="multipart/form-data">
      <label>Plik PCAP/PCAPNG
        <input type="file" name="pcap" accept=".pcap,.pcapng" required>
      </label>
      <div class="row">
        <label>Host
          <input type="text" name="host" placeholder="192.168.1.10">
        </label>
        <label>Protokol
          <input type="text" name="protocol" placeholder="HTTPS">
        </label>
        <label>Port
          <input type="number" name="port" min="1" max="65535" placeholder="443">
        </label>
      </div>
      <label>Limit rankingow
        <input type="number" name="limit" min="1" max="100" value="10">
      </label>
      <button type="submit">Analizuj</button>
    </form>
  </main>
</body>
</html>"""


def render_result_page(report_html: str, artifact_id: str) -> str:
    return report_html.replace(
        "<main>",
        (
            "<main>"
            '<section style="margin-bottom:18px">'
            '<h2>Eksport</h2>'
            f'<p><a href="/download/json?id={artifact_id}">Pobierz JSON</a> | '
            f'<a href="/download/csv?id={artifact_id}">Pobierz CSV ZIP</a> | '
            '<a href="/">Nowa analiza</a></p>'
            "</section>"
        ),
        1,
    )


def parse_multipart(content_type: str, body: bytes) -> dict[str, str | tuple[str, bytes]]:
    marker = "boundary="
    if marker not in content_type:
        raise ValueError("Niepoprawny formularz uploadu.")
    boundary = content_type.split(marker, 1)[1].strip().strip('"').encode("utf-8")
    result: dict[str, str | tuple[str, bytes]] = {}
    for part in body.split(b"--" + boundary):
        part = part.strip(b"\r\n")
        if not part or part == b"--":
            continue
        headers, _, payload = part.partition(b"\r\n\r\n")
        disposition = _content_disposition(headers)
        name = disposition.get("name")
        if not name:
            continue
        payload = payload.removesuffix(b"\r\n")
        if "filename" in disposition:
            result[name] = (disposition["filename"], payload)
        else:
            result[name] = payload.decode("utf-8", errors="replace")
    return result


def _content_disposition(headers: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in headers.decode("utf-8", errors="replace").splitlines():
        if line.lower().startswith("content-disposition:"):
            parts = line.split(";", 1)[1].split(";")
            for part in parts:
                if "=" in part:
                    key, value = part.strip().split("=", 1)
                    values[key.lower()] = value.strip().strip('"')
    return values


def _content_length(headers: Any) -> int:
    try:
        return int(headers.get("Content-Length", "0"))
    except ValueError:
        return 0


def _text_value(value: str | tuple[str, bytes] | None) -> str:
    return value.strip() if isinstance(value, str) else ""


def _int_value(value: str | tuple[str, bytes] | None) -> int | None:
    text = _text_value(value)
    return int(text) if text.isdigit() else None


def _safe_filename(filename: str) -> str:
    name = Path(filename).name
    return name or "upload.pcap"


def _artifact_from_query(query: str) -> GuiArtifact | None:
    artifact_id = parse_qs(query).get("id", [""])[0]
    return ARTIFACTS.get(artifact_id)


def _csv_zip(result: Any, tmp_path: Path) -> bytes:
    csv_dir = tmp_path / "csv"
    write_csv_exports(result, csv_dir)
    zip_path = tmp_path / "csv.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(csv_dir.iterdir()):
            archive.write(file, file.name)
    return zip_path.read_bytes()

"""Opening scripts must wait on cheap /api/alive and open the UI."""

from __future__ import annotations

from pathlib import Path
from wsgiref.simple_server import make_server

import threading

REPO = Path(__file__).resolve().parents[1]


def test_start_scripts_probe_alive_not_health():
    ps1 = (REPO / "scripts" / "start.ps1").read_text(encoding="utf-8")
    sh = (REPO / "scripts" / "start.sh").read_text(encoding="utf-8")
    wait = (REPO / "scripts" / "wait_open.py").read_text(encoding="utf-8")
    assert "wait_open.py" in ps1
    assert "wait_open.py" in sh
    assert "/api/alive" in wait
    assert "--open-after" in wait
    assert '"--timeout", "12"' in ps1
    assert "--timeout 12" in sh
    assert 'Invoke-WebRequest -Uri "$appUrl/api/health"' not in ps1


def test_wait_open_ready_on_alive(monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location("wait_open", REPO / "scripts" / "wait_open.py")
    wait_open = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(wait_open)

    opened: list[str] = []
    monkeypatch.setattr(wait_open.webbrowser, "open", lambda url: opened.append(url))

    def app(environ, start_response):
        path = environ.get("PATH_INFO") or "/"
        body = b'{"ok":true}' if path == "/api/alive" else b"<html></html>"
        start_response("200 OK", [("Content-Type", "text/plain"), ("Content-Length", str(len(body)))])
        return [body]

    httpd = make_server("127.0.0.1", 0, app)
    port = httpd.server_port
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        code = wait_open.main(["--url", f"http://127.0.0.1:{port}", "--timeout", "5"])
        assert code == 0
        assert opened and opened[0].endswith("/")
    finally:
        httpd.shutdown()


def test_wait_open_opens_quickly_even_if_alive_slow(monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location("wait_open_slow", REPO / "scripts" / "wait_open.py")
    wait_open = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(wait_open)

    opened: list[str] = []
    monkeypatch.setattr(wait_open.webbrowser, "open", lambda url: opened.append(url))
    monkeypatch.setattr(wait_open, "_ok", lambda url, timeout=1.5: False)
    code = wait_open.main(["--url", "http://127.0.0.1:9", "--timeout", "2.2", "--open-after", "0.2"])
    assert code == 2
    assert opened

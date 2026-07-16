"""Local web viewer: stdlib HTTP server exposing a JSON API + static UI."""

from __future__ import annotations

import json
import os
import re
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import export, types
from .db import Case, CaseError

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}


def _types_payload() -> list[dict]:
    return [{
        "key": ft.key,
        "label": ft.label,
        "view": ft.view,
        "fields": [{"key": f.key, "label": f.label, "hint": f.hint}
                   for f in ft.fields],
    } for ft in types.FINDING_TYPES.values()]


class Handler(BaseHTTPRequestHandler):
    case_path: str = ""  # set by serve()

    # -- plumbing -------------------------------------------------------------

    def log_message(self, fmt, *args):  # quiet default access log
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, code: int = 200) -> None:
        self._send(code, json.dumps(data).encode(), "application/json")

    def _error(self, msg: str, code: int = 400) -> None:
        self._json({"error": msg}, code)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        data = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(data, dict):
            raise CaseError("expected a JSON object")
        return data

    def _case(self) -> Case:
        return Case(self.case_path)

    # -- routing --------------------------------------------------------------

    def do_GET(self):
        url = urlparse(self.path)
        if url.path in STATIC:
            name, ctype = STATIC[url.path]
            with open(os.path.join(WEB_DIR, name), "rb") as fh:
                self._send(200, fh.read(), ctype)
            return
        try:
            self._api_get(url)
        except CaseError as exc:
            self._error(str(exc))
        except Exception as exc:  # keep the viewer alive on bugs
            self._error(f"internal error: {exc}", 500)

    def do_POST(self):
        self._mutate("POST")

    def do_PATCH(self):
        self._mutate("PATCH")

    def _mutate(self, method: str):
        try:
            self._api_mutate(method, urlparse(self.path))
        except CaseError as exc:
            self._error(str(exc))
        except json.JSONDecodeError:
            self._error("invalid JSON body")
        except Exception as exc:
            self._error(f"internal error: {exc}", 500)

    # -- GET endpoints ----------------------------------------------------------

    def _api_get(self, url):
        q = parse_qs(url.query)
        with self._case() as case:
            if url.path == "/api/case":
                self._json({"meta": case.meta(), "evidence": case.evidence(),
                            "counts": case.counts(),
                            "file": os.path.basename(case.path),
                            "types": _types_payload()})
            elif url.path == "/api/tree":
                self._json({"roots": case.tree(),
                            "unattached": case.unattached_findings()})
            elif url.path == "/api/findings":
                ftype = (q.get("type") or [None])[0]
                self._json(case.findings(ftype))
            elif url.path == "/api/timeline":
                self._json(case.timeline())
            elif url.path == "/api/export/md":
                self._send(200, export.render_md(case).encode(),
                           "text/markdown; charset=utf-8")
            else:
                self._error("not found", 404)

    # -- POST / PATCH endpoints ---------------------------------------------------

    def _api_mutate(self, method: str, url):
        body = self._body()
        with self._case() as case:
            if method == "POST" and url.path == "/api/actions":
                aid = case.add_action(
                    body.get("command", ""),
                    host=body.get("host", ""),
                    tool=body.get("tool", ""),
                    evidence_id=body.get("evidence_id"),
                    output=body.get("output", ""),
                    notes=body.get("notes", ""),
                    parent_finding_id=body.get("parent_finding_id"))
                self._json({"id": aid}, 201)
            elif method == "POST" and url.path == "/api/findings":
                fid = case.add_finding(
                    body.get("title", ""),
                    ftype=body.get("ftype", "note"),
                    action_id=body.get("action_id"),
                    host=body.get("host", ""),
                    detail=body.get("detail", ""),
                    event_time=body.get("event_time", ""),
                    attrs=body.get("attrs") or {},
                    starred=bool(body.get("starred")))
                self._json({"id": fid}, 201)
            elif method == "POST" and url.path == "/api/evidence":
                eid = case.add_evidence(
                    body.get("label", ""), kind=body.get("kind", ""),
                    source=body.get("source", ""), sha256=body.get("sha256", ""),
                    notes=body.get("notes", ""))
                self._json({"id": eid}, 201)
            elif method == "PATCH":
                m = re.fullmatch(r"/api/(actions|findings)/(\d+)", url.path)
                if not m:
                    self._error("not found", 404)
                    return
                table, row_id = m.group(1), int(m.group(2))
                if table == "actions":
                    case.update_action(row_id, **body)
                else:
                    case.update_finding(row_id, **body)
                self._json({"ok": True})
            else:
                self._error("not found", 404)


def serve(case_path: str, port: int = 8845, open_browser: bool = True) -> int:
    Handler.case_path = os.path.abspath(case_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
    print(f"vera viewer: {url}  (case: {case_path})  Ctrl-C to stop")
    if open_browser:
        threading.Timer(0.3, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
    return 0

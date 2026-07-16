"""Local web viewer: stdlib HTTP server exposing a JSON API + static UI."""

from __future__ import annotations

import base64
import binascii
import glob
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


def _slug(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.").lower()
    return s or "case"


def _set_active_case(path: str) -> None:
    """Keep the CLI's active-case selection in sync with UI actions."""
    try:
        from .cli import _set_active
        _set_active(path)
    except Exception:
        pass


class Handler(BaseHTTPRequestHandler):
    case_path: str | None = None  # active case; None = show New Investigation screen
    case_dir: str = "."           # where .vera files live and get created

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
        if not self.case_path:
            raise CaseError("no active investigation — create or open one first")
        return Case(self.case_path)

    @classmethod
    def _list_cases(cls) -> list[dict]:
        out = []
        for p in sorted(glob.glob(os.path.join(cls.case_dir, "*.vera"))):
            try:
                with Case(p) as c:
                    out.append({"file": os.path.basename(p),
                                "name": c.meta().get("name", ""),
                                "counts": c.counts()})
            except CaseError:
                continue
        return out

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

    def do_DELETE(self):
        self._mutate("DELETE")

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
        if url.path == "/api/cases":
            self._json({"case_dir": Handler.case_dir,
                        "cases": self._list_cases()})
            return
        if url.path == "/api/case" and not self.case_path:
            self._json({"active": False})
            return
        m = re.fullmatch(r"/api/attachments/(\d+)", url.path)
        if m:
            with self._case() as case:
                data, mime, filename = case.attachment_blob(int(m.group(1)))
            self.send_response(200)
            self.send_header("Content-Type", mime or "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition",
                             f'inline; filename="{filename or "attachment"}"')
            self.send_header("Cache-Control", "private, max-age=86400")
            self.end_headers()
            self.wfile.write(data)
            return
        with self._case() as case:
            if url.path == "/api/case":
                self._json({"active": True, "meta": case.meta(),
                            "evidence": case.evidence(), "counts": case.counts(),
                            "hosts": case.hosts(), "collections": case.collections(),
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
            elif url.path == "/api/hosts":
                self._json(case.hosts())
            elif url.path == "/api/collections":
                self._json(case.collections())
            elif url.path == "/api/stack":
                self._json(case.stack_findings())
            elif url.path == "/api/host_findings":
                hid = int((q.get("id") or [0])[0])
                self._json(case.findings_for_host(hid))
            elif url.path == "/api/host_detail":
                hid = int((q.get("id") or [0])[0])
                self._json({"findings": case.findings_for_host(hid),
                            "evidence": case.evidence_for_host(hid),
                            "actions": case.actions_for_host(hid)})
            elif url.path == "/api/export/md":
                self._send(200, export.render_md(case).encode(),
                           "text/markdown; charset=utf-8")
            else:
                self._error("not found", 404)

    # -- POST / PATCH endpoints ---------------------------------------------------

    def _api_mutate(self, method: str, url):
        body = self._body()
        if method == "POST" and url.path == "/api/cases":
            self._create_case(body)
            return
        if method == "POST" and url.path == "/api/open":
            self._open_case(body)
            return
        with self._case() as case:
            if method == "POST" and url.path == "/api/actions":
                aid = case.add_action(
                    body.get("command", ""),
                    host=body.get("host", ""),
                    tool=body.get("tool", ""),
                    method=body.get("method", "command"),
                    procedure=body.get("procedure", ""),
                    evidence_id=body.get("evidence_id"),
                    collection_id=body.get("collection_id"),
                    output=body.get("output", ""),
                    notes=body.get("notes", ""),
                    parent_finding_id=body.get("parent_finding_id"),
                    host_ids=self._host_ids(case, body))
                self._json({"id": aid}, 201)
            elif method == "POST" and url.path == "/api/attachments":
                self._add_attachment(case, body)
            elif method == "DELETE":
                m = re.fullmatch(r"/api/attachments/(\d+)", url.path)
                if m:
                    case.delete_attachment(int(m.group(1)))
                    self._json({"ok": True})
                    return
                m = re.fullmatch(r"/api/hosts/(\d+)", url.path)
                if m:
                    case.soft_delete_host(int(m.group(1)))
                    self._json({"ok": True})
                    return
                self._error("not found", 404)
            elif method == "POST" and url.path == "/api/findings":
                fid = case.add_finding(
                    body.get("title", ""),
                    ftype=body.get("ftype", "note"),
                    action_id=body.get("action_id"),
                    host=body.get("host", ""),
                    detail=body.get("detail", ""),
                    event_time=body.get("event_time", ""),
                    attrs=body.get("attrs") or {},
                    hashes=body.get("hashes") or {},
                    starred=bool(body.get("starred")),
                    host_ids=self._host_ids(case, body))
                self._json({"id": fid}, 201)
            elif method == "POST" and url.path == "/api/evidence":
                eid = case.add_evidence(
                    body.get("label", ""), kind=body.get("kind", ""),
                    source=body.get("source", ""), sha256=body.get("sha256", ""),
                    notes=body.get("notes", ""),
                    collection_id=body.get("collection_id"),
                    host_ids=self._host_ids(case, body))
                self._json({"id": eid}, 201)
            elif method == "POST" and url.path == "/api/hosts":
                self._add_hosts(case, body)
            elif method == "POST" and url.path == "/api/collections":
                cid = case.add_collection(
                    body.get("name", ""), tool=body.get("tool", ""),
                    operator=body.get("operator", ""),
                    collected_at=body.get("collected_at", ""),
                    scope=body.get("scope", ""), notes=body.get("notes", ""),
                    host_ids=self._host_ids(case, body))
                self._json({"id": cid}, 201)
            elif method == "PATCH":
                m = re.fullmatch(
                    r"/api/(actions|findings|hosts|evidence|collections)/(\d+)",
                    url.path)
                if not m:
                    self._error("not found", 404)
                    return
                table, row_id = m.group(1), int(m.group(2))
                if table == "actions":
                    self._patch_with_hosts(case, "action", row_id, body)
                elif table == "evidence":
                    self._patch_with_hosts(case, "evidence", row_id, body)
                elif table == "collections":
                    self._patch_collection(case, row_id, body)
                elif table == "hosts":
                    case.update_host(row_id, **body)
                else:
                    self._patch_finding(case, row_id, body)
                self._json({"ok": True})
            else:
                self._error("not found", 404)

    @staticmethod
    def _host_ids(case: Case, body: dict) -> list[int]:
        """Merge explicit host_ids with resolved/auto-created host_names."""
        ids = list(body.get("host_ids") or [])
        names = body.get("host_names") or []
        if names:
            ids += case.resolve_hosts(names, create=True)
        seen, out = set(), []
        for i in ids:
            if i not in seen:
                seen.add(i)
                out.append(i)
        return out

    def _patch_finding(self, case: Case, fid: int, body: dict) -> None:
        body = dict(body)
        has_hosts = "host_ids" in body or "host_names" in body
        host_ids = self._host_ids(case, body) if has_hosts else None
        body.pop("host_ids", None)
        body.pop("host_names", None)
        if body:
            case.update_finding(fid, **body)
        if has_hosts:
            case.set_finding_hosts(fid, host_ids)

    def _patch_with_hosts(self, case: Case, kind: str, row_id: int,
                          body: dict) -> None:
        """PATCH an action/evidence row's host links (and, for actions, fields)."""
        body = dict(body)
        has_hosts = "host_ids" in body or "host_names" in body
        host_ids = self._host_ids(case, body) if has_hosts else None
        body.pop("host_ids", None)
        body.pop("host_names", None)
        if kind == "action":
            if body:
                case.update_action(row_id, **body)
            if has_hosts:
                case.set_action_hosts(row_id, host_ids)
        else:  # evidence: fields and/or host links
            if body:
                case.update_evidence(row_id, **body)
            if has_hosts:
                case.set_evidence_hosts(row_id, host_ids)

    def _patch_collection(self, case: Case, cid: int, body: dict) -> None:
        body = dict(body)
        has_hosts = "host_ids" in body or "host_names" in body
        host_ids = self._host_ids(case, body) if has_hosts else None
        body.pop("host_ids", None)
        body.pop("host_names", None)
        if body:
            case.update_collection(cid, **body)
        if has_hosts:
            case.set_collection_hosts(cid, host_ids)

    def _add_hosts(self, case: Case, body: dict):
        names = body.get("names")
        if names is None and body.get("name"):
            names = [body["name"]]
        if not names:
            raise CaseError("provide a host name or a 'names' list")
        ids = [case.add_host(
            n, aliases=body.get("aliases") or [], ip=body.get("ip", ""),
            os=body.get("os", ""), system_type=body.get("system_type", ""),
            criticality=body.get("criticality", ""), notes=body.get("notes", ""))
            for n in names if n and n.strip()]
        self._json({"ids": ids, "count": len(ids)}, 201)

    def _add_attachment(self, case: Case, body: dict):
        owner_type = body.get("owner_type", "")
        owner_id = body.get("owner_id")
        b64 = body.get("data_base64", "")
        if not isinstance(owner_id, int):
            raise CaseError("owner_id must be an integer")
        try:
            data = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError):
            raise CaseError("data_base64 is not valid base64") from None
        att = case.add_attachment(
            owner_type, owner_id, data,
            filename=body.get("filename", ""),
            mime=body.get("mime", "application/octet-stream"),
            role=body.get("role", "exhibit"),
            caption=body.get("caption", ""))
        self._json({"id": att}, 201)

    # -- case lifecycle -----------------------------------------------------------

    def _create_case(self, body: dict):
        name = (body.get("name") or "").strip()
        if not name:
            raise CaseError("an investigation name is required")
        os.makedirs(Handler.case_dir, exist_ok=True)
        base = _slug(name)
        path = os.path.join(Handler.case_dir, base + ".vera")
        n = 2
        while os.path.exists(path):
            path = os.path.join(Handler.case_dir, f"{base}-{n}.vera")
            n += 1
        with Case(path, create=True) as c:
            c.set_meta(name=name, investigator=body.get("investigator", ""))
        Handler.case_path = path
        _set_active_case(path)
        self._json({"file": os.path.basename(path), "name": name}, 201)

    def _open_case(self, body: dict):
        fname = os.path.basename(body.get("file", ""))
        if not fname:
            raise CaseError("which investigation?")
        path = os.path.join(Handler.case_dir, fname)
        Case(path).close()  # validate before switching
        Handler.case_path = path
        _set_active_case(path)
        self._json({"ok": True})


def serve(case_path: str | None, port: int = 8845, open_browser: bool = True,
          case_dir: str | None = None) -> int:
    Handler.case_path = os.path.abspath(case_path) if case_path else None
    Handler.case_dir = os.path.abspath(
        case_dir or (os.path.dirname(case_path) if case_path else os.getcwd()))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
    where = case_path or f"New Investigation screen — cases in {Handler.case_dir}"
    print(f"vera viewer: {url}  ({where})  Ctrl-C to stop")
    if open_browser:
        threading.Timer(0.3, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
    return 0

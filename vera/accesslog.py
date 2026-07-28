"""Global access / security log — the server-wide event trail.

This is DISTINCT from the per-case `audit_log` (which records data edits inside
one .vera and travels with it). The access log lives beside the users DB, spans
all cases, and records what happens on the SERVER: who logged in, who
administered users, and who exported which case. It is server-private and is
never included in a case export. Stdlib-only, append-only.
"""

from __future__ import annotations

import datetime as _dt
import json
import sqlite3

# canonical event names (free-form is allowed, these are the ones we emit)
LOGIN = "login"
LOGIN_FAILED = "login_failed"
LOGOUT = "logout"
BOOTSTRAP = "bootstrap"
USER_CREATE = "user_create"
USER_UPDATE = "user_update"          # role change / enable / disable
RESET_ISSUED = "reset_issued"
PASSWORD_CHANGE = "password_change"
EXPORT = "export"

SCHEMA = """
CREATE TABLE IF NOT EXISTS access_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    at       TEXT NOT NULL,
    who      TEXT NOT NULL DEFAULT '',   -- acting username (or the attempted one)
    who_role TEXT NOT NULL DEFAULT '',
    event    TEXT NOT NULL,
    case_ref TEXT NOT NULL DEFAULT '',    -- case file/name, for export events
    ip       TEXT NOT NULL DEFAULT '',
    detail   TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_access_event ON access_log(event);
"""


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class AccessLog:
    """Open per use, like Case/UsersDB — connections aren't thread-shared."""

    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout = 5000")
        self.conn.execute("PRAGMA journal_mode = WAL")
        with self.conn:
            self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "AccessLog":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def log(self, event: str, who: str = "", who_role: str = "",
            case_ref: str = "", ip: str = "", detail: dict | None = None) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO access_log(at, who, who_role, event, case_ref, ip,"
                " detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (_now(), who, who_role, event, case_ref, ip,
                 json.dumps(detail or {})))

    def recent(self, limit: int = 200, event: str = "") -> list[dict]:
        q = "SELECT * FROM access_log"
        params: tuple = ()
        if event:
            q += " WHERE event = ?"
            params = (event,)
        q += " ORDER BY id DESC LIMIT ?"
        out = []
        for r in self.conn.execute(q, (*params, limit)):
            d = dict(r)
            try:
                d["detail"] = json.loads(d.get("detail") or "{}")
            except json.JSONDecodeError:
                d["detail"] = {}
            out.append(d)
        return out

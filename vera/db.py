"""Case storage: one SQLite file per investigation, all queries live here."""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import sqlite3

SCHEMA_VERSION = 1
OUTPUT_CAP = 256 * 1024  # chars of captured command output stored per action

SCHEMA = """
CREATE TABLE case_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE evidence (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    label      TEXT NOT NULL,
    kind       TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL DEFAULT '',
    sha256     TEXT NOT NULL DEFAULT '',
    notes      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE actions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    performed_at      TEXT NOT NULL,
    host              TEXT NOT NULL DEFAULT '',
    evidence_id       INTEGER REFERENCES evidence(id),
    tool              TEXT NOT NULL DEFAULT '',
    command           TEXT NOT NULL,
    output            TEXT NOT NULL DEFAULT '',
    output_sha256     TEXT NOT NULL DEFAULT '',
    output_truncated  INTEGER NOT NULL DEFAULT 0,
    exit_code         INTEGER,
    notes             TEXT NOT NULL DEFAULT '',
    parent_finding_id INTEGER REFERENCES findings(id)
);
CREATE TABLE findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id  INTEGER REFERENCES actions(id),
    created_at TEXT NOT NULL,
    event_time TEXT NOT NULL DEFAULT '',
    title      TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    ftype      TEXT NOT NULL DEFAULT 'note',
    host       TEXT NOT NULL DEFAULT '',
    attrs      TEXT NOT NULL DEFAULT '{}',
    starred    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_findings_action ON findings(action_id);
CREATE INDEX idx_findings_ftype  ON findings(ftype);
CREATE INDEX idx_actions_parent  ON actions(parent_finding_id);
"""


class CaseError(Exception):
    """User-facing case/database error."""


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


class Case:
    """A single investigation file. Thin wrapper over sqlite3."""

    def __init__(self, path: str, create: bool = False):
        self.path = os.path.abspath(path)
        exists = os.path.exists(self.path)
        if not exists and not create:
            raise CaseError(f"case file not found: {path}")
        if exists and create:
            raise CaseError(f"refusing to overwrite existing case: {path}")
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        if create:
            with self.conn:
                self.conn.executescript(SCHEMA)
                self.conn.execute(
                    "INSERT INTO case_meta(key, value) VALUES ('schema_version', ?)",
                    (str(SCHEMA_VERSION),))
                self.conn.execute(
                    "INSERT INTO case_meta(key, value) VALUES ('created_at', ?)",
                    (_now(),))
        else:
            try:
                self.conn.execute("SELECT value FROM case_meta LIMIT 1")
            except sqlite3.DatabaseError:
                raise CaseError(f"not a vera case file: {path}") from None

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Case":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- meta ---------------------------------------------------------------

    def set_meta(self, **kv: str) -> None:
        with self.conn:
            for k, v in kv.items():
                self.conn.execute(
                    "INSERT INTO case_meta(key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (k, v))

    def meta(self) -> dict:
        return {r["key"]: r["value"]
                for r in self.conn.execute("SELECT key, value FROM case_meta")}

    # -- evidence -----------------------------------------------------------

    def add_evidence(self, label: str, kind: str = "", source: str = "",
                     sha256: str = "", notes: str = "") -> int:
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO evidence(label, kind, source, sha256, notes, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (label, kind, source, sha256, notes, _now()))
        return cur.lastrowid

    def evidence(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM evidence ORDER BY id")]

    def resolve_evidence(self, ref: str) -> int:
        """Accept an evidence id ('2' / 'E2') or a unique label substring."""
        token = ref[1:] if ref[:1].upper() == "E" and ref[1:].isdigit() else ref
        if token.isdigit():
            row = self.conn.execute("SELECT id FROM evidence WHERE id = ?",
                                    (int(token),)).fetchone()
            if row:
                return row["id"]
        rows = self.conn.execute(
            "SELECT id, label FROM evidence WHERE label LIKE ?",
            (f"%{ref}%",)).fetchall()
        if len(rows) == 1:
            return rows[0]["id"]
        if not rows:
            raise CaseError(f"no evidence matches {ref!r}")
        opts = ", ".join(f"E{r['id']} {r['label']!r}" for r in rows)
        raise CaseError(f"evidence ref {ref!r} is ambiguous: {opts}")

    # -- actions ------------------------------------------------------------

    def add_action(self, command: str, host: str = "", tool: str = "",
                   evidence_id: int | None = None, output: str = "",
                   exit_code: int | None = None, notes: str = "",
                   parent_finding_id: int | None = None,
                   performed_at: str = "") -> int:
        if not command.strip():
            raise CaseError("command must not be empty")
        if parent_finding_id is not None:
            self._require("findings", parent_finding_id, "F")
        if evidence_id is not None:
            self._require("evidence", evidence_id, "E")
        truncated = len(output) > OUTPUT_CAP
        digest = sha256_text(output) if output else ""
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO actions(performed_at, host, evidence_id, tool, command,"
                " output, output_sha256, output_truncated, exit_code, notes,"
                " parent_finding_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (performed_at or _now(), host, evidence_id,
                 tool or command.split()[0], command, output[:OUTPUT_CAP],
                 digest, int(truncated), exit_code, notes, parent_finding_id))
        return cur.lastrowid

    def last_action_id(self) -> int | None:
        row = self.conn.execute("SELECT MAX(id) AS m FROM actions").fetchone()
        return row["m"]

    # -- findings -----------------------------------------------------------

    def add_finding(self, title: str, ftype: str = "note",
                    action_id: int | None = None, host: str = "",
                    detail: str = "", event_time: str = "",
                    attrs: dict | None = None, starred: bool = False) -> int:
        if not title.strip():
            raise CaseError("finding title must not be empty")
        if action_id is not None:
            self._require("actions", action_id, "A")
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO findings(action_id, created_at, event_time, title,"
                " detail, ftype, host, attrs, starred)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (action_id, _now(), event_time, title, detail, ftype, host,
                 json.dumps(attrs or {}), int(starred)))
        return cur.lastrowid

    def findings(self, ftype: str | None = None) -> list[dict]:
        if ftype:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE ftype = ? ORDER BY id", (ftype,))
        else:
            rows = self.conn.execute("SELECT * FROM findings ORDER BY id")
        return [self._finding_dict(r) for r in rows]

    def timeline(self) -> list[dict]:
        """All findings with an event_time, oldest incident-time first."""
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE event_time != '' "
            "ORDER BY event_time, id")
        return [self._finding_dict(r) for r in rows]

    # -- updates ------------------------------------------------------------

    ACTION_EDITABLE = {"host", "tool", "command", "notes", "output",
                       "performed_at", "evidence_id", "parent_finding_id"}
    FINDING_EDITABLE = {"title", "detail", "ftype", "host", "event_time",
                        "attrs", "starred", "action_id"}

    def update_action(self, action_id: int, **fields) -> None:
        self._update("actions", self.ACTION_EDITABLE, action_id, fields, "A")

    def update_finding(self, finding_id: int, **fields) -> None:
        if isinstance(fields.get("attrs"), dict):
            fields["attrs"] = json.dumps(fields["attrs"])
        self._update("findings", self.FINDING_EDITABLE, finding_id, fields, "F")

    def _update(self, table: str, allowed: set, row_id: int,
                fields: dict, prefix: str) -> None:
        bad = set(fields) - allowed
        if bad:
            raise CaseError(f"cannot edit field(s): {', '.join(sorted(bad))}")
        if not fields:
            raise CaseError("nothing to update")
        self._require(table, row_id, prefix)
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self.conn:
            self.conn.execute(f"UPDATE {table} SET {cols} WHERE id = ?",
                              (*fields.values(), row_id))

    def _require(self, table: str, row_id: int, prefix: str) -> None:
        row = self.conn.execute(f"SELECT id FROM {table} WHERE id = ?",
                                (row_id,)).fetchone()
        if not row:
            raise CaseError(f"{prefix}{row_id} does not exist")

    # -- graph --------------------------------------------------------------

    def get_action(self, action_id: int) -> dict:
        row = self.conn.execute("SELECT * FROM actions WHERE id = ?",
                                (action_id,)).fetchone()
        if not row:
            raise CaseError(f"A{action_id} does not exist")
        return dict(row)

    def get_finding(self, finding_id: int) -> dict:
        row = self.conn.execute("SELECT * FROM findings WHERE id = ?",
                                (finding_id,)).fetchone()
        if not row:
            raise CaseError(f"F{finding_id} does not exist")
        return self._finding_dict(row)

    def tree(self) -> list[dict]:
        """Full investigation graph as nested dicts.

        Top level: actions with no parent finding, in execution order. Each
        action carries its findings; each finding carries the follow-up
        actions it prompted. Orphan findings (no action) appear at the end
        under a synthetic 'unattached' bucket handled by callers.
        """
        actions = {r["id"]: {**dict(r), "findings": []}
                   for r in self.conn.execute("SELECT * FROM actions ORDER BY id")}
        findings = {}
        for r in self.conn.execute("SELECT * FROM findings ORDER BY id"):
            f = self._finding_dict(r)
            f["actions"] = []
            findings[f["id"]] = f
            if f["action_id"] in actions:
                actions[f["action_id"]]["findings"].append(f)
        roots = []
        for a in actions.values():
            pf = a["parent_finding_id"]
            if pf in findings:
                findings[pf]["actions"].append(a)
            else:
                roots.append(a)
        return roots

    def unattached_findings(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE action_id IS NULL ORDER BY id")
        return [self._finding_dict(r) for r in rows]

    def counts(self) -> dict:
        c = {}
        for table in ("actions", "findings", "evidence"):
            c[table] = self.conn.execute(
                f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
        return c

    @staticmethod
    def _finding_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        try:
            d["attrs"] = json.loads(d.get("attrs") or "{}")
        except json.JSONDecodeError:
            d["attrs"] = {}
        return d


def resolve_ref(ref: str) -> tuple[str, int]:
    """Parse 'A4' / 'F2' / 'E1' into (kind, id)."""
    kind = ref[:1].upper()
    if kind in ("A", "F", "E") and ref[1:].isdigit():
        return kind, int(ref[1:])
    raise CaseError(f"bad reference {ref!r} (expected A<n>, F<n>, or E<n>)")

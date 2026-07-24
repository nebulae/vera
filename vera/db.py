"""Case storage: one SQLite file per investigation, all queries live here."""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import sqlite3

from . import types

SCHEMA_VERSION = 16
OUTPUT_CAP = 256 * 1024        # chars of captured command output stored per action
ATTACHMENT_CAP = 25 * 1024 * 1024  # max bytes per stored attachment

# Leading keywords that identify an OS phrase at the start of a host's notes,
# used to backfill the `os` field on upgrade (e.g. "Windows 11 - Jane" -> "Windows 11").
OS_KEYWORDS = ("windows", "server", "ubuntu", "linux", "macos", "mac", "rhel",
               "centos", "debian", "fedora", "redhat")

# Hash algorithms a finding can carry, with their expected hex-digest length.
HASH_SPECS = {"md5": 32, "sha1": 40, "sha256": 64}

# Host disposition. '' = not yet triaged; the Comp. Hosts view derives from this.
HOST_STATUSES = ("", "clean", "suspicious", "compromised")

# What a finding's event_time MEANS — a ShimCache time is a file-modification
# time, not an execution time; mixing those up on a timeline is an analytic
# error. '' = unspecified.
TIME_KINDS = ("", "executed", "created", "modified", "accessed", "logged",
              "observed")

# vera never purges rows. "Deleting" sets deleted_at; queries filter it out.

OWNER_TYPES = ("action", "finding", "evidence")
_OWNER_TABLE = {"action": "actions", "finding": "findings", "evidence": "evidence"}

SCHEMA = """
CREATE TABLE case_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    aliases     TEXT NOT NULL DEFAULT '[]',
    ip          TEXT NOT NULL DEFAULT '',
    os          TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT '',
    system_type TEXT NOT NULL DEFAULT '',
    criticality TEXT NOT NULL DEFAULT '',
    notes       TEXT NOT NULL DEFAULT '',
    deleted_at  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_hosts_name ON hosts(name COLLATE NOCASE) WHERE deleted_at = '';
CREATE TABLE accounts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    domain       TEXT NOT NULL DEFAULT '',
    sid          TEXT NOT NULL DEFAULT '',
    account_type TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT '',
    notes        TEXT NOT NULL DEFAULT '',
    deleted_at   TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_accounts_name ON accounts(name COLLATE NOCASE) WHERE deleted_at = '';
CREATE TABLE collections (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    tool         TEXT NOT NULL DEFAULT '',
    operator     TEXT NOT NULL DEFAULT '',
    collected_at TEXT NOT NULL DEFAULT '',
    scope        TEXT NOT NULL DEFAULT '',
    notes        TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);
CREATE TABLE evidence (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    label         TEXT NOT NULL,
    kind          TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT '',
    sha256        TEXT NOT NULL DEFAULT '',
    acquired_by   TEXT NOT NULL DEFAULT '',
    acquired_at   TEXT NOT NULL DEFAULT '',
    acquisition   TEXT NOT NULL DEFAULT '',
    notes         TEXT NOT NULL DEFAULT '',
    collection_id INTEGER REFERENCES collections(id),
    created_at    TEXT NOT NULL
);
CREATE TABLE actions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    performed_at      TEXT NOT NULL,
    host              TEXT NOT NULL DEFAULT '',
    evidence_id       INTEGER REFERENCES evidence(id),
    collection_id     INTEGER REFERENCES collections(id),
    tool              TEXT NOT NULL DEFAULT '',
    method            TEXT NOT NULL DEFAULT 'command',
    command           TEXT NOT NULL DEFAULT '',
    procedure         TEXT NOT NULL DEFAULT '',
    output            TEXT NOT NULL DEFAULT '',
    output_sha256     TEXT NOT NULL DEFAULT '',
    output_truncated  INTEGER NOT NULL DEFAULT 0,
    exit_code         INTEGER,
    notes             TEXT NOT NULL DEFAULT '',
    parent_finding_id INTEGER REFERENCES findings(id)
);
CREATE TABLE findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id   INTEGER REFERENCES actions(id),
    evidence_id INTEGER REFERENCES evidence(id),
    created_at TEXT NOT NULL,
    event_time TEXT NOT NULL DEFAULT '',
    time_kind  TEXT NOT NULL DEFAULT '',
    title      TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    ftype      TEXT NOT NULL DEFAULT 'note',
    host       TEXT NOT NULL DEFAULT '',
    attrs      TEXT NOT NULL DEFAULT '{}',
    hashes     TEXT NOT NULL DEFAULT '{}',
    starred    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE attachments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_type TEXT NOT NULL,
    owner_id   INTEGER NOT NULL,
    role       TEXT NOT NULL DEFAULT 'exhibit',
    filename   TEXT NOT NULL DEFAULT '',
    mime       TEXT NOT NULL DEFAULT 'image/png',
    caption    TEXT NOT NULL DEFAULT '',
    sha256     TEXT NOT NULL,
    size       INTEGER NOT NULL,
    bytes      BLOB NOT NULL,
    deleted_at TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE finding_hosts (
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    PRIMARY KEY (finding_id, host_id)
);
CREATE TABLE evidence_hosts (
    evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    PRIMARY KEY (evidence_id, host_id)
);
CREATE TABLE action_hosts (
    action_id INTEGER NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    host_id   INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    PRIMARY KEY (action_id, host_id)
);
CREATE TABLE collection_hosts (
    collection_id INTEGER NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    host_id       INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    PRIMARY KEY (collection_id, host_id)
);
CREATE TABLE finding_accounts (
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    PRIMARY KEY (finding_id, account_id)
);
CREATE INDEX idx_faccounts_account ON finding_accounts(account_id);
CREATE TABLE lead_items (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    lead_id    INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    label      TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'open',      -- open | triaged | dismissed
    finding_id INTEGER REFERENCES findings(id),   -- the finding that resolved it
    note       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    deleted_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TEXT NOT NULL,
    table_name TEXT NOT NULL,
    row_id     INTEGER NOT NULL,
    op         TEXT NOT NULL,                 -- update | soft_delete
    changes    TEXT NOT NULL DEFAULT '{}'     -- {field: {"from": .., "to": ..}}
);
CREATE INDEX idx_audit_row ON audit_log(table_name, row_id);
CREATE INDEX idx_leaditems_lead  ON lead_items(lead_id);
CREATE INDEX idx_findings_action ON findings(action_id);
CREATE INDEX idx_findings_ftype  ON findings(ftype);
CREATE INDEX idx_actions_parent  ON actions(parent_finding_id);
CREATE INDEX idx_attach_owner    ON attachments(owner_type, owner_id);
CREATE INDEX idx_fhosts_host     ON finding_hosts(host_id);
CREATE INDEX idx_ehosts_host     ON evidence_hosts(host_id);
CREATE INDEX idx_ahosts_host     ON action_hosts(host_id);
CREATE INDEX idx_chosts_host     ON collection_hosts(host_id);
"""


def _migrate_v2(conn: sqlite3.Connection) -> None:
    """v1 -> v2: generalize actions into steps, add attachments store."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(actions)")}
    if "method" not in cols:
        conn.execute("ALTER TABLE actions ADD COLUMN method TEXT NOT NULL "
                     "DEFAULT 'command'")
    if "procedure" not in cols:
        conn.execute("ALTER TABLE actions ADD COLUMN procedure TEXT NOT NULL "
                     "DEFAULT ''")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attachments (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_type TEXT NOT NULL,
            owner_id   INTEGER NOT NULL,
            role       TEXT NOT NULL DEFAULT 'exhibit',
            filename   TEXT NOT NULL DEFAULT '',
            mime       TEXT NOT NULL DEFAULT 'image/png',
            caption    TEXT NOT NULL DEFAULT '',
            sha256     TEXT NOT NULL,
            size       INTEGER NOT NULL,
            bytes      BLOB NOT NULL,
            created_at TEXT NOT NULL
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_attach_owner "
                 "ON attachments(owner_type, owner_id)")


def _migrate_v3(conn: sqlite3.Connection) -> None:
    """v2 -> v3: host registry, collections/batches, cross-host findings."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            aliases     TEXT NOT NULL DEFAULT '[]',
            ip          TEXT NOT NULL DEFAULT '',
            system_type TEXT NOT NULL DEFAULT '',
            criticality TEXT NOT NULL DEFAULT '',
            notes       TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL
        )""")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_hosts_name "
                 "ON hosts(name COLLATE NOCASE)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS collections (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL,
            tool         TEXT NOT NULL DEFAULT '',
            operator     TEXT NOT NULL DEFAULT '',
            collected_at TEXT NOT NULL DEFAULT '',
            scope        TEXT NOT NULL DEFAULT '',
            notes        TEXT NOT NULL DEFAULT '',
            created_at   TEXT NOT NULL
        )""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS finding_hosts (
            finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            PRIMARY KEY (finding_id, host_id)
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_fhosts_host "
                 "ON finding_hosts(host_id)")
    ev_cols = {r[1] for r in conn.execute("PRAGMA table_info(evidence)")}
    if "collection_id" not in ev_cols:
        conn.execute("ALTER TABLE evidence ADD COLUMN collection_id "
                     "INTEGER REFERENCES collections(id)")
    ac_cols = {r[1] for r in conn.execute("PRAGMA table_info(actions)")}
    if "collection_id" not in ac_cols:
        conn.execute("ALTER TABLE actions ADD COLUMN collection_id "
                     "INTEGER REFERENCES collections(id)")


def _migrate_v4(conn: sqlite3.Connection) -> None:
    """v3 -> v4: soft-delete. Add deleted_at; never purge rows."""
    for tbl in ("hosts", "attachments"):
        info = list(conn.execute(f"PRAGMA table_info({tbl})"))
        if not info:
            continue  # table not present in this case; nothing to migrate
        if "deleted_at" not in {r[1] for r in info}:
            conn.execute(f"ALTER TABLE {tbl} ADD COLUMN deleted_at TEXT NOT NULL "
                         "DEFAULT ''")
    # host-name uniqueness should ignore soft-deleted rows (so a name can be reused)
    conn.execute("DROP INDEX IF EXISTS idx_hosts_name")
    conn.execute("CREATE UNIQUE INDEX idx_hosts_name ON hosts(name COLLATE NOCASE) "
                 "WHERE deleted_at = ''")


def _migrate_v5(conn: sqlite3.Connection) -> None:
    """v4 -> v5: link evidence and actions to the host registry (m2m)."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS evidence_hosts (
            evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
            host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            PRIMARY KEY (evidence_id, host_id)
        )""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS action_hosts (
            action_id INTEGER NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
            host_id   INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            PRIMARY KEY (action_id, host_id)
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ehosts_host "
                 "ON evidence_hosts(host_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ahosts_host "
                 "ON action_hosts(host_id)")


def _migrate_v6(conn: sqlite3.Connection) -> None:
    """v5 -> v6: findings carry file hashes (md5/sha1/sha256/…)."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
    if "hashes" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN hashes TEXT NOT NULL "
                     "DEFAULT '{}'")


def os_from_notes(notes: str) -> str:
    """Best-effort OS phrase from the start of a host's notes (blank if unclear).

    Handles the common "<OS> - person - role" and "<OS descriptor>" shapes by
    taking the first two words when they start with a known OS keyword.
    """
    words = (notes or "").replace(" - ", "  ").split()
    if words and words[0].lower() in OS_KEYWORDS:
        return " ".join(words[:2])
    return ""


def _migrate_v7(conn: sqlite3.Connection) -> None:
    """v6 -> v7: first-class `os` field on hosts, backfilled from notes."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(hosts)")}
    if "os" not in cols:
        conn.execute("ALTER TABLE hosts ADD COLUMN os TEXT NOT NULL DEFAULT ''")
    # backfill only empty os fields, non-destructively, from the notes prefix
    for row in conn.execute("SELECT id, os, notes FROM hosts"):
        if not row[1]:
            guess = os_from_notes(row[2])
            if guess:
                conn.execute("UPDATE hosts SET os = ? WHERE id = ?", (guess, row[0]))


def _migrate_v8(conn: sqlite3.Connection) -> None:
    """v7 -> v8: collections carry a host set (evidence inherits it)."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS collection_hosts (
            collection_id INTEGER NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
            host_id       INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            PRIMARY KEY (collection_id, host_id)
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_chosts_host "
                 "ON collection_hosts(host_id)")


def _migrate_v9(conn: sqlite3.Connection) -> None:
    """v8 -> v9: host disposition (clean/suspicious/compromised)."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(hosts)")}
    if "status" not in cols:
        conn.execute("ALTER TABLE hosts ADD COLUMN status TEXT NOT NULL "
                     "DEFAULT ''")


def _migrate_v10(conn: sqlite3.Connection) -> None:
    """v9 -> v10: split a host-indicator 'artifact' that holds a full path into
    a stackable name + a 'path' field.

    Conservative and non-destructive: only when the artifact value contains a
    path separator and no 'path' is set yet. The full string is preserved in
    'path'; 'artifact' keeps its basename (the name you stack by). Bare-name
    artifacts (no separator) are left untouched.
    """
    for r in conn.execute("SELECT id, attrs FROM findings "
                          "WHERE ftype = 'hostindicator'"):
        try:
            attrs = json.loads(r[1] or "{}")
        except json.JSONDecodeError:
            continue
        if not isinstance(attrs, dict):
            continue
        art = (attrs.get("artifact") or "").strip()
        if art and not (attrs.get("path") or "").strip() \
                and ("\\" in art or "/" in art):
            attrs["path"] = art
            attrs["artifact"] = types.basename(art)
            conn.execute("UPDATE findings SET attrs = ? WHERE id = ?",
                         (json.dumps(attrs), r[0]))


def _migrate_v11(conn: sqlite3.Connection) -> None:
    """v10 -> v11: leads carry a triage worklist (`lead_items`)."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS lead_items (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            lead_id    INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            label      TEXT NOT NULL,
            status     TEXT NOT NULL DEFAULT 'open',
            finding_id INTEGER REFERENCES findings(id),
            note       TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            deleted_at TEXT NOT NULL DEFAULT ''
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_leaditems_lead "
                 "ON lead_items(lead_id)")


def _migrate_v12(conn: sqlite3.Connection) -> None:
    """v11 -> v12: findings carry the evidence they came from (inherited from
    their action, cascades to follow-up actions)."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
    if "evidence_id" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN evidence_id INTEGER")
    # backfill: existing findings inherit the evidence of the action they hang off
    conn.execute(
        "UPDATE findings SET evidence_id = "
        "(SELECT a.evidence_id FROM actions a WHERE a.id = findings.action_id) "
        "WHERE evidence_id IS NULL AND action_id IS NOT NULL")


# Accepted incoming event-time shapes (ISO-ish + the US format EZ tools emit).
_ET_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
               "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M",
               "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m/%d/%Y")


def normalize_event_time(value: str) -> str:
    """Canonicalize an incident timestamp for reliable sorting/correlation.

    Case convention: ALL event times are UTC — a trailing 'UTC'/'Z' is
    stripped, fractional seconds dropped. Precision is preserved, never
    invented: date-only stays date-only, minutes stay minutes. Raises on
    anything unparseable so a stray local-format time can't silently poison
    the timeline."""
    v = (value or "").strip()
    if not v:
        return ""
    v = re.sub(r"\s*(UTC|Z)$", "", v, flags=re.IGNORECASE).strip()
    v = re.sub(r"(\d{2}:\d{2}(?::\d{2})?)\.\d+", r"\1", v)
    for fmt in _ET_FORMATS:
        try:
            parsed = _dt.datetime.strptime(v, fmt)
        except ValueError:
            continue
        if "%H" not in fmt:
            return parsed.strftime("%Y-%m-%d")
        if "%S" in fmt:
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        return parsed.strftime("%Y-%m-%d %H:%M")
    raise CaseError(f"cannot parse event time {value!r} — use "
                    "YYYY-MM-DD [HH:MM[:SS]] (all event times are UTC)")


def _check_time_kind(kind: str) -> str:
    k = (kind or "").strip().lower()
    if k not in TIME_KINDS:
        known = ", ".join(t or "unspecified" for t in TIME_KINDS)
        raise CaseError(f"unknown time kind {kind!r} (one of: {known})")
    return k


def _migrate_v13(conn: sqlite3.Connection) -> None:
    """v12 -> v13: chain-of-custody fields on evidence — who acquired it,
    when, and how (the acquisition method/tool)."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(evidence)")}
    for col in ("acquired_by", "acquired_at", "acquisition"):
        if col not in cols:
            conn.execute(
                f"ALTER TABLE evidence ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")


def _migrate_v14(conn: sqlite3.Connection) -> None:
    """v13 -> v14: time_kind (what the event_time MEANS) on findings, and a
    best-effort normalization pass over existing event_times. Values that
    don't parse are left untouched — a migration never destroys data."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
    if "time_kind" not in cols:
        conn.execute(
            "ALTER TABLE findings ADD COLUMN time_kind TEXT NOT NULL DEFAULT ''")
    for row in conn.execute(
            "SELECT id, event_time FROM findings WHERE event_time != ''").fetchall():
        try:
            norm = normalize_event_time(row[1])
        except CaseError:
            continue
        if norm != row[1]:
            conn.execute("UPDATE findings SET event_time = ? WHERE id = ?",
                         (norm, row[0]))


def _migrate_v15(conn: sqlite3.Connection) -> None:
    """v14 -> v15: append-only audit log — every edit and soft-delete records
    field-level before/after, so 'was this changed after it was written?'
    has an answer."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            at         TEXT NOT NULL,
            table_name TEXT NOT NULL,
            row_id     INTEGER NOT NULL,
            op         TEXT NOT NULL,
            changes    TEXT NOT NULL DEFAULT '{}'
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_row "
                 "ON audit_log(table_name, row_id)")


def _migrate_v16(conn: sqlite3.Connection) -> None:
    """v15 -> v16: account registry (like the host registry) + finding links.
    Backfills from existing Compromised Account and Lateral Movement findings
    so the registry starts populated, not empty."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL,
            domain       TEXT NOT NULL DEFAULT '',
            sid          TEXT NOT NULL DEFAULT '',
            account_type TEXT NOT NULL DEFAULT '',
            status       TEXT NOT NULL DEFAULT '',
            notes        TEXT NOT NULL DEFAULT '',
            deleted_at   TEXT NOT NULL DEFAULT '',
            created_at   TEXT NOT NULL
        )""")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_name "
                 "ON accounts(name COLLATE NOCASE) WHERE deleted_at = ''")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS finding_accounts (
            finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            PRIMARY KEY (finding_id, account_id)
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_faccounts_account "
                 "ON finding_accounts(account_id)")

    def upsert(name: str, sid: str, account_type: str) -> int:
        row = conn.execute(
            "SELECT id, sid, account_type FROM accounts "
            "WHERE name = ? COLLATE NOCASE AND deleted_at = ''", (name,)).fetchone()
        if row:
            if sid and not row[1]:
                conn.execute("UPDATE accounts SET sid = ? WHERE id = ?", (sid, row[0]))
            if account_type and not row[2]:
                conn.execute("UPDATE accounts SET account_type = ? WHERE id = ?",
                             (account_type, row[0]))
            return row[0]
        return conn.execute(
            "INSERT INTO accounts(name, sid, account_type, created_at) "
            "VALUES (?, ?, ?, ?)", (name, sid, account_type, _now())).lastrowid

    for f in conn.execute("SELECT id, ftype, title, attrs FROM findings "
                          "WHERE ftype IN ('account', 'lateral')").fetchall():
        try:
            attrs = json.loads(f[3] or "{}")
        except json.JSONDecodeError:
            attrs = {}
        name = (attrs.get("account") or "").strip()
        if not name and f[1] == "account":
            name = (f[2] or "").strip()
        if not name:
            continue
        aid = upsert(name, (attrs.get("sid") or "").strip(),
                     (attrs.get("account_type") or "").strip())
        conn.execute("INSERT OR IGNORE INTO finding_accounts(finding_id,"
                     " account_id) VALUES (?, ?)", (f[0], aid))


# Applied in ascending order to bring a case up to SCHEMA_VERSION.
MIGRATIONS = {2: _migrate_v2, 3: _migrate_v3, 4: _migrate_v4, 5: _migrate_v5,
              6: _migrate_v6, 7: _migrate_v7, 8: _migrate_v8, 9: _migrate_v9,
              10: _migrate_v10, 11: _migrate_v11, 12: _migrate_v12,
              13: _migrate_v13, 14: _migrate_v14, 15: _migrate_v15,
              16: _migrate_v16}


class CaseError(Exception):
    """User-facing case/database error."""


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path: str) -> dict:
    """Compute md5/sha1/sha256 of a file in one pass."""
    digests = {algo: hashlib.new(algo) for algo in HASH_SPECS}
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                for d in digests.values():
                    d.update(chunk)
    except OSError as exc:
        raise CaseError(f"cannot hash {path}: {exc}") from None
    return {algo: d.hexdigest() for algo, d in digests.items()}


def normalize_hashes(hashes: dict | None) -> dict:
    """Lowercase, validate (hex + expected length), drop blanks. Raise on bad."""
    out = {}
    for algo, val in (hashes or {}).items():
        if algo not in HASH_SPECS:
            raise CaseError(f"unknown hash type {algo!r} "
                            f"(expected one of: {', '.join(HASH_SPECS)})")
        v = (val or "").strip().lower()
        if not v:
            continue
        want = HASH_SPECS[algo]
        if len(v) != want or any(c not in "0123456789abcdef" for c in v):
            raise CaseError(f"{algo} must be {want} hex characters, got {val!r}")
        out[algo] = v
    return out


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
            self._migrate()

    def _migrate(self) -> None:
        """Bring an older case file up to the current SCHEMA_VERSION."""
        row = self.conn.execute(
            "SELECT value FROM case_meta WHERE key = 'schema_version'").fetchone()
        current = int(row["value"]) if row else 1
        if current < SCHEMA_VERSION:
            self._backup_before_migration(current)
        for version in sorted(MIGRATIONS):
            if current < version:
                with self.conn:
                    MIGRATIONS[version](self.conn)
                    self.conn.execute(
                        "INSERT INTO case_meta(key, value) VALUES "
                        "('schema_version', ?) ON CONFLICT(key) DO UPDATE SET "
                        "value = excluded.value", (str(version),))
                current = version

    def _backup_before_migration(self, from_version: int) -> None:
        """Copy the case file aside before a schema migration touches it, so a
        buggy migration can never eat the only copy of an investigation. The
        backup name records the schema it holds; an existing backup for the
        same version is left alone (first one wins — it's the oldest state)."""
        backup = f"{self.path}.pre-v{from_version}"
        if not os.path.exists(self.path) or os.path.exists(backup):
            return
        dest = sqlite3.connect(backup)
        try:
            with dest:
                self.conn.backup(dest)
        finally:
            dest.close()

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
                     sha256: str = "", notes: str = "",
                     collection_id: int | None = None,
                     host_ids: list[int] | None = None,
                     acquired_by: str = "", acquired_at: str = "",
                     acquisition: str = "") -> int:
        if collection_id is not None:
            self._require("collections", collection_id, "C")
            # evidence in a collection sources its hosts from the collection
            # (explicit host_ids — e.g. a per-host expansion item — still wins)
            if not host_ids:
                host_ids = self.collection_host_ids(collection_id)
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO evidence(label, kind, source, sha256, acquired_by,"
                " acquired_at, acquisition, notes, collection_id, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (label, kind, source, sha256, acquired_by, acquired_at,
                 acquisition, notes, collection_id, _now()))
            eid = cur.lastrowid
        if host_ids:
            self.set_evidence_hosts(eid, host_ids, audit=False)
        return eid

    def evidence(self) -> list[dict]:
        att = self._attachment_index()
        links = self._host_links("evidence_hosts")
        return [{**dict(r), "attachments": att.get(("evidence", r["id"]), []),
                 "hosts": links.get(r["id"], [])}
                for r in self.conn.execute("SELECT * FROM evidence ORDER BY id")]

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

    def add_action(self, command: str = "", host: str = "", tool: str = "",
                   evidence_id: int | None = None, output: str = "",
                   exit_code: int | None = None, notes: str = "",
                   parent_finding_id: int | None = None,
                   performed_at: str = "", method: str = "command",
                   procedure: str = "", collection_id: int | None = None,
                   host_ids: list[int] | None = None) -> int:
        if method not in ("command", "manual"):
            raise CaseError(f"unknown method {method!r} (command or manual)")
        if method == "command" and not command.strip():
            raise CaseError("command must not be empty")
        if method == "manual" and not tool.strip():
            raise CaseError("a manual step needs a --tool (the tool you used)")
        if parent_finding_id is not None:
            self._require("findings", parent_finding_id, "F")
            # a follow-up step examines the same evidence as the finding that
            # prompted it (which got it from its own action) — cascade it down
            if evidence_id is None:
                row = self.conn.execute(
                    "SELECT evidence_id FROM findings WHERE id = ?",
                    (parent_finding_id,)).fetchone()
                evidence_id = row["evidence_id"] if row else None
        if evidence_id is not None:
            self._require("evidence", evidence_id, "E")
        # an action inherits its collection AND its hosts from the evidence it
        # examines — hosts belong to evidence/collections, not individual steps,
        # so neither has to be picked separately (explicit host_ids still wins)
        if collection_id is None and evidence_id is not None:
            row = self.conn.execute("SELECT collection_id FROM evidence WHERE id = ?",
                                    (evidence_id,)).fetchone()
            collection_id = row["collection_id"] if row else None
        if not host_ids and evidence_id is not None:
            host_ids = self.evidence_host_ids(evidence_id)
        if collection_id is not None:
            self._require("collections", collection_id, "C")
        if exit_code is not None:
            try:
                exit_code = int(exit_code)
            except (TypeError, ValueError):
                raise CaseError("exit_code must be an integer") from None
        truncated = len(output) > OUTPUT_CAP
        digest = sha256_text(output) if output else ""
        default_tool = command.split()[0] if (method == "command" and command) else ""
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO actions(performed_at, host, evidence_id, collection_id,"
                " tool, method, command, procedure, output, output_sha256,"
                " output_truncated, exit_code, notes, parent_finding_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (performed_at or _now(), host, evidence_id, collection_id,
                 tool or default_tool, method, command, procedure,
                 output[:OUTPUT_CAP], digest, int(truncated), exit_code, notes,
                 parent_finding_id))
            aid = cur.lastrowid
        if host_ids:
            self.set_action_hosts(aid, host_ids, audit=False)
        return aid

    def clone_action(self, action_id: int, **overrides) -> int:
        """Duplicate an action (command/procedure, tool, method, evidence,
        collection, hosts, notes, and the finding it hangs off) into a new step,
        for logging a similar step without re-typing. Captured output and
        attachments are NOT copied — a clone is a fresh run you re-capture.
        Keyword overrides replace the copied value."""
        src = self.get_action(action_id)
        fields = {
            "command": src.get("command", ""),
            "host": src.get("host", ""),
            "tool": src.get("tool", ""),
            "evidence_id": src.get("evidence_id"),
            "notes": src.get("notes", ""),
            "parent_finding_id": src.get("parent_finding_id"),
            "method": src.get("method", "command"),
            "procedure": src.get("procedure", ""),
            "collection_id": src.get("collection_id"),
            "host_ids": [h["id"] for h in src.get("hosts", [])] or None,
        }
        fields.update(overrides)
        return self.add_action(**fields)

    def last_action_id(self) -> int | None:
        row = self.conn.execute("SELECT MAX(id) AS m FROM actions").fetchone()
        return row["m"]

    # -- findings -----------------------------------------------------------

    def add_finding(self, title: str, ftype: str = "note",
                    action_id: int | None = None, host: str = "",
                    detail: str = "", event_time: str = "",
                    attrs: dict | None = None, starred: bool = False,
                    host_ids: list[int] | None = None,
                    hashes: dict | None = None,
                    evidence_id: int | None = None,
                    time_kind: str = "",
                    account_ids: list[int] | None = None) -> int:
        if not title.strip():
            raise CaseError("finding title must not be empty")
        event_time = normalize_event_time(event_time)
        time_kind = _check_time_kind(time_kind)
        if action_id is not None:
            self._require("actions", action_id, "A")
        # a finding carries the evidence it came from — inherited from its
        # action when not given, so it can cascade to follow-up actions
        if evidence_id is None and action_id is not None:
            row = self.conn.execute("SELECT evidence_id FROM actions WHERE id = ?",
                                    (action_id,)).fetchone()
            evidence_id = row["evidence_id"] if row else None
        if evidence_id is not None:
            self._require("evidence", evidence_id, "E")
        clean_hashes = normalize_hashes(hashes)
        attrs = self._normalize_finding_attrs(ftype, attrs)
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO findings(action_id, evidence_id, created_at,"
                " event_time, time_kind, title, detail, ftype, host, attrs,"
                " hashes, starred)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (action_id, evidence_id, _now(), event_time, time_kind, title,
                 detail, ftype, host, json.dumps(attrs),
                 json.dumps(clean_hashes), int(starred)))
            fid = cur.lastrowid
        if host_ids:
            self.set_finding_hosts(fid, host_ids, audit=False)
        if account_ids:
            self.set_finding_accounts(fid, account_ids, audit=False)
        else:
            self._merge_derived_account(fid)
        return fid

    def clone_finding(self, finding_id: int, **overrides) -> int:
        """Duplicate a finding (type, detail, attrs, hashes, affected hosts, and
        the action it hangs off) into a new one, for entering similar findings
        without re-typing everything. Attachments are NOT copied (they are
        evidence specific to the original); the clone starts un-starred. Any
        keyword overrides (e.g. title=) replace the copied value."""
        src = self.get_finding(finding_id)
        fields = {
            "title": src["title"],
            "ftype": src["ftype"],
            "action_id": src.get("action_id"),
            "evidence_id": src.get("evidence_id"),
            "host": src.get("host", ""),
            "detail": src.get("detail", ""),
            "event_time": src.get("event_time", ""),
            "time_kind": src.get("time_kind", ""),
            "attrs": dict(src.get("attrs") or {}),
            "hashes": dict(src.get("hashes") or {}),
            "host_ids": [h["id"] for h in src.get("affected_hosts", [])] or None,
        }
        fields.update(overrides)
        return self.add_finding(**fields)

    def findings(self, ftype: str | None = None) -> list[dict]:
        if ftype:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE ftype = ? ORDER BY id", (ftype,))
        else:
            rows = self.conn.execute("SELECT * FROM findings ORDER BY id")
        return self._enrich([self._finding_dict(r) for r in rows])

    def timeline(self) -> list[dict]:
        """All findings with an event_time, oldest incident-time first."""
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE event_time != '' "
            "ORDER BY event_time, id")
        return self._enrich([self._finding_dict(r) for r in rows])

    # -- updates ------------------------------------------------------------

    ACTION_EDITABLE = {"host", "tool", "command", "method", "procedure", "notes",
                       "output", "exit_code", "performed_at", "evidence_id",
                       "collection_id", "parent_finding_id"}
    FINDING_EDITABLE = {"title", "detail", "ftype", "host", "event_time",
                        "time_kind", "attrs", "hashes", "starred", "action_id",
                        "evidence_id"}
    EVIDENCE_EDITABLE = {"label", "kind", "source", "sha256", "notes",
                         "collection_id", "acquired_by", "acquired_at",
                         "acquisition"}

    def update_action(self, action_id: int, **fields) -> None:
        # validate against the public set FIRST so clients can never set the
        # derived integrity columns (output_sha256/output_truncated) directly
        bad = set(fields) - self.ACTION_EDITABLE
        if bad:
            raise CaseError(f"cannot edit field(s): {', '.join(sorted(bad))}")
        if fields.get("exit_code") is not None:
            try:
                fields["exit_code"] = int(fields["exit_code"])
            except (TypeError, ValueError):
                raise CaseError("exit_code must be an integer") from None
        allowed = self.ACTION_EDITABLE
        if "output" in fields:
            # editing the captured output re-derives its hash + truncation so
            # the stored sha256 always matches the stored text
            out = fields["output"] or ""
            fields.update(output=out[:OUTPUT_CAP],
                          output_sha256=sha256_text(out) if out else "",
                          output_truncated=int(len(out) > OUTPUT_CAP))
            allowed = allowed | {"output_sha256", "output_truncated"}
        self._update("actions", allowed, action_id, fields, "A")

    def update_evidence(self, evidence_id: int, **fields) -> None:
        if fields.get("collection_id") is not None:
            self._require("collections", fields["collection_id"], "C")
        if "label" in fields and not str(fields["label"]).strip():
            raise CaseError("evidence label must not be empty")
        self._update("evidence", self.EVIDENCE_EDITABLE, evidence_id, fields, "E")

    @staticmethod
    def _normalize_finding_attrs(ftype: str, attrs: dict | None) -> dict:
        """Fill a host-indicator's stackable name from its path when left blank,
        so `--path C:\\...\\evil.dll` alone yields artifact `evil.dll`."""
        attrs = dict(attrs or {})
        if ftype in ("hostindicator", "filesystem"):
            path = (attrs.get("path") or "").strip()
            if path and not (attrs.get("artifact") or "").strip():
                attrs["artifact"] = types.basename(path)
        return attrs

    def update_finding(self, finding_id: int, **fields) -> None:
        if isinstance(fields.get("attrs"), dict):
            ftype = fields.get("ftype")
            if ftype is None:
                row = self.conn.execute(
                    "SELECT ftype FROM findings WHERE id = ?", (finding_id,)
                ).fetchone()
                ftype = row["ftype"] if row else ""
            fields["attrs"] = json.dumps(
                self._normalize_finding_attrs(ftype, fields["attrs"]))
        if "hashes" in fields and isinstance(fields["hashes"], dict):
            fields["hashes"] = json.dumps(normalize_hashes(fields["hashes"]))
        if fields.get("evidence_id") is not None:
            self._require("evidence", fields["evidence_id"], "E")
        if "event_time" in fields:
            fields["event_time"] = normalize_event_time(fields["event_time"])
        if "time_kind" in fields:
            fields["time_kind"] = _check_time_kind(fields["time_kind"])
        content_change = bool({"attrs", "title", "ftype"} & set(fields))
        old_derived = self._derived_account(finding_id) if content_change else None
        self._update("findings", self.FINDING_EDITABLE, finding_id, fields, "F")
        # the derived account tie follows the finding's content: renaming the
        # named account moves its link; explicitly picked accounts stay put
        if content_change:
            new_derived = self._derived_account(finding_id)
            old_name = old_derived[0] if old_derived else ""
            new_name = new_derived[0] if new_derived else ""
            if old_name and old_name.lower() != new_name.lower():
                stale = self._find_account(old_name)
                if stale is not None:
                    with self.conn:
                        self.conn.execute(
                            "DELETE FROM finding_accounts WHERE finding_id = ?"
                            " AND account_id = ?", (finding_id, stale))
            self._merge_derived_account(finding_id)

    def _audit(self, table: str, row_id: int, op: str, changes: dict) -> None:
        """Append to the audit log (same transaction as the change). The log
        is append-only: nothing in vera ever updates or deletes its rows."""
        if op == "update" and not changes:
            return
        self.conn.execute(
            "INSERT INTO audit_log(at, table_name, row_id, op, changes)"
            " VALUES (?, ?, ?, ?, ?)",
            (_now(), table, row_id, op, json.dumps(changes, default=str)))

    def _update(self, table: str, allowed: set, row_id: int,
                fields: dict, prefix: str) -> None:
        bad = set(fields) - allowed
        if bad:
            raise CaseError(f"cannot edit field(s): {', '.join(sorted(bad))}")
        if not fields:
            raise CaseError("nothing to update")
        self._require(table, row_id, prefix)
        old = self.conn.execute(f"SELECT * FROM {table} WHERE id = ?",
                                (row_id,)).fetchone()
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self.conn:
            self.conn.execute(f"UPDATE {table} SET {cols} WHERE id = ?",
                              (*fields.values(), row_id))
            self._audit(table, row_id, "update",
                        {k: {"from": old[k], "to": v}
                         for k, v in fields.items() if old[k] != v})

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
        d = dict(row)
        d["attachments"] = self.attachments("action", action_id)
        d["hosts"] = self._host_links("action_hosts").get(action_id, [])
        return d

    def get_finding(self, finding_id: int) -> dict:
        row = self.conn.execute("SELECT * FROM findings WHERE id = ?",
                                (finding_id,)).fetchone()
        if not row:
            raise CaseError(f"F{finding_id} does not exist")
        f = self._finding_dict(row)
        f["attachments"] = self.attachments("finding", finding_id)
        self._enrich([f])
        return f

    def tree(self) -> list[dict]:
        """Full investigation graph as nested dicts.

        Top level: actions with no parent finding, in execution order. Each
        action carries its findings; each finding carries the follow-up
        actions it prompted. Orphan findings (no action) appear at the end
        under a synthetic 'unattached' bucket handled by callers.
        """
        att = self._attachment_index()
        ahosts = self._host_links("action_hosts")
        actions = {}
        for r in self.conn.execute("SELECT * FROM actions ORDER BY id"):
            a = {**dict(r), "findings": [],
                 "attachments": att.get(("action", r["id"]), []),
                 "hosts": ahosts.get(r["id"], [])}
            actions[r["id"]] = a
        findings = {}
        for r in self.conn.execute("SELECT * FROM findings ORDER BY id"):
            f = self._finding_dict(r)
            f["actions"] = []
            f["attachments"] = att.get(("finding", f["id"]), [])
            findings[f["id"]] = f
            if f["action_id"] in actions:
                actions[f["action_id"]]["findings"].append(f)
        self._enrich(findings.values())
        roots = []
        for a in actions.values():
            pf = a["parent_finding_id"]
            if pf in findings:
                findings[pf]["actions"].append(a)
            else:
                roots.append(a)
        return roots

    def unattached_findings(self) -> list[dict]:
        att = self._attachment_index()
        out = []
        for r in self.conn.execute(
                "SELECT * FROM findings WHERE action_id IS NULL ORDER BY id"):
            f = self._finding_dict(r)
            f["attachments"] = att.get(("finding", f["id"]), [])
            out.append(f)
        return self._enrich(out)

    def counts(self) -> dict:
        c = {}
        for table in ("actions", "findings", "evidence", "collections"):
            c[table] = self.conn.execute(
                f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
        c["hosts"] = self.conn.execute(
            "SELECT COUNT(*) AS n FROM hosts WHERE deleted_at = ''").fetchone()["n"]
        c["accounts"] = self.conn.execute(
            "SELECT COUNT(*) AS n FROM accounts WHERE deleted_at = ''"
        ).fetchone()["n"]
        return c

    @staticmethod
    def _finding_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        for key in ("attrs", "hashes"):
            try:
                d[key] = json.loads(d.get(key) or "{}")
            except json.JSONDecodeError:
                d[key] = {}
        return d

    # -- hosts --------------------------------------------------------------

    @staticmethod
    def _check_status(status: str) -> str:
        status = (status or "").strip().lower()
        if status in ("unknown", "none"):
            status = ""
        if status not in HOST_STATUSES:
            known = ", ".join(s or "unknown" for s in HOST_STATUSES)
            raise CaseError(f"bad host status {status!r} (one of: {known})")
        return status

    def add_host(self, name: str, aliases: list[str] | None = None, ip: str = "",
                 system_type: str = "", criticality: str = "",
                 notes: str = "", os: str = "", status: str = "") -> int:
        """Register a host; reuse an existing row if the name/alias collides."""
        name = name.strip()
        if not name:
            raise CaseError("host name must not be empty")
        if not os and notes:
            os = os_from_notes(notes)  # convenience: derive OS from notes prefix
        status = self._check_status(status)
        existing = self._find_host(name)
        if existing is not None:
            # merge any new aliases / fill blank fields on the existing host
            self._merge_host(existing, aliases, ip, system_type, criticality,
                             notes, os, status)
            return existing
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO hosts(name, aliases, ip, os, status, system_type,"
                " criticality, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (name, json.dumps(aliases or []), ip, os, status, system_type,
                 criticality, notes, _now()))
        return cur.lastrowid

    def _merge_host(self, host_id: int, aliases, ip, system_type,
                    criticality, notes, os="", status="") -> None:
        row = self.conn.execute("SELECT * FROM hosts WHERE id = ?",
                                (host_id,)).fetchone()
        try:
            cur_aliases = json.loads(row["aliases"] or "[]")
        except json.JSONDecodeError:
            cur_aliases = []
        merged = list(cur_aliases)
        lowered = {str(a).lower() for a in cur_aliases}
        for a in (aliases or []):
            if a and a.lower() not in lowered and a.lower() != row["name"].lower():
                merged.append(a)
                lowered.add(a.lower())
        fields = {"aliases": json.dumps(merged)}
        for key, val in (("ip", ip), ("os", os), ("status", status),
                         ("system_type", system_type),
                         ("criticality", criticality), ("notes", notes)):
            if val and not row[key]:
                fields[key] = val
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self.conn:
            self.conn.execute(f"UPDATE hosts SET {cols} WHERE id = ?",
                              (*fields.values(), host_id))

    def _find_host(self, token: str) -> int | None:
        token = token.strip()
        row = self.conn.execute(
            "SELECT id FROM hosts WHERE name = ? COLLATE NOCASE AND deleted_at = ''",
            (token,)).fetchone()
        if row:
            return row["id"]
        for r in self.conn.execute(
                "SELECT id, aliases FROM hosts WHERE deleted_at = ''"):
            try:
                aliases = json.loads(r["aliases"] or "[]")
            except json.JSONDecodeError:
                aliases = []
            if any(token.lower() == str(a).lower() for a in aliases):
                return r["id"]
        return None

    def resolve_host(self, ref: str, create: bool = False) -> int:
        """Accept 'H<id>'/'<id>', a host name (case-insensitive), or an alias."""
        token = ref.strip()
        bare = token[1:] if token[:1].upper() == "H" and token[1:].isdigit() else token
        if bare.isdigit():
            row = self.conn.execute(
                "SELECT id FROM hosts WHERE id = ? AND deleted_at = ''",
                (int(bare),)).fetchone()
            if row:
                return row["id"]
            if not create:
                raise CaseError(f"host {ref!r} does not exist")
        found = self._find_host(token)
        if found is not None:
            return found
        if create:
            return self.add_host(token)
        raise CaseError(f"no host matches {ref!r} (add it with 'vera host add')")

    def resolve_hosts(self, refs: list[str], create: bool = False) -> list[int]:
        ids, seen = [], set()
        for ref in refs:
            if not ref.strip():
                continue
            hid = self.resolve_host(ref, create=create)
            if hid not in seen:
                seen.add(hid)
                ids.append(hid)
        return ids

    def hosts(self) -> list[dict]:
        counts = self.host_finding_counts()
        out = []
        for r in self.conn.execute(
                "SELECT * FROM hosts WHERE deleted_at = '' "
                "ORDER BY name COLLATE NOCASE"):
            d = dict(r)
            try:
                d["aliases"] = json.loads(d.get("aliases") or "[]")
            except json.JSONDecodeError:
                d["aliases"] = []
            d["finding_count"] = counts.get(r["id"], 0)
            out.append(d)
        return out

    def soft_delete_host(self, host_id: int) -> None:
        """Mark a host deleted (never purged). Its finding links are retained."""
        self._require("hosts", host_id, "H")
        with self.conn:
            self.conn.execute("UPDATE hosts SET deleted_at = ? WHERE id = ?",
                              (_now(), host_id))
            self._audit("hosts", host_id, "soft_delete", {})

    HOST_EDITABLE = {"name", "aliases", "ip", "os", "status", "system_type",
                     "criticality", "notes"}

    def update_host(self, host_id: int, **fields) -> None:
        self._require("hosts", host_id, "H")
        bad = set(fields) - self.HOST_EDITABLE
        if bad:
            raise CaseError(f"cannot edit host field(s): {', '.join(sorted(bad))}")
        if isinstance(fields.get("aliases"), list):
            fields["aliases"] = json.dumps(fields["aliases"])
        if "status" in fields:
            fields["status"] = self._check_status(fields["status"])
        if "name" in fields:
            name = fields["name"].strip()
            if not name:
                raise CaseError("host name must not be empty")
            clash = self.conn.execute(
                "SELECT id FROM hosts WHERE name = ? COLLATE NOCASE AND id != ? "
                "AND deleted_at = ''", (name, host_id)).fetchone()
            if clash:
                raise CaseError(f"another host is already named {name!r} "
                                f"(H{clash['id']})")
            fields["name"] = name
        if not fields:
            raise CaseError("nothing to update")
        old = self.conn.execute("SELECT * FROM hosts WHERE id = ?",
                                (host_id,)).fetchone()
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self.conn:
            self.conn.execute(f"UPDATE hosts SET {cols} WHERE id = ?",
                              (*fields.values(), host_id))
            self._audit("hosts", host_id, "update",
                        {k: {"from": old[k], "to": v}
                         for k, v in fields.items() if old[k] != v})

    def host_finding_counts(self) -> dict[int, int]:
        return {r["host_id"]: r["n"] for r in self.conn.execute(
            "SELECT host_id, COUNT(*) AS n FROM finding_hosts GROUP BY host_id")}

    def findings_for_host(self, host_id: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT f.* FROM findings f JOIN finding_hosts fh ON fh.finding_id = f.id "
            "WHERE fh.host_id = ? ORDER BY f.id", (host_id,))
        return self._enrich([self._finding_dict(r) for r in rows])

    def evidence_for_host(self, host_id: int) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT e.id, e.label, e.kind FROM evidence e "
            "JOIN evidence_hosts eh ON eh.evidence_id = e.id "
            "WHERE eh.host_id = ? ORDER BY e.id", (host_id,))]

    def actions_for_host(self, host_id: int) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT a.id, a.tool, a.method, a.command, a.procedure FROM actions a "
            "JOIN action_hosts ah ON ah.action_id = a.id "
            "WHERE ah.host_id = ? ORDER BY a.id", (host_id,))]

    # -- accounts -----------------------------------------------------------
    # A registry of user/service accounts seen in the case (like the host
    # registry): findings that name an account (Compromised Account, Lateral
    # Movement) auto-register it here and link to it, so account names can be
    # offered as suggestions and one account's findings can be pulled together.

    def add_account(self, name: str, domain: str = "", sid: str = "",
                    account_type: str = "", status: str = "",
                    notes: str = "") -> int:
        """Register an account; reuse an existing row if the name collides
        (case-insensitive), filling any blank fields from the new values."""
        name = name.strip()
        if not name:
            raise CaseError("account name must not be empty")
        status = self._check_status(status)
        existing = self._find_account(name)
        if existing is not None:
            row = self.conn.execute("SELECT * FROM accounts WHERE id = ?",
                                    (existing,)).fetchone()
            fields = {k: v for k, v in (("domain", domain), ("sid", sid),
                                        ("account_type", account_type),
                                        ("status", status), ("notes", notes))
                      if v and not row[k]}
            if fields:
                cols = ", ".join(f"{k} = ?" for k in fields)
                with self.conn:
                    self.conn.execute(f"UPDATE accounts SET {cols} WHERE id = ?",
                                      (*fields.values(), existing))
            return existing
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO accounts(name, domain, sid, account_type, status,"
                " notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name, domain, sid, account_type, status, notes, _now()))
            return cur.lastrowid

    def _find_account(self, token: str) -> int | None:
        row = self.conn.execute(
            "SELECT id FROM accounts WHERE name = ? COLLATE NOCASE "
            "AND deleted_at = ''", (token.strip(),)).fetchone()
        return row["id"] if row else None

    def resolve_account(self, ref: str, create: bool = False) -> int:
        """Accept a numeric id or an account name (case-insensitive)."""
        token = ref.strip()
        if token.isdigit():
            row = self.conn.execute(
                "SELECT id FROM accounts WHERE id = ? AND deleted_at = ''",
                (int(token),)).fetchone()
            if row:
                return row["id"]
            if not create:
                raise CaseError(f"account {ref!r} does not exist")
        found = self._find_account(token)
        if found is not None:
            return found
        if create:
            return self.add_account(token)
        raise CaseError(
            f"no account matches {ref!r} (add it with 'vera account add')")

    def accounts(self) -> list[dict]:
        counts = self.account_finding_counts()
        return [{**dict(r), "finding_count": counts.get(r["id"], 0)}
                for r in self.conn.execute(
                    "SELECT * FROM accounts WHERE deleted_at = '' "
                    "ORDER BY name COLLATE NOCASE")]

    ACCOUNT_EDITABLE = {"name", "domain", "sid", "account_type", "status",
                        "notes"}

    def update_account(self, account_id: int, **fields) -> None:
        self._require("accounts", account_id, "account ")
        bad = set(fields) - self.ACCOUNT_EDITABLE
        if bad:
            raise CaseError(
                f"cannot edit account field(s): {', '.join(sorted(bad))}")
        if "status" in fields:
            fields["status"] = self._check_status(fields["status"])
        if "name" in fields:
            name = str(fields["name"]).strip()
            if not name:
                raise CaseError("account name must not be empty")
            clash = self.conn.execute(
                "SELECT id FROM accounts WHERE name = ? COLLATE NOCASE "
                "AND id != ? AND deleted_at = ''", (name, account_id)).fetchone()
            if clash:
                raise CaseError(f"another account is already named {name!r}")
            fields["name"] = name
        self._update("accounts", self.ACCOUNT_EDITABLE, account_id, fields,
                     "account ")

    def soft_delete_account(self, account_id: int) -> None:
        """Mark an account deleted (never purged); finding links are retained."""
        self._require("accounts", account_id, "account ")
        with self.conn:
            self.conn.execute("UPDATE accounts SET deleted_at = ? WHERE id = ?",
                              (_now(), account_id))
            self._audit("accounts", account_id, "soft_delete", {})

    def account_finding_counts(self) -> dict[int, int]:
        return {r["account_id"]: r["n"] for r in self.conn.execute(
            "SELECT account_id, COUNT(*) AS n FROM finding_accounts "
            "GROUP BY account_id")}

    def findings_for_account(self, account_id: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT f.* FROM findings f "
            "JOIN finding_accounts fa ON fa.finding_id = f.id "
            "WHERE fa.account_id = ? ORDER BY f.id", (account_id,))
        return self._enrich([self._finding_dict(r) for r in rows])

    def resolve_accounts(self, refs: list[str], create: bool = False) -> list[int]:
        ids, seen = [], set()
        for ref in refs:
            if not ref.strip():
                continue
            acct_id = self.resolve_account(ref, create=create)
            if acct_id not in seen:
                seen.add(acct_id)
                ids.append(acct_id)
        return ids

    def set_finding_accounts(self, finding_id: int, account_ids: list[int],
                             audit: bool = True) -> None:
        """Replace a finding's account links (the picker is authoritative) —
        except that the account NAMED in the finding's own attrs/title is
        always re-merged, so the content and its links can't contradict."""
        self._require("findings", finding_id, "F")
        for acct_id in account_ids:
            self._require("accounts", acct_id, "account ")
        old_ids = sorted(r[0] for r in self.conn.execute(
            "SELECT account_id FROM finding_accounts WHERE finding_id = ?",
            (finding_id,)))
        with self.conn:
            self.conn.execute(
                "DELETE FROM finding_accounts WHERE finding_id = ?",
                (finding_id,))
            self.conn.executemany(
                "INSERT OR IGNORE INTO finding_accounts(finding_id, account_id)"
                " VALUES (?, ?)", [(finding_id, a) for a in account_ids])
            new_ids = sorted(set(account_ids))
            if audit and new_ids != old_ids:
                self._audit("findings", finding_id, "update",
                            {"account_ids": {"from": old_ids, "to": new_ids}})
        self._merge_derived_account(finding_id)

    def _derived_account(self, finding_id: int) -> tuple[str, str, str] | None:
        """(name, sid, account_type) named by the finding's own content:
        Compromised Account = attrs.account (falling back to the title);
        Lateral Movement = attrs.account (the account that authenticated)."""
        row = self.conn.execute(
            "SELECT ftype, title, attrs FROM findings WHERE id = ?",
            (finding_id,)).fetchone()
        if row is None or row["ftype"] not in ("account", "lateral"):
            return None
        try:
            attrs = json.loads(row["attrs"] or "{}")
        except json.JSONDecodeError:
            attrs = {}
        name = (attrs.get("account") or "").strip()
        if not name and row["ftype"] == "account":
            name = (row["title"] or "").strip()
        if not name:
            return None
        return (name, (attrs.get("sid") or "").strip(),
                (attrs.get("account_type") or "").strip())

    def _merge_derived_account(self, finding_id: int) -> None:
        """Auto-register + link the account the finding names. Merge-only:
        explicitly picked accounts on the finding are never removed here."""
        derived = self._derived_account(finding_id)
        if not derived:
            return
        name, sid, atype = derived
        acct_id = self.add_account(name, sid=sid, account_type=atype)
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO finding_accounts(finding_id, account_id)"
                " VALUES (?, ?)", (finding_id, acct_id))

    def coverage(self) -> dict:
        """Per-host analysis rollup: what has (and hasn't) been examined.

        Answers "did we look at everything?" — hosts with zero actions are the
        gaps. Tools come from the actions actually logged, so the matrix grows
        with the investigation.
        """
        def _counts(table: str) -> dict[int, int]:
            owner = self._HOST_LINK[table]
            return {r["host_id"]: r["n"] for r in self.conn.execute(
                f"SELECT host_id, COUNT(DISTINCT {owner}) AS n FROM {table} "
                "GROUP BY host_id")}

        ev_n, act_n = _counts("evidence_hosts"), _counts("action_hosts")
        find_n = self.host_finding_counts()
        last = {r["host_id"]: r["last"] for r in self.conn.execute(
            "SELECT ah.host_id, MAX(a.performed_at) AS last FROM action_hosts ah "
            "JOIN actions a ON a.id = ah.action_id GROUP BY ah.host_id")}
        per_tool: dict[int, dict[str, int]] = {}
        tools: list[str] = []
        for r in self.conn.execute(
                "SELECT ah.host_id, COALESCE(NULLIF(a.tool, ''), '(other)') AS tool,"
                " COUNT(*) AS n FROM action_hosts ah "
                "JOIN actions a ON a.id = ah.action_id "
                "GROUP BY ah.host_id, tool ORDER BY tool"):
            per_tool.setdefault(r["host_id"], {})[r["tool"]] = r["n"]
            if r["tool"] not in tools:
                tools.append(r["tool"])
        hosts = []
        for h in self.hosts():
            hosts.append({
                "id": h["id"], "name": h["name"], "ip": h["ip"], "os": h["os"],
                "status": h["status"], "system_type": h["system_type"],
                "evidence": ev_n.get(h["id"], 0),
                "actions": act_n.get(h["id"], 0),
                "findings": find_n.get(h["id"], 0),
                "last_examined": last.get(h["id"], ""),
                "tools": per_tool.get(h["id"], {}),
            })
        return {"tools": tools, "hosts": hosts}

    # -- collections --------------------------------------------------------

    def add_collection(self, name: str, tool: str = "", operator: str = "",
                       collected_at: str = "", scope: str = "",
                       notes: str = "", host_ids: list[int] | None = None) -> int:
        if not name.strip():
            raise CaseError("collection name must not be empty")
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO collections(name, tool, operator, collected_at,"
                " scope, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name, tool, operator, collected_at, scope, notes, _now()))
            cid = cur.lastrowid
        if host_ids:
            self.set_collection_hosts(cid, host_ids, audit=False)
        return cid

    def collections(self) -> list[dict]:
        links = self._host_links("collection_hosts")
        return [{**dict(r), "hosts": links.get(r["id"], [])}
                for r in self.conn.execute("SELECT * FROM collections ORDER BY id")]

    def tool_suggestions(self) -> list[str]:
        """Tool/action names to offer as autocomplete in the Step modal.

        Tools this case has actually used (in steps and collections) come first
        and most-recent-first, so an analyst's own toolset floats to the top;
        the curated DEFAULT_TOOLS fill in the rest. Deduped case-insensitively,
        keeping the first-seen spelling.
        """
        seen: set[str] = set()
        out: list[str] = []

        def add(name: str) -> None:
            name = (name or "").strip()
            key = name.lower()
            if name and key not in seen:
                seen.add(key)
                out.append(name)

        for r in self.conn.execute(
                "SELECT tool FROM actions WHERE tool != '' ORDER BY id DESC"):
            add(r["tool"])
        for r in self.conn.execute(
                "SELECT tool FROM collections WHERE tool != '' ORDER BY id DESC"):
            add(r["tool"])
        for name in types.DEFAULT_TOOLS:
            add(name)
        return out

    COLLECTION_EDITABLE = {"name", "tool", "operator", "collected_at", "scope",
                           "notes"}

    def update_collection(self, collection_id: int, **fields) -> None:
        if "name" in fields and not str(fields["name"]).strip():
            raise CaseError("collection name must not be empty")
        self._update("collections", self.COLLECTION_EDITABLE, collection_id,
                     fields, "C")

    def collection_host_ids(self, collection_id: int) -> list[int]:
        return [r["host_id"] for r in self.conn.execute(
            "SELECT host_id FROM collection_hosts WHERE collection_id = ? "
            "ORDER BY host_id", (collection_id,))]

    def expand_collection(self, collection_id: int, kind: str = "") -> list[dict]:
        """One evidence item per collection host (Lab-2 style per-host artifacts).

        Idempotent: hosts that already have evidence in this collection are
        skipped, so re-running after adding hosts only fills the gaps.
        Returns the created items as [{'id', 'host'}].
        """
        self._require("collections", collection_id, "C")
        name = self.conn.execute("SELECT name FROM collections WHERE id = ?",
                                 (collection_id,)).fetchone()["name"]
        covered = {r["host_id"] for r in self.conn.execute(
            "SELECT DISTINCT eh.host_id FROM evidence_hosts eh "
            "JOIN evidence e ON e.id = eh.evidence_id "
            "WHERE e.collection_id = ?", (collection_id,))}
        created = []
        for r in self.conn.execute(
                "SELECT h.id, h.name FROM collection_hosts ch "
                "JOIN hosts h ON h.id = ch.host_id AND h.deleted_at = '' "
                "WHERE ch.collection_id = ? ORDER BY h.name COLLATE NOCASE",
                (collection_id,)):
            if r["id"] in covered:
                continue
            eid = self.add_evidence(f"{name} — {r['name']}", kind=kind,
                                    collection_id=collection_id,
                                    host_ids=[r["id"]])
            created.append({"id": eid, "host": r["name"]})
        return created

    def resolve_collection(self, ref: str) -> int:
        token = ref[1:] if ref[:1].upper() == "C" and ref[1:].isdigit() else ref
        if token.isdigit():
            row = self.conn.execute("SELECT id FROM collections WHERE id = ?",
                                    (int(token),)).fetchone()
            if row:
                return row["id"]
        rows = self.conn.execute(
            "SELECT id FROM collections WHERE name LIKE ?", (f"%{ref}%",)).fetchall()
        if len(rows) == 1:
            return rows[0]["id"]
        if not rows:
            raise CaseError(f"no collection matches {ref!r}")
        raise CaseError(f"collection ref {ref!r} is ambiguous")

    # -- host links (evidence / actions / findings all reference the registry) --

    # join table -> foreign-key column naming the owner row
    _HOST_LINK = {"finding_hosts": "finding_id",
                  "evidence_hosts": "evidence_id",
                  "action_hosts": "action_id",
                  "collection_hosts": "collection_id"}

    def _set_host_links(self, table: str, owner_col: str, owner_table: str,
                        owner_id: int, host_ids: list[int], prefix: str,
                        audit: bool = True) -> None:
        self._require(owner_table, owner_id, prefix)
        for hid in host_ids:
            self._require("hosts", hid, "H")
        old_ids = sorted(r[0] for r in self.conn.execute(
            f"SELECT host_id FROM {table} WHERE {owner_col} = ?", (owner_id,)))
        with self.conn:
            self.conn.execute(f"DELETE FROM {table} WHERE {owner_col} = ?",
                              (owner_id,))
            self.conn.executemany(
                f"INSERT OR IGNORE INTO {table}({owner_col}, host_id) VALUES (?, ?)",
                [(owner_id, hid) for hid in host_ids])
            new_ids = sorted(set(host_ids))
            if audit and new_ids != old_ids:
                # audited against the OWNER row (host attribution is evidence)
                self._audit(owner_table, owner_id, "update",
                            {"host_ids": {"from": old_ids, "to": new_ids}})

    def set_finding_hosts(self, finding_id: int, host_ids: list[int],
                          audit: bool = True) -> None:
        self._set_host_links("finding_hosts", "finding_id", "findings",
                             finding_id, host_ids, "F", audit=audit)

    def set_evidence_hosts(self, evidence_id: int, host_ids: list[int],
                           audit: bool = True) -> None:
        old = set(self.evidence_host_ids(evidence_id))
        self._set_host_links("evidence_hosts", "evidence_id", "evidence",
                             evidence_id, host_ids, "E", audit=audit)
        if old == set(host_ids):
            return
        # steps derive their hosts from the evidence they examine: any step
        # still tracking the old set follows; a step with a different set
        # (explicit override) is left alone
        for r in self.conn.execute(
                "SELECT id FROM actions WHERE evidence_id = ?", (evidence_id,)):
            if set(self.action_host_ids(r["id"])) == old:
                self._set_host_links("action_hosts", "action_id", "actions",
                                     r["id"], host_ids, "A")

    def set_action_hosts(self, action_id: int, host_ids: list[int],
                         audit: bool = True) -> None:
        self._set_host_links("action_hosts", "action_id", "actions",
                             action_id, host_ids, "A", audit=audit)

    def set_collection_hosts(self, collection_id: int, host_ids: list[int],
                             audit: bool = True) -> None:
        old = set(self.collection_host_ids(collection_id))
        self._set_host_links("collection_hosts", "collection_id", "collections",
                             collection_id, host_ids, "C", audit=audit)
        if old == set(host_ids):
            return
        # evidence in the collection follows the collection's host set — but
        # only items still tracking the old set, so per-host expansion items
        # (deliberate subsets) keep their single host
        for r in self.conn.execute(
                "SELECT id FROM evidence WHERE collection_id = ?",
                (collection_id,)):
            if set(self.evidence_host_ids(r["id"])) == old:
                self.set_evidence_hosts(r["id"], list(host_ids))

    def finding_host_ids(self, finding_id: int) -> list[int]:
        return [r["host_id"] for r in self.conn.execute(
            "SELECT host_id FROM finding_hosts WHERE finding_id = ? ORDER BY host_id",
            (finding_id,))]

    def evidence_host_ids(self, evidence_id: int) -> list[int]:
        return [r["host_id"] for r in self.conn.execute(
            "SELECT host_id FROM evidence_hosts WHERE evidence_id = ? "
            "ORDER BY host_id", (evidence_id,))]

    def action_host_ids(self, action_id: int) -> list[int]:
        return [r["host_id"] for r in self.conn.execute(
            "SELECT host_id FROM action_hosts WHERE action_id = ? "
            "ORDER BY host_id", (action_id,))]

    def _host_links(self, table: str) -> dict[int, list[dict]]:
        """{owner_id: [{id,name}]} for a host-link table; skips deleted hosts."""
        owner_col = self._HOST_LINK[table]
        index: dict[int, list[dict]] = {}
        for r in self.conn.execute(
                f"SELECT j.{owner_col} AS oid, h.id AS id, h.name AS name "
                f"FROM {table} j JOIN hosts h ON h.id = j.host_id "
                "WHERE h.deleted_at = '' ORDER BY h.name COLLATE NOCASE"):
            index.setdefault(r["oid"], []).append({"id": r["id"], "name": r["name"]})
        return index

    def _account_links(self) -> dict[int, list[dict]]:
        """{finding_id: [{id,name,status}]}; skips deleted accounts."""
        index: dict[int, list[dict]] = {}
        for r in self.conn.execute(
                "SELECT fa.finding_id AS oid, a.id AS id, a.name AS name,"
                " a.status AS status "
                "FROM finding_accounts fa JOIN accounts a ON a.id = fa.account_id "
                "WHERE a.deleted_at = '' ORDER BY a.name COLLATE NOCASE"):
            index.setdefault(r["oid"], []).append(
                {"id": r["id"], "name": r["name"], "status": r["status"]})
        return index

    def _enrich(self, findings) -> list:
        """Attach affected_hosts + stack + a derived host string to findings,
        and, for leads, their triage worklist so it can be shown inline."""
        findings = list(findings)
        index = self._host_links("finding_hosts")
        acct_index = self._account_links()
        items_index = self._lead_items_index()
        for f in findings:
            hosts = index.get(f["id"], [])
            f["affected_hosts"] = hosts
            f["accounts"] = acct_index.get(f["id"], [])
            f["stack"] = len(hosts)
            # category/CSV views read f["host"]; derive it from the links so the
            # registry is the single source of truth (fall back to legacy text).
            if hosts:
                f["host"] = ", ".join(h["name"] for h in hosts)
            # leads always carry their worklist; any OTHER finding carries its
            # follow-up checklist when it has one (same table, same shape)
            items = items_index.get(f["id"])
            if f.get("ftype") == "lead" or items:
                items = items or []
                f["items"] = items
                f["item_total"] = len(items)
                f["item_resolved"] = sum(1 for it in items if it["status"] != "open")
        return findings

    def stack_findings(self) -> list[dict]:
        """Cross-host findings, rarest first (least-frequency-of-occurrence).

        Only live hosts count, so a finding whose hosts were all soft-deleted
        drops out and stack counts match the affected-host sets.
        """
        rows = self.conn.execute("""
            SELECT f.*, COUNT(fh.host_id) AS stack
            FROM findings f
            JOIN finding_hosts fh ON fh.finding_id = f.id
            JOIN hosts h ON h.id = fh.host_id AND h.deleted_at = ''
            WHERE f.ftype != 'lead'
            GROUP BY f.id ORDER BY stack ASC, f.id ASC""")
        return self._enrich([self._finding_dict(r) for r in rows])

    def artifact_stacks(self) -> list[dict]:
        """Host-based indicators grouped by artifact name, regardless of path.

        The same planted DLL name across several app directories/hosts collapses
        into one group that still lists every distinct full path and host. Names
        are matched case-insensitively (Windows filenames); most-spread first so
        the widely-deployed artifacts rise to the top.
        """
        rows = self._enrich([self._finding_dict(r) for r in self.conn.execute(
            "SELECT * FROM findings WHERE ftype = 'hostindicator' ORDER BY id")])
        groups: dict[str, dict] = {}
        for f in rows:
            name = types.artifact_name(f)
            g = groups.get(name.lower())
            if g is None:
                g = groups[name.lower()] = {
                    "name": name, "findings": [], "paths": [], "hosts": [],
                    "artifact_types": [], "_host_ids": set(),
                }
            g["findings"].append(f)
            path = (f.get("attrs") or {}).get("path", "").strip()
            if path and path not in g["paths"]:
                g["paths"].append(path)
            atype = (f.get("attrs") or {}).get("artifact_type", "").strip()
            if atype and atype not in g["artifact_types"]:
                g["artifact_types"].append(atype)
            for h in f.get("affected_hosts", []):
                if h["id"] not in g["_host_ids"]:
                    g["_host_ids"].add(h["id"])
                    g["hosts"].append(h)
        out = []
        for g in groups.values():
            g.pop("_host_ids")
            g["count"] = len(g["findings"])
            g["host_count"] = len(g["hosts"])
            out.append(g)
        out.sort(key=lambda g: (-g["count"], -g["host_count"], g["name"].lower()))
        return out

    # -- leads (triage worklists) ------------------------------------------

    LEAD_ITEM_STATUSES = ("open", "triaged", "dismissed")
    LEAD_ITEM_EDITABLE = {"label", "status", "finding_id", "note"}

    @staticmethod
    def _check_lead_status(status: str) -> str:
        status = (status or "").strip().lower()
        if status not in Case.LEAD_ITEM_STATUSES:
            raise CaseError(f"bad lead item status {status!r} "
                            f"(one of: {', '.join(Case.LEAD_ITEM_STATUSES)})")
        return status

    def leads(self) -> list[dict]:
        """Lead findings (triage worklists); _enrich attaches items + counts."""
        return self._enrich([self._finding_dict(r) for r in self.conn.execute(
            "SELECT * FROM findings WHERE ftype = 'lead' ORDER BY id")])

    def lead_items(self, lead_id: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM lead_items WHERE lead_id = ? AND deleted_at = '' "
            "ORDER BY id", (lead_id,))
        out = []
        for r in rows:
            d = dict(r)
            if d.get("finding_id"):
                fr = self.conn.execute(
                    "SELECT id, title, ftype, starred FROM findings WHERE id = ?",
                    (d["finding_id"],)).fetchone()
                d["finding"] = dict(fr) if fr else None
            else:
                d["finding"] = None
            out.append(d)
        return out

    def _lead_items_index(self) -> dict[int, list[dict]]:
        """{owner finding id: [items]} across the whole case, same item shape
        as lead_items() (resolving finding attached where linked)."""
        index: dict[int, list[dict]] = {}
        for r in self.conn.execute(
                "SELECT li.*, rf.id AS rf_id, rf.title AS rf_title,"
                " rf.ftype AS rf_ftype, rf.starred AS rf_starred "
                "FROM lead_items li "
                "LEFT JOIN findings rf ON rf.id = li.finding_id "
                "WHERE li.deleted_at = '' ORDER BY li.id"):
            d = {k: r[k] for k in r.keys()
                 if not k.startswith("rf_")}
            d["finding"] = ({"id": r["rf_id"], "title": r["rf_title"],
                             "ftype": r["rf_ftype"], "starred": r["rf_starred"]}
                            if r["rf_id"] is not None else None)
            index.setdefault(d["lead_id"], []).append(d)
        return index

    def followups(self) -> list[dict]:
        """Open checklist items on NON-lead findings — the case-wide
        'what still needs following up' queue (leads have their own views)."""
        return [dict(r) for r in self.conn.execute(
            "SELECT li.*, f.title AS owner_title, f.ftype AS owner_ftype "
            "FROM lead_items li JOIN findings f ON f.id = li.lead_id "
            "WHERE li.deleted_at = '' AND li.status = 'open' "
            "AND f.ftype != 'lead' ORDER BY li.id")]

    def add_lead_item(self, lead_id: int, label: str, status: str = "open",
                      finding_id: int | None = None, note: str = "") -> int:
        if not str(label).strip():
            raise CaseError("lead item label must not be empty")
        self._require("findings", lead_id, "F")
        status = self._check_lead_status(status)
        if finding_id is not None:
            self._require("findings", finding_id, "F")
            if status == "open":
                status = "triaged"   # linking a finding resolves the item
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO lead_items(lead_id, label, status, finding_id, note,"
                " created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (lead_id, label.strip(), status, finding_id, note, _now()))
        return cur.lastrowid

    def update_lead_item(self, item_id: int, **fields) -> None:
        if "status" in fields:
            fields["status"] = self._check_lead_status(fields["status"])
        if fields.get("finding_id") is not None:
            self._require("findings", fields["finding_id"], "F")
            # linking a finding resolves an otherwise-open item
            if "status" not in fields:
                cur = self.conn.execute(
                    "SELECT status FROM lead_items WHERE id = ?", (item_id,)
                ).fetchone()
                if cur and cur["status"] == "open":
                    fields["status"] = "triaged"
        self._update("lead_items", self.LEAD_ITEM_EDITABLE, item_id, fields,
                     "lead item ")

    def soft_delete_lead_item(self, item_id: int) -> None:
        self._require("lead_items", item_id, "lead item ")
        with self.conn:
            self.conn.execute("UPDATE lead_items SET deleted_at = ? WHERE id = ?",
                              (_now(), item_id))
            self._audit("lead_items", item_id, "soft_delete", {})

    # -- attachments --------------------------------------------------------

    _ATTACH_META = ("id, owner_type, owner_id, role, filename, mime, caption, "
                    "sha256, size, created_at")

    def add_attachment(self, owner_type: str, owner_id: int, data: bytes,
                       filename: str = "", mime: str = "application/octet-stream",
                       role: str = "exhibit", caption: str = "") -> int:
        if owner_type not in OWNER_TYPES:
            raise CaseError(f"bad owner type {owner_type!r}")
        if not data:
            raise CaseError("attachment has no data")
        if len(data) > ATTACHMENT_CAP:
            raise CaseError(
                f"attachment is {len(data) // 1024 // 1024} MB — over the "
                f"{ATTACHMENT_CAP // 1024 // 1024} MB limit")
        self._require(_OWNER_TABLE[owner_type], owner_id,
                      owner_type[0].upper())
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO attachments(owner_type, owner_id, role, filename,"
                " mime, caption, sha256, size, bytes, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (owner_type, owner_id, role, filename, mime, caption,
                 sha256_bytes(data), len(data), data, _now()))
        return cur.lastrowid

    def attachments(self, owner_type: str, owner_id: int) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            f"SELECT {self._ATTACH_META} FROM attachments "
            "WHERE owner_type = ? AND owner_id = ? AND deleted_at = '' ORDER BY id",
            (owner_type, owner_id))]

    def _attachment_index(self) -> dict[tuple[str, int], list[dict]]:
        """Live attachment metadata grouped by (owner_type, owner_id)."""
        index: dict[tuple[str, int], list[dict]] = {}
        for r in self.conn.execute(
                f"SELECT {self._ATTACH_META} FROM attachments "
                "WHERE deleted_at = '' ORDER BY id"):
            index.setdefault((r["owner_type"], r["owner_id"]), []).append(dict(r))
        return index

    def all_attachments(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            f"SELECT {self._ATTACH_META} FROM attachments "
            "WHERE deleted_at = '' ORDER BY id")]

    def attachment_blob(self, attach_id: int) -> tuple[bytes, str, str]:
        row = self.conn.execute(
            "SELECT bytes, mime, filename FROM attachments "
            "WHERE id = ? AND deleted_at = ''", (attach_id,)).fetchone()
        if not row:
            raise CaseError(f"attachment {attach_id} does not exist")
        return row["bytes"], row["mime"], row["filename"]

    def delete_attachment(self, attach_id: int) -> None:
        """Soft-delete: the bytes are retained, just hidden. vera never purges."""
        self._require("attachments", attach_id, "attachment ")
        with self.conn:
            self.conn.execute("UPDATE attachments SET deleted_at = ? WHERE id = ?",
                              (_now(), attach_id))
            self._audit("attachments", attach_id, "soft_delete", {})

    # -- audit trail --------------------------------------------------------

    def audit(self, ref: str | None = None, limit: int = 200) -> list[dict]:
        """Read the append-only edit history, newest first. `ref` filters to
        one row (A4 / F2 / E1 / H3 / C1). There is deliberately NO write API
        beyond _audit and nothing that updates or deletes log rows."""
        q = ("SELECT id, at, table_name, row_id, op, changes FROM audit_log")
        params: tuple = ()
        if ref:
            kind = ref[:1].upper()
            table = AUDIT_TABLES.get(kind)
            if not table or not ref[1:].isdigit():
                known = ", ".join(f"{k}#" for k in AUDIT_TABLES)
                raise CaseError(f"audit expects a ref like {known}, got {ref!r}")
            q += " WHERE table_name = ? AND row_id = ?"
            params = (table, int(ref[1:]))
        q += " ORDER BY id DESC LIMIT ?"
        out = []
        for r in self.conn.execute(q, (*params, limit)):
            d = dict(r)
            try:
                d["changes"] = json.loads(d["changes"])
            except json.JSONDecodeError:
                d["changes"] = {}
            out.append(d)
        return out


AUDIT_TABLES = {"A": "actions", "F": "findings", "E": "evidence",
                "H": "hosts", "C": "collections"}


def resolve_ref(ref: str) -> tuple[str, int]:
    """Parse 'A4' / 'F2' / 'E1' into (kind, id)."""
    kind = ref[:1].upper()
    if kind in ("A", "F", "E") and ref[1:].isdigit():
        return kind, int(ref[1:])
    raise CaseError(f"bad reference {ref!r} (expected A<n>, F<n>, or E<n>)")

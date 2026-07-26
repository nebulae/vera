"""User accounts, sessions and password handling for the web server.

Users are global (cross-case), so they live in their own SQLite DB next to
the case files — never inside a portable .vera file. Everything here is
stdlib-only: scrypt for password hashing (memory-hard, via hashlib/OpenSSL),
`secrets` for tokens, `hmac.compare_digest` for constant-time comparison.

This is WEB-TIER access control: anyone with filesystem access to the case
files (or the CLI on the server box) is outside its scope by design.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import re
import secrets
import sqlite3

ROLES = ("admin", "investigator", "viewer")

# scrypt parameters, recorded per-hash so they can be raised later without
# invalidating existing hashes (verify reads the stored parameters)
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
_SCRYPT_MAXMEM = 64 * 1024 * 1024
_DKLEN = 32

SESSION_IDLE_TTL = 24 * 3600          # session dies after a day unused …
SESSION_MAX_TTL = 14 * 24 * 3600      # … and unconditionally after two weeks
RESET_TOKEN_TTL = 3600                # admin-issued reset codes: one hour

# failed-login backoff: after this many misses, lock briefly (doubling)
LOCK_THRESHOLD = 5
LOCK_BASE_SECONDS = 30
LOCK_MAX_SECONDS = 600

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,32}$")

# small embedded blocklist — the point is catching the reflexive choices,
# not replacing a breach corpus
COMMON_PASSWORDS = {
    "password", "password1", "password123", "passw0rd", "p@ssw0rd",
    "p@ssword123", "letmein", "welcome1", "welcome123", "qwerty123",
    "qwertyuiop", "1234567890", "123456789012", "iloveyou123",
    "admin123", "administrator", "changeme", "changeme123", "default1",
    "summer2023", "summer2024", "summer2025", "summer2026",
    "winter2023", "winter2024", "winter2025", "winter2026",
    "spring2024", "spring2025", "spring2026", "autumn2025",
    "monkey123456", "dragon123456", "football1234", "baseball1234",
    "sunshine1234", "princess1234", "trustno1", "letmein12345",
    "password2023", "password2024", "password2025", "password2026",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL,
    display_name  TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL DEFAULT 'viewer',
    pw            TEXT NOT NULL DEFAULT '',
    disabled      INTEGER NOT NULL DEFAULT 0,
    must_change   INTEGER NOT NULL DEFAULT 0,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_name
    ON users(username COLLATE NOCASE);
CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reset_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    used_at    TEXT NOT NULL DEFAULT ''
);
"""


class AuthError(Exception):
    """User-facing authentication/authorization error."""


def _now_dt() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _ts(dt: _dt.datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _now() -> str:
    return _ts(_now_dt())


def hash_password(password: str) -> str:
    """scrypt$N$r$p$salt_hex$hash_hex — parameters travel with the hash."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N,
                            r=SCRYPT_R, p=SCRYPT_P, dklen=_DKLEN,
                            maxmem=_SCRYPT_MAXMEM)
    return (f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}"
            f"${salt.hex()}${digest.hex()}")


def verify_password(stored: str, password: str) -> bool:
    try:
        algo, n, r, p, salt_hex, hash_hex = stored.split("$")
        if algo != "scrypt":
            return False
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                                n=int(n), r=int(r), p=int(p),
                                dklen=len(bytes.fromhex(hash_hex)),
                                maxmem=_SCRYPT_MAXMEM)
        return hmac.compare_digest(digest, bytes.fromhex(hash_hex))
    except (ValueError, TypeError):
        return False


def password_problems(password: str, username: str = "") -> list[str]:
    """Empty list = acceptable. 12+ chars with 3 of 4 character classes, or
    16+ chars of anything (passphrase-friendly); never the username or a
    blocklisted favorite."""
    problems = []
    if len(password) < 12:
        problems.append("use at least 12 characters (16+ if you want to skip "
                        "the character-class rules)")
    elif len(password) < 16:
        classes = sum(bool(re.search(pat, password)) for pat in
                      (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
        if classes < 3:
            problems.append("12–15 character passwords need 3 of: lowercase, "
                            "uppercase, digit, symbol — or just make it 16+")
    if username and len(username) >= 3 and username.lower() in password.lower():
        problems.append("must not contain your username")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("that password is on the common-passwords blocklist")
    return problems


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class UsersDB:
    """All user/session/reset-token storage and logic. Open per request,
    like Case — sqlite connections aren't shared across threads."""

    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA busy_timeout = 5000")
        self.conn.execute("PRAGMA journal_mode = WAL")
        with self.conn:
            self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "UsersDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- users ---------------------------------------------------------------

    def needs_bootstrap(self) -> bool:
        return self.conn.execute(
            "SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 0

    def create_user(self, username: str, role: str, password: str | None = None,
                    display_name: str = "", must_change: bool = False) -> int:
        username = username.strip()
        if not USERNAME_RE.fullmatch(username):
            raise AuthError("username must be 2–32 chars of letters, digits, "
                            "dot, dash or underscore")
        if role not in ROLES:
            raise AuthError(f"role must be one of: {', '.join(ROLES)}")
        if self._find(username) is not None:
            raise AuthError(f"user {username!r} already exists")
        pw = ""
        if password is not None:
            problems = password_problems(password, username)
            if problems:
                raise AuthError("weak password: " + "; ".join(problems))
            pw = hash_password(password)
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO users(username, display_name, role, pw,"
                " must_change, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (username, display_name.strip(), role, pw,
                 int(must_change), _now()))
        return cur.lastrowid

    def _enabled_admin_count(self) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) AS n FROM users "
            "WHERE role = 'admin' AND disabled = 0").fetchone()["n"]

    def _find(self, username: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username.strip(),)).fetchone()

    def get_user(self, user_id: int) -> dict:
        row = self.conn.execute("SELECT * FROM users WHERE id = ?",
                                (user_id,)).fetchone()
        if row is None:
            raise AuthError(f"no user {user_id}")
        return self._public(row)

    @staticmethod
    def _public(row: sqlite3.Row) -> dict:
        return {"id": row["id"], "username": row["username"],
                "display_name": row["display_name"], "role": row["role"],
                "disabled": bool(row["disabled"]),
                "must_change_password": bool(row["must_change"]),
                "created_at": row["created_at"]}

    def users(self) -> list[dict]:
        return [self._public(r) for r in self.conn.execute(
            "SELECT * FROM users ORDER BY username COLLATE NOCASE")]

    USER_EDITABLE = {"display_name", "role", "disabled"}

    def update_user(self, user_id: int, **fields) -> None:
        bad = set(fields) - self.USER_EDITABLE
        if bad:
            raise AuthError(
                f"cannot edit user field(s): {', '.join(sorted(bad))}")
        if "role" in fields and fields["role"] not in ROLES:
            raise AuthError(f"role must be one of: {', '.join(ROLES)}")
        if "disabled" in fields:
            fields["disabled"] = int(bool(fields["disabled"]))
        if not fields:
            raise AuthError("nothing to update")
        current = self.get_user(user_id)  # existence check
        # never strand the system with no way in: block demoting/disabling the
        # last enabled admin
        losing_admin = (current["role"] == "admin"
                        and (fields.get("role", "admin") != "admin"
                             or fields.get("disabled")))
        if losing_admin and self._enabled_admin_count() <= 1:
            raise AuthError("this is the only active admin — promote another "
                            "admin before changing this one")
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self.conn:
            self.conn.execute(f"UPDATE users SET {cols} WHERE id = ?",
                              (*fields.values(), user_id))
            if fields.get("disabled"):
                self.conn.execute("DELETE FROM sessions WHERE user_id = ?",
                                  (user_id,))

    # -- login / lockout -----------------------------------------------------

    def authenticate(self, username: str, password: str) -> dict:
        row = self._find(username)
        if row is None or row["disabled"]:
            # burn comparable time so missing users aren't distinguishable
            verify_password(hash_password("x" * 16), password)
            raise AuthError("bad username or password")
        if row["locked_until"] and _now() < row["locked_until"]:
            raise AuthError("too many failed attempts — try again shortly")
        if not row["pw"] or not verify_password(row["pw"], password):
            self._record_failure(row)
            raise AuthError("bad username or password")
        with self.conn:
            self.conn.execute(
                "UPDATE users SET failed_logins = 0, locked_until = '' "
                "WHERE id = ?", (row["id"],))
        return self._public(row)

    def _record_failure(self, row: sqlite3.Row) -> None:
        failed = row["failed_logins"] + 1
        locked_until = ""
        if failed >= LOCK_THRESHOLD:
            lock = min(LOCK_MAX_SECONDS,
                       LOCK_BASE_SECONDS * 2 ** (failed - LOCK_THRESHOLD))
            locked_until = _ts(_now_dt() + _dt.timedelta(seconds=lock))
        with self.conn:
            self.conn.execute(
                "UPDATE users SET failed_logins = ?, locked_until = ? "
                "WHERE id = ?", (failed, locked_until, row["id"]))

    # -- sessions ------------------------------------------------------------

    def create_session(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        now = _now_dt()
        with self.conn:
            self.conn.execute(
                "INSERT INTO sessions(token_hash, user_id, created_at,"
                " expires_at, last_seen) VALUES (?, ?, ?, ?, ?)",
                (_token_hash(token), user_id, _ts(now),
                 _ts(now + _dt.timedelta(seconds=SESSION_IDLE_TTL)), _ts(now)))
        return token

    def session_user(self, token: str) -> dict | None:
        """The session's user (refreshing the sliding expiry), or None."""
        if not token:
            return None
        row = self.conn.execute(
            "SELECT s.*, u.disabled FROM sessions s "
            "JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
            (_token_hash(token),)).fetchone()
        if row is None or row["disabled"]:
            return None
        now = _now_dt()
        if _ts(now) > row["expires_at"]:
            with self.conn:
                self.conn.execute("DELETE FROM sessions WHERE id = ?",
                                  (row["id"],))
            return None
        hard_stop = (_dt.datetime.strptime(row["created_at"],
                                           "%Y-%m-%d %H:%M:%S")
                     .replace(tzinfo=_dt.timezone.utc)
                     + _dt.timedelta(seconds=SESSION_MAX_TTL))
        expires = min(now + _dt.timedelta(seconds=SESSION_IDLE_TTL), hard_stop)
        with self.conn:
            self.conn.execute(
                "UPDATE sessions SET last_seen = ?, expires_at = ? "
                "WHERE id = ?", (_ts(now), _ts(expires), row["id"]))
        return self.get_user(row["user_id"])

    def delete_session(self, token: str) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM sessions WHERE token_hash = ?",
                              (_token_hash(token),))

    # -- passwords -----------------------------------------------------------

    def set_password(self, user_id: int, new_password: str) -> None:
        user = self.get_user(user_id)
        problems = password_problems(new_password, user["username"])
        if problems:
            raise AuthError("weak password: " + "; ".join(problems))
        with self.conn:
            self.conn.execute(
                "UPDATE users SET pw = ?, must_change = 0, failed_logins = 0,"
                " locked_until = '' WHERE id = ?",
                (hash_password(new_password), user_id))
            # a changed password invalidates every existing session
            self.conn.execute("DELETE FROM sessions WHERE user_id = ?",
                              (user_id,))

    def change_password(self, user_id: int, current: str, new: str) -> None:
        row = self.conn.execute("SELECT * FROM users WHERE id = ?",
                                (user_id,)).fetchone()
        if row is None or not verify_password(row["pw"], current):
            raise AuthError("current password is wrong")
        self.set_password(user_id, new)

    # -- reset tokens (admin-issued, single-use) -----------------------------

    def create_reset_token(self, user_id: int) -> str:
        self.get_user(user_id)  # existence check
        token = secrets.token_urlsafe(24)
        with self.conn:
            self.conn.execute(
                "INSERT INTO reset_tokens(token_hash, user_id, expires_at)"
                " VALUES (?, ?, ?)",
                (_token_hash(token), user_id,
                 _ts(_now_dt() + _dt.timedelta(seconds=RESET_TOKEN_TTL))))
        return token

    def consume_reset_token(self, token: str) -> int:
        """Validate + burn a reset token, returning the user id."""
        row = self.conn.execute(
            "SELECT * FROM reset_tokens WHERE token_hash = ?",
            (_token_hash(token or ""),)).fetchone()
        if row is None or row["used_at"] or _now() > row["expires_at"]:
            raise AuthError("invalid or expired reset code")
        with self.conn:
            self.conn.execute(
                "UPDATE reset_tokens SET used_at = ? WHERE id = ?",
                (_now(), row["id"]))
        return row["user_id"]

    def reset_password(self, token: str, new_password: str) -> int:
        """Set a password via a reset token. The policy is checked BEFORE the
        token is burned, so a too-weak first attempt doesn't waste the code."""
        row = self.conn.execute(
            "SELECT * FROM reset_tokens WHERE token_hash = ?",
            (_token_hash(token or ""),)).fetchone()
        if row is None or row["used_at"] or _now() > row["expires_at"]:
            raise AuthError("invalid or expired reset code")
        user = self.get_user(row["user_id"])
        problems = password_problems(new_password, user["username"])
        if problems:
            raise AuthError("weak password: " + "; ".join(problems))
        self.consume_reset_token(token)
        self.set_password(row["user_id"], new_password)
        return row["user_id"]

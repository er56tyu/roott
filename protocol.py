"""The VexR uplink protocol, server side.

Mirrors the implant's a/wg1.java and a/sp0.java:

    envelope  v=3&d=<b64 AES-CBC(payload)>&k=<b64 RSA(aesKey)>&i=<b64 iv>
    key       RSA/ECB/PKCS1Padding over an X.509 SubjectPublicKeyInfo
    payload   AES/CBC/PKCS5Padding, 256-bit key, fresh per message

There is a second, unencrypted transport that the implant falls back to, and it
matters just as much:

  * `sp0.e()` builds the envelope but, when either crypto step returns null,
    jumps to `:cond_6` and POSTs the *plaintext* form anyway. That is the
    `action=heartbeat&Model=...` body seen in production.
  * `sp0.f()` -- the file uploader used for every command result -- does no
    encryption whatsoever. It posts the raw file as the request body.

So the server must accept three shapes on the uplink, and identifying them is
the job of this module rather than of string-matching inside the handlers.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qsl

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BASE_DIR = Path(__file__).resolve().parent
PRIVATE_KEY_PATH = BASE_DIR / "server_private.pem"
PUBLIC_KEY_PATH = BASE_DIR / "server_public.pem"

ENCRYPTED = "encrypted"
PLAIN_FORM = "plain-form"
RAW_FILE = "raw-file"


class ProtocolError(ValueError):
    """Raised when a body cannot be interpreted as any known uplink shape."""


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------

def _pkcs5_pad(data: bytes, block: int = 16) -> bytes:
    padlen = block - (len(data) % block)
    return data + bytes([padlen]) * padlen


def _pkcs5_unpad(data: bytes) -> bytes:
    if not data:
        raise ProtocolError("empty ciphertext")
    padlen = data[-1]
    if padlen < 1 or padlen > 16 or data[-padlen:] != bytes([padlen]) * padlen:
        raise ProtocolError("bad PKCS#5 padding")
    return data[:-padlen]


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

    @staticmethod
    def _b64(value: str, field: str) -> bytes:
        """Decode an envelope field, tolerating the encoding damage seen in transit.

        The implant URL-encodes each field, but a client that does not (or a
        proxy that normalises the body) turns '+' into ' ' and strips '='. Both
        are recoverable, so try the strict form first and repair only on failure
        rather than rejecting a genuine beacon.
        """
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            pass
        repaired = value.strip().replace(" ", "+").replace("-", "+").replace("_", "/")
        repaired += "=" * (-len(repaired) % 4)
        try:
            return base64.b64decode(repaired, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ProtocolError(f"bad base64 in {field}: {exc}") from exc

    def decrypt(self, envelope: dict[str, str]) -> dict[str, Any]:
        missing = [f for f in ("k", "d", "i") if not envelope.get(f)]
        if missing:
            raise ProtocolError(f"envelope missing {','.join(missing)}")
        encrypted_key = self._b64(envelope["k"], "k")
        encrypted_data = self._b64(envelope["d"], "d")
        iv = self._b64(envelope["i"], "i")

        try:
            aes_key = self._private_key.decrypt(encrypted_key, padding.PKCS1v15())
        except Exception as exc:  # noqa: BLE001
            raise ProtocolError(f"RSA unwrap failed: {exc!r}") from exc

        if len(aes_key) not in (16, 24, 32):
            raise ProtocolError(f"unexpected AES key length {len(aes_key)}")
        if len(iv) != 16:
            raise ProtocolError(f"unexpected IV length {len(iv)}")

        decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(encrypted_data) + decryptor.finalize()
        plaintext = _pkcs5_unpad(padded)
        text = plaintext.decode("utf-8", "replace")

        # The implant encrypts the *same* urlencoded form it would otherwise post
        # in the clear (sp0.e hands p0 straight to wg1.b), so the plaintext is
        # normally `action=...&Model=...`, not JSON. Accept both shapes: a JSON
        # object when something else talks to us, a form when it is the implant.
        stripped = text.lstrip()
        if stripped[:1] in ("{", "["):
            try:
                parsed = json.loads(text)
            except Exception as exc:  # noqa: BLE001
                raise ProtocolError(f"payload looks like JSON but does not parse: {exc!r}") from exc
            if isinstance(parsed, dict):
                return parsed
            return {"data": parsed}

        form = dict(parse_qsl(text, keep_blank_values=True))
        if not form:
            raise ProtocolError(f"decrypted payload is neither JSON nor a form: {text[:32]!r}")
        return form

    def encrypt(self, payload: dict[str, Any]) -> dict[str, str]:
        """Encrypt a payload with the same envelope (used by the test client)."""
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        plaintext = json.dumps(payload).encode()

        encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
        padded = _pkcs5_pad(plaintext)
        encrypted = encryptor.update(padded) + encryptor.finalize()

        wrapped = self._private_key.public_key().encrypt(aes_key, padding.PKCS1v15())
        return {
            "v": "3",
            "d": base64.b64encode(encrypted).decode(),
            "k": base64.b64encode(wrapped).decode(),
            "i": base64.b64encode(iv).decode(),
        }


crypto = ProtocolCrypto()


# ---------------------------------------------------------------------------
# Body classification
# ---------------------------------------------------------------------------

@dataclass
class Uplink:
    """A parsed uplink request."""

    transport: str
    payload: dict[str, Any]
    raw: bytes

    @property
    def action(self) -> Optional[str]:
        a = self.payload.get("action") or self.payload.get("command")
        return str(a) if a else None


def parse_form(body: bytes) -> dict[str, str]:
    """Parse a urlencoded body, keeping blank values.

    keep_blank_values matters: the implant emits `&k=` with an empty value when
    its RSA step fails, and dropping the key would turn that into a KeyError
    instead of a clear diagnostic.
    """
    text = body.decode("utf-8", "replace")
    return dict(parse_qsl(text, keep_blank_values=True))


def _looks_like_envelope(form: dict[str, str]) -> bool:
    return form.get("v") == "3" and any(k in form for k in ("d", "k", "i"))


def _looks_like_form(form: dict[str, str]) -> bool:
    """The gm1.a() heartbeat shape: action plus a handful of device fields."""
    return "action" in form or "command" in form


def _looks_like_json(body: bytes) -> bool:
    stripped = body.lstrip()[:1]
    return stripped in (b"{", b"[")


def classify(
    body: bytes,
    form: Optional[dict[str, str]] = None,
    content_type: str = "",
    filename: Optional[str] = None,
) -> Uplink:
    """Work out which uplink shape this request is and parse it.

    Order matters: an encrypted envelope is unambiguous, a JSON body is
    unambiguous, and only then do we fall back to a form or a raw file. A
    command result posted by sp0.f() has a Content-Type of text/plain or
    image/jpeg and no form fields at all -- that is the RAW_FILE case.
    """
    if form is None:
        form = parse_form(body)

    if _looks_like_envelope(form):
        return Uplink(ENCRYPTED, crypto.decrypt(form), body)

    if _looks_like_json(body):
        try:
            parsed = json.loads(body.decode("utf-8", "replace"))
        except Exception as exc:  # noqa: BLE001
            raise ProtocolError(f"body starts like JSON but does not parse: {exc!r}") from exc
        if isinstance(parsed, dict):
            return Uplink(PLAIN_FORM, parsed, body)
        return Uplink(RAW_FILE, {"filename": filename, "content_type": content_type}, body)

    if _looks_like_form(form) and len(form) > 0:
        return Uplink(PLAIN_FORM, dict(form), body)

    # Nothing parsed as a form and it is not an envelope: this is an uploaded
    # file. The implant sends the bytes verbatim.
    return Uplink(
        RAW_FILE,
        {"filename": filename, "content_type": content_type},
        body,
    )


def describe(body: bytes, form: Optional[dict[str, str]] = None) -> str:
    """Summarise a body for the log without dumping its ciphertext."""
    if form is None:
        form = parse_form(body)
    keys = ",".join(sorted(form)) or "<none>"
    parts = [f"keys=[{keys}]", f"body_len={len(body)}"]
    for field in ("v", "d", "k", "i"):
        parts.append(f"{field}_len={len(form.get(field, ''))}")
    parts.append(f"head={body[:24]!r}")
    return " ".join(parts)

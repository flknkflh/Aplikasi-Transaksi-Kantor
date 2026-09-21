// Archive app controller: login, sending a file, the receipt, and checking a
// receipt. The central-admin screens live in admin.js.
//
// Trust notes (docs/adr/0004-archive-server-side-signing.md): the server signs on
// the sender's behalf after authenticating them; this page only ever shows what the
// server says and lets the user re-check it. The page is served under a strict CSP
// (no inline script/style/handlers), so all dynamic text goes through esc()/textContent.
import * as api from './api.js';
import { Sha256, sha256File } from './sha256.js';
import { Uploader, pendingUpload, clearPending, sameFile } from './upload.js';
import { initAdmin } from './admin.js';

const $ = (id) => document.getElementById(id);
const S = { me: null, server: null, file: null, uploader: null, receipt: null };

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// ---------- helpers ----------
function screen(id) {
  document.querySelectorAll('.screen').forEach((s) => s.classList.remove('active'));
  $(id).classList.add('active');
  document.body.classList.toggle('office', id === 'scArchive' || id === 'scItem' || id === 'scOffices');
  window.scrollTo(0, 0);
}
let toastT;
function toast(text, kind) {
  const t = $('toast');
  t.textContent = text; t.className = 'show ' + (kind || '');
  clearTimeout(toastT);
  toastT = setTimeout(() => { t.className = ''; }, kind === 'bad' ? 5500 : 2800);
}
async function withBtn(btn, fn) {
  btn.classList.add('loading'); btn.disabled = true;
  try { return await fn(); } finally { btn.classList.remove('loading'); btn.disabled = false; }
}
function friendly(e) {
  const m = (e && e.message) || String(e);
  if (/pending|menunggu persetujuan/i.test(m)) return 'Akun belum disetujui admin pusat.';
  if (/disabled|dinonaktifkan/i.test(m)) return 'Akun dinonaktifkan. Hubungi admin pusat.';
  if (/invalid credentials/i.test(m)) return 'Email atau kata sandi salah.';
  return m;
}
export const fmtBytes = (n) => {
  if (n < 1024) return n + ' B';
  const u = ['KiB', 'MiB', 'GiB', 'TiB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n >= 100 ? 0 : n >= 10 ? 1 : 2) + ' ' + u[i];
};
const fmtDate = (v) => { try { return new Date(v).toLocaleString('id-ID', { dateStyle: 'medium', timeStyle: 'medium' }); } catch { return String(v || ''); } };
const fmtDur = (s) => (s < 60 ? Math.ceil(s) + ' dtk' : s < 3600 ? Math.ceil(s / 60) + ' mnt' : (s / 3600).toFixed(1) + ' jam');
const row = (k, v, mono) => (v == null || v === '' ? '' : `<dt>${esc(k)}</dt><dd${mono ? ' class="mono"' : ''}>${esc(v)}</dd>`);
const CHECK = {
  manifest_hash: 'Isi manifest utuh (tidak diubah)', sender_signature: 'Tanda tangan pengirim (Ed25519 + ML-DSA-65)',
  event_chain: 'Rantai peristiwa utuh', event_signatures: 'Tanda tangan peristiwa server',
  receipt_signature: 'Tanda tangan bukti oleh server', stored_file: 'Berkas tersimpan cocok dengan yang dicatat',
};
const checksHTML = (v) => '<ul class="checks">' + v.checks.map((c) =>
  `<li class="${c.ok ? 'ok' : 'no'}"><span class="mk">${c.ok ? '✓' : '✕'}</span><span><b>${esc(CHECK[c.name] || c.name)}</b>${c.detail ? `<div class="faint">${esc(c.detail)}</div>` : ''}</span></li>`).join('') + '</ul>';
const ledgerBadge = (l) => {
  if (!l) return '';
  if (l.state === 'recorded') return '<span class="pill ok" title="Semua peristiwa tercatat di blockchain">Tercatat di blockchain</span>';
  if (l.state === 'failed') return '<span class="pill bad">Blockchain: gagal</span>';
  return l.enabled ? '<span class="pill warn" title="Menunggu dicatat">Antre ke blockchain</span>'
    : '<span class="pill neutral" title="Jaringan blockchain belum dihubungkan; peristiwa tersimpan dan bertanda tangan">Blockchain belum terhubung</span>';
};

function activatable(el, fn) {
  el.addEventListener('click', fn);
  el.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fn(); } });
}

// ---------- which server am I talking to ----------
async function showServer() {
  try {
    S.server = await api.serverInfo();
    $('sbName').textContent = S.server.server_name || 'Server';
    $('sbHost').textContent = S.server.host || location.host;
    $('sbSecure').hidden = !(S.server.https || location.protocol === 'https:');
    $('sbInsecure').hidden = !$('sbSecure').hidden;
    if (!S.server.office_enabled) $('fatal').hidden = false, $('fatal').textContent = 'Fitur arsip belum diaktifkan di server ini.';
  } catch {
    $('sbName').textContent = 'tidak dikenal'; $('sbHost').textContent = location.host;
    $('sbInsecure').hidden = false;
  }
}

// ---------- auth ----------
function tab(which) {
  for (const [id, pane] of [['tabLogin', 'paneLogin'], ['tabReg', 'paneReg'], ['tabCheck', 'paneCheck']]) {
    const on = id === 'tab' + which;
    $(id).classList.toggle('on', on);
    $(pane).hidden = !on;
  }
}
$('tabLogin').addEventListener('click', () => tab('Login'));
$('tabReg').addEventListener('click', () => tab('Reg'));
$('tabCheck').addEventListener('click', () => tab('Check'));
$('btnCheck').addEventListener('click', () => { const id = $('cid').value.trim(); if (id) openVerify(id); });

$('paneReg').addEventListener('submit', (ev) => {
  ev.preventDefault();
  withBtn($('btnReg'), async () => {
    $('regMsg').textContent = '';
    if (!$('remail').value.trim() || $('rpw').value.length < 8) { $('regMsg').textContent = 'Isi email dan kata sandi minimal 8 karakter.'; return; }
    try {
      const r = await api.register({ fullName: $('rname').value.trim(), org: $('rorg').value.trim(), email: $('remail').value.trim(), password: $('rpw').value });
      $('lemail').value = $('remail').value.trim(); $('rpw').value = '';
      tab('Login');
      toast(r.message || 'Akun dibuat, menunggu persetujuan admin pusat.', 'ok');
    } catch (e) { $('regMsg').textContent = friendly(e); }
  });
});

$('paneLogin').addEventListener('submit', (ev) => {
  ev.preventDefault();
  withBtn($('btnLogin'), async () => {
    $('loginMsg').textContent = '';
    try {
      await api.login($('lemail').value.trim(), $('lpw').value);
      $('lpw').value = '';
      await enter();
    } catch (e) { $('loginMsg').textContent = friendly(e); }
  });
});

async function enter() {
  try {
    S.me = (await api.get('/office/archive/config')).me;
  } catch (e) {
    if (e.status === 401) { logout(); return; }
    api.setToken('');
    throw new Error(e.status === 404 ? 'Fitur arsip belum diaktifkan di server ini.' : friendly(e));
  }
  $('acctEmail').textContent = S.me.email || S.me.name; $('acct').hidden = false;
  $('nav').hidden = false;
  $('navArchive').hidden = $('navOffices').hidden = !S.me.is_admin;
  $('navUpload').hidden = S.me.is_admin && !S.me.organization_id; // an admin who is not in an office has nothing to send
  if (S.me.is_admin) { admin.enter(); setNav('archive'); } else { showUpload(); }
}

function logout() {
  api.setToken('');
  if (S.uploader) S.uploader.pause();
  S.me = null; S.file = null; S.uploader = null;
  $('acct').hidden = true; $('nav').hidden = true; $('lpw').value = '';
  screen('scAuth'); tab('Login');
}
$('acctBtn').addEventListener('click', () => { $('acctMenu').hidden = !$('acctMenu').hidden; });
document.addEventListener('click', (e) => { if (!$('acct').contains(e.target)) $('acctMenu').hidden = true; });
$('acctMenu').addEventListener('click', (e) => { if (e.target.dataset.act === 'logout') { $('acctMenu').hidden = true; logout(); } });

function setNav(active) { document.querySelectorAll('#nav [data-nav]').forEach((b) => b.classList.toggle('on', b.dataset.nav === active)); }
$('nav').addEventListener('click', (e) => {
  const b = e.target.closest('[data-nav]'); if (!b) return;
  setNav(b.dataset.nav);
  if (b.dataset.nav === 'upload') showUpload();
  else if (b.dataset.nav === 'archive') admin.showArchive();
  else if (b.dataset.nav === 'offices') admin.showOffices();
  else openVerify('');
});

// ---------- sending a file ----------
function showUpload() {
  setNav('upload'); screen('scUpload');
  const me = S.me;
  $('upWho').textContent = 'Anda mengirim sebagai ' + me.name + (me.organization_name ? ' · ' + me.organization_name : '') + ' · ke server ' + (S.server ? S.server.server_name + ' (' + S.server.host + ')' : location.host);
  $('upNoOffice').hidden = !!me.organization_id;
  resetUploadForm();
  const p = pendingUpload(me.id);
  $('upPending').hidden = !p;
  if (p) $('upPending').textContent = 'Ada unggahan yang belum selesai: “' + p.name + '” (' + fmtBytes(p.size) + '). Pilih berkas yang sama untuk melanjutkan dari titik terakhir.';
}

function resetUploadForm() {
  S.file = null;
  $('upForm').hidden = false; $('upBusy').hidden = true; $('upMsg').textContent = '';
  $('upName').textContent = 'Pilih atau seret berkas apa saja…'; $('upName').classList.remove('fn');
  $('upMeta').textContent = ''; $('upGo').disabled = true; $('upDesc').value = '';
}

function chooseFile(f) {
  if (!f || !S.me || !S.me.organization_id) return;
  S.file = f;
  $('upName').textContent = f.name; $('upName').classList.add('fn');
  $('upMeta').textContent = fmtBytes(f.size) + ' · ' + (f.type || 'jenis tidak diketahui');
  $('upGo').disabled = false;
  const p = pendingUpload(S.me.id);
  if (p && sameFile(p, f)) $('upMeta').textContent += ' · unggahan sebelumnya akan dilanjutkan';
}
activatable($('upPick'), () => {
  const inp = document.createElement('input');
  inp.type = 'file';
  inp.addEventListener('change', () => chooseFile(inp.files && inp.files[0]));
  inp.click();
});
for (const ev of ['dragenter', 'dragover']) $('upPick').addEventListener(ev, (e) => { e.preventDefault(); $('upPick').classList.add('drag'); });
for (const ev of ['dragleave', 'drop']) $('upPick').addEventListener(ev, (e) => { e.preventDefault(); $('upPick').classList.remove('drag'); });
$('upPick').addEventListener('drop', (e) => chooseFile(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]));

$('upGo').addEventListener('click', () => startUpload());
async function startUpload() {
  const file = S.file; if (!file) return;
  $('upMsg').textContent = '';
  const p = pendingUpload(S.me.id);
  const up = new Uploader(file, {
    userId: S.me.id, description: $('upDesc').value.trim(), resume: p, onProgress: showProgress,
  });
  S.uploader = up;
  $('upForm').hidden = true; $('upBusy').hidden = false; $('upPause').textContent = 'Jeda'; $('upPause').disabled = false;
  $('upBusyName').textContent = file.name + ' (' + fmtBytes(file.size) + ')';
  showProgress({ sent: 0, total: file.size, phase: 'upload', speed: 0 });
  try {
    const receipt = await up.run();
    S.uploader = null;
    showReceipt(receipt);
  } catch (e) {
    if (e && e.name === 'AbortError') return; // paused: the buttons handle the rest
    S.uploader = null;
    $('upBusy').hidden = true; $('upForm').hidden = false;
    $('upMsg').textContent = friendly(e);
    $('upPending').hidden = !pendingUpload(S.me.id);
  }
}
function showProgress({ sent, total, phase, speed }) {
  const pct = total ? Math.min(100, (sent / total) * 100) : 100;
  $('upBar').style.width = pct.toFixed(1) + '%';
  const what = phase === 'hash' ? 'Memeriksa berkas' : phase === 'finish' ? 'Server menandatangani & mencatat…' : 'Mengunggah';
  let line = what + ' · ' + fmtBytes(sent) + ' / ' + fmtBytes(total) + ' (' + pct.toFixed(0) + '%)';
  if (phase === 'upload' && speed > 0) line += ' · ' + fmtBytes(speed) + '/dtk · sisa ' + fmtDur((total - sent) / speed);
  $('upStat').textContent = line;
}
$('upPause').addEventListener('click', async () => {
  const up = S.uploader; if (!up) return;
  if (!up.paused) { up.pause(); $('upPause').textContent = 'Lanjutkan'; $('upStat').textContent += ' — dijeda'; return; }
  // resume = a fresh run that asks the server where it left off
  $('upPause').textContent = 'Jeda';
  startUpload();
});
$('upCancel').addEventListener('click', async () => {
  if (S.uploader) await S.uploader.cancel();
  S.uploader = null; resetUploadForm(); $('upPending').hidden = true;
  toast('Unggahan dibatalkan.');
});
window.addEventListener('beforeunload', (e) => { if (S.uploader && !S.uploader.paused) { e.preventDefault(); e.returnValue = ''; } });

// ---------- receipt ----------
function showReceipt(resp) {
  S.receipt = resp;
  const b = resp.receipt.body, m = b.manifest, sig = b.sender_signature;
  $('rcBody').innerHTML = `
    <div class="verdict ok"><span class="mark">✓</span> Berkas terkirim, ditandatangani, dan diarsipkan</div>
    <dl class="kv">
      ${row('Nomor bukti', resp.receipt_id, true)}
      ${row('Waktu (jam server)', fmtDate(m.received_at))}
      ${row('Server tujuan', m.server_name)}
      ${row('Kantor', m.organization_name)}
      ${row('Pengirim', m.sender_name + ' (' + m.sender_email + ')')}
      ${row('Nama berkas', m.file_name)}
      ${row('Ukuran', fmtBytes(m.size_bytes) + ' (' + m.size_bytes.toLocaleString('id-ID') + ' byte)')}
      ${row('Jenis', m.media_type)}
      ${row('Keterangan', m.description)}
      ${row('Alamat IP terekam', m.client_ip)}
    </dl>
    <h3 class="h3">Sidik jari berkas</h3>
    <div class="hashbox"><b>SHA-256</b> ${esc(m.sha256)}</div>
    <div class="hashbox mt4"><b>SHA-512</b> ${esc(m.sha512)}</div>
    <h3 class="h3">Tanda tangan</h3>
    <dl class="kv">
      ${row('Algoritma', 'Hybrid Ed25519 + ML-DSA-65 (pasca-kuantum)')}
      ${row('Kunci pengirim', sig.classical_key_id + ' · ' + sig.pqc_key_id, true)}
      ${row('Hash manifest', b.manifest_hash, true)}
      ${row('Status blockchain', '')}
    </dl>
    <div>${ledgerBadge(resp.ledger)}</div>
    <p class="note">Tanda tangan dibuat oleh server atas nama Anda setelah Anda login, lalu dicatat berantai hash ke blockchain. Bukti ini juga ditandatangani server.</p>`;
  screen('scReceipt');
}
$('rcJson').addEventListener('click', () => {
  const r = S.receipt; if (!r) return;
  const blob = new Blob([JSON.stringify(r.receipt, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'bukti-' + r.receipt_id + '.json';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
});
$('rcPrint').addEventListener('click', () => window.print());
$('rcCopy').addEventListener('click', async () => {
  const url = location.origin + '/app/#r=' + S.receipt.receipt_id;
  try { await navigator.clipboard.writeText(url); toast('Tautan disalin.', 'ok'); } catch { toast(url); }
});
$('rcAgain').addEventListener('click', () => showUpload());

// ---------- checking a receipt (public) ----------
function openVerify(id) {
  screen('scVerify');
  if (S.me) setNav('verify');
  $('vid').value = id || ''; $('vResult').hidden = true;
  if (id) runVerify(id);
}
$('vGo').addEventListener('click', () => { const id = $('vid').value.trim(); if (id) runVerify(id); });
async function runVerify(id) {
  const out = $('vResult');
  out.hidden = false; out.innerHTML = '<div class="hint">Memeriksa…</div>';
  try {
    const r = await api.get('/api/v1/public/receipts/' + encodeURIComponent(id));
    const v = r.verification;
    out.innerHTML = `
      <div class="verdict ${v.ok ? 'ok' : 'bad'}"><span class="mark">${v.ok ? '✓' : '✕'}</span> ${v.ok ? 'Bukti ASLI' : 'Bukti TIDAK lolos pemeriksaan'}</div>
      <dl class="kv">
        ${row('Nomor bukti', r.receipt_id, true)}${row('Server', r.server_name)}${row('Kantor', r.organization_name)}
        ${row('Pengirim', r.sender_name)}${row('Berkas', r.file_name)}${row('Ukuran', fmtBytes(r.size_bytes))}
        ${row('Waktu (jam server)', fmtDate(r.received_at))}
      </dl>
      <div class="hashbox"><b>SHA-256</b> ${esc(r.sha256)}</div>
      ${checksHTML(v)}
      <div class="mt14">${ledgerBadge(r.ledger)}</div>
      <h3 class="h3">Cocokkan berkas yang Anda pegang</h3>
      <div class="filepick" id="vPick" role="button" tabindex="0"><span>📎</span><span id="vPickName">Pilih berkas untuk dibandingkan (tidak diunggah)…</span></div>
      <div class="hint" id="vHashStat"></div>`;
    activatable($('vPick'), () => {
      const inp = document.createElement('input'); inp.type = 'file';
      inp.addEventListener('change', async () => {
        const f = inp.files && inp.files[0]; if (!f) return;
        $('vPickName').textContent = f.name;
        const stat = $('vHashStat');
        try {
          const h = await sha256File(f, { onProgress: (n) => { stat.textContent = 'Menghitung… ' + Math.round((n / f.size) * 100) + '%'; } });
          stat.innerHTML = h === r.sha256
            ? '<div class="banner ok">✓ Berkas ini SAMA PERSIS dengan yang diarsipkan.</div>'
            : '<div class="banner bad">✕ Berkas ini BERBEDA dari yang diarsipkan (SHA-256 tidak sama).</div>';
        } catch (e) { stat.textContent = friendly(e); }
      });
      inp.click();
    });
  } catch (e) {
    out.innerHTML = '<div class="verdict bad"><span class="mark">✕</span> ' + esc(e.status === 404 ? 'Nomor bukti tidak ditemukan' : friendly(e)) + '</div>';
  }
}

// ---------- boot ----------
const admin = initAdmin({ $, esc, toast, screen, friendly, withBtn, fmtBytes, fmtDate, row, checksHTML, ledgerBadge, activatable, getMe: () => S.me, setNav });

(async function init() {
  $('verTag').textContent = 'arsip-v1';
  await showServer();
  const m = /^#r=(rcp_[a-z0-9]+)$/i.exec(location.hash);
  if (api.hasToken()) {
    try { await enter(); } catch (e) { $('fatal').hidden = false; $('fatal').textContent = friendly(e); }
  }
  if (m) openVerify(m[1]);
})();

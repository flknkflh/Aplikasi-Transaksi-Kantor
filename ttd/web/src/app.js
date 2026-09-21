// UI controller for the browser client. Port of the desktop frontend plus the
// appcore flow (EnsureEnrolled / CertificateStatus / SignPDF), with the Wails
// bindings replaced by api.js (server), vault.js (IndexedDB) and signer.js
// (the wasm worker that holds the key).
//
// Trust model reminders (docs/threat-model-browser.md):
//   - the private key exists only inside the worker, per operation;
//   - the page is served under a strict CSP: no inline script/style/handlers,
//     so every dynamic string below goes through esc() or textContent;
//   - only the pinned Root CA is trusted, never one attached to a document.
import * as api from './api.js';
import * as vault from './vault.js';
import * as signer from './signer.js';
import * as office from './office.js';

const $ = (id) => document.getElementById(id);
const pdfjs = window.pdfjsLib;
if (pdfjs) pdfjs.GlobalWorkerOptions.workerSrc = 'vendor/pdf.worker.min.js';

const STAMP_ASPECT = 0.42; // caption+QR block, height/width — must match the server
const STAGE_W = 780;
const APP_VERSION = 'web-v1';
const MAX_PDF_BYTES = 512 << 20;

const S = {
  email: '',
  rec: null,        // vault record (key blob is encrypted; never the plaintext key)
  cert: null,       // { state: 'none'|'pending'|'active'|'expired'|'rootchanged', info }
  file: null,       // { name, bytes } chosen for signing
  me: null,         // /office/me (null when the office service is not deployed)
  approval: null,   // { txId, title, docId, fileName, pid } while signing on behalf of a request
  outUrl: '',
};

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// ---------- generic helpers ----------
function screen(id) {
  document.querySelectorAll('.screen').forEach((s) => s.classList.remove('active'));
  $(id).classList.add('active');
  document.body.classList.toggle('placing', id === 'scPlace');
  document.body.classList.toggle('hist', id === 'scHistory');
  document.body.classList.toggle('office', id === 'scTx' || id === 'scTxDetail' || id === 'scRoles');
}

let toastT;
function toast(text, kind) {
  const t = $('toast');
  t.textContent = text;
  t.className = 'show ' + (kind || '');
  clearTimeout(toastT);
  toastT = setTimeout(() => { t.className = ''; }, kind === 'bad' ? 5500 : 2800);
}

async function withBtn(btn, fn) {
  btn.classList.add('loading'); btn.disabled = true;
  try { return await fn(); } finally { btn.classList.remove('loading'); btn.disabled = false; }
}

function friendly(e) {
  const m = (e && e.message) || String(e);
  if (e && e.code === 'wrong_pin') return 'PIN salah.';
  if (e && e.code === 'pin_too_short') return 'PIN minimal 6 karakter.';
  if (e && e.code === 'corrupt') return 'Data kunci di perangkat ini rusak. Gunakan “Reset perangkat ini”.';
  if (e && e.code === 'unsupported') return 'Format data kunci tidak dikenali. Gunakan “Reset perangkat ini”.';
  if (/pending|menunggu persetujuan/i.test(m)) return 'Akun belum disetujui admin.';
  if (/disabled|dinonaktifkan/i.test(m)) return 'Akun dinonaktifkan. Hubungi admin.';
  if (/invalid credentials/i.test(m)) return 'Email atau kata sandi salah.';
  if (/sudah memiliki tanda tangan|message digest mismatch|exactly one signature|already been completed/i.test(m)) {
    return 'Dokumen ini sudah ditandatangani. Sistem hanya mendukung satu tanda tangan per dokumen — pilih PDF yang belum ditandatangani.';
  }
  if (/device not found|different device|no active certificate/i.test(m)) {
    return 'Perangkat ini belum dikenali server. Menu akun → “Reset perangkat ini”, lalu masuk lagi.';
  }
  return m;
}

function fatal(text) {
  const el = $('fatal');
  el.textContent = text || '';
  el.hidden = !text;
}

// Pick a PDF from disk; resolves { name, bytes } or null when cancelled.
function pickPDF() {
  return new Promise((resolve) => {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = 'application/pdf,.pdf';
    inp.addEventListener('change', async () => {
      const f = inp.files && inp.files[0];
      if (!f) return resolve(null);
      if (f.size > MAX_PDF_BYTES) { toast('Berkas terlalu besar.', 'bad'); return resolve(null); }
      resolve({ name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) });
    });
    inp.addEventListener('cancel', () => resolve(null));
    inp.click();
  });
}

function activatable(el, fn) {
  el.addEventListener('click', fn);
  el.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fn(); } });
}

// ---------- PIN dialog ----------
// opts: { title, text, old (ask current PIN), confirm (ask new PIN twice),
//         verify: async (pin, oldPin) => void  — throw to keep the dialog open }
// resolves { pin, old } or null when cancelled.
function pinDialog(opts) {
  const dlg = $('pinDlg');
  const askOld = !!opts.old, askNew = !!opts.confirm;
  $('pinTitle').textContent = opts.title;
  $('pinText').textContent = opts.text || '';
  $('pinOld').value = ''; $('pin1').value = ''; $('pin2').value = ''; $('pinMsg').textContent = '';
  $('pinOk').disabled = false; $('pinOk').classList.remove('loading');
  $('pinOldLbl').hidden = $('pinOld').hidden = !askOld;
  $('pin1Lbl').textContent = askOld ? 'PIN baru' : 'PIN';
  $('pin2Lbl').hidden = $('pin2').hidden = !askNew;
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => {
      if (done) return; done = true;
      $('pinOld').value = ''; $('pin1').value = ''; $('pin2').value = '';
      $('pinForm').onsubmit = null; $('pinCancel').onclick = null; dlg.oncancel = null;
      if (dlg.open) dlg.close();
      resolve(v);
    };
    $('pinCancel').onclick = () => finish(null);
    dlg.oncancel = (e) => { e.preventDefault(); finish(null); };
    $('pinForm').onsubmit = async (e) => {
      e.preventDefault();
      const oldPin = $('pinOld').value, pin = $('pin1').value;
      $('pinMsg').textContent = '';
      if (askNew && [...pin].length < 6) { $('pinMsg').textContent = 'PIN minimal 6 karakter.'; return; }
      if (askNew && pin !== $('pin2').value) { $('pinMsg').textContent = 'Pengulangan PIN tidak sama.'; return; }
      if (!pin || (askOld && !oldPin)) { $('pinMsg').textContent = 'PIN wajib diisi.'; return; }
      $('pinOk').disabled = true; $('pinOk').classList.add('loading');
      try {
        if (opts.verify) await opts.verify(pin, oldPin);
        finish({ pin, old: oldPin });
      } catch (err) {
        $('pinMsg').textContent = friendly(err);
        $('pinOk').disabled = false; $('pinOk').classList.remove('loading');
        $('pin1').select();
      }
    };
    dlg.showModal();
    (askOld ? $('pinOld') : $('pin1')).focus();
  });
}

// ---------- auth ----------
function tab(which) {
  for (const [id, pane] of [['tabLogin', 'paneLogin'], ['tabReg', 'paneReg'], ['tabVerify', 'paneVerify']]) {
    const on = id === 'tab' + which[0].toUpperCase() + which.slice(1);
    $(id).classList.toggle('on', on);
    $(pane).hidden = !on;
  }
}
$('tabLogin').addEventListener('click', () => tab('login'));
$('tabReg').addEventListener('click', () => tab('reg'));
$('tabVerify').addEventListener('click', () => tab('verify'));

activatable($('vpPick'), async () => {
  const out = $('vpResult');
  try {
    const f = await pickPDF(); if (!f) return;
    $('vpName').textContent = f.name;
    out.hidden = false; out.innerHTML = '<div class="hint">Memeriksa…</div>';
    out.innerHTML = renderVerdict(await api.verifyPublic(f.bytes));
  } catch (e) {
    out.hidden = false;
    out.innerHTML = '<div class="verdict bad"><span class="mark">✕</span> Gagal memverifikasi</div><div class="hint">' + esc(friendly(e)) + '</div>';
  }
});

$('paneReg').addEventListener('submit', (ev) => {
  ev.preventDefault();
  withBtn($('btnReg'), async () => {
    $('regMsg').textContent = '';
    const email = $('remail').value.trim();
    if (!email || $('rpw').value.length < 8) { $('regMsg').textContent = 'Isi email dan kata sandi minimal 8 karakter.'; return; }
    try {
      const r = await api.register({
        fullName: $('rname').value.trim(), org: $('rorg').value.trim(), email, password: $('rpw').value,
        position: $('rpos').value.trim(), nip: $('rnip').value.trim(),
      });
      $('lemail').value = email; $('rpw').value = '';
      tab('login');
      toast(r.message || 'Akun dibuat, menunggu persetujuan admin.', 'ok');
    } catch (e) { $('regMsg').textContent = friendly(e); }
  });
});

$('paneLogin').addEventListener('submit', (ev) => {
  ev.preventDefault();
  withBtn($('btnLogin'), async () => {
    $('loginMsg').textContent = '';
    const email = $('lemail').value.trim();
    try {
      await api.login(email, $('lpw').value);
      $('lpw').value = '';
      S.email = email;
      try { sessionStorage.setItem('pqc_email', email); } catch { /* ignore */ }
      enterApp();
    } catch (e) { $('loginMsg').textContent = friendly(e); }
  });
});

async function enterApp() {
  $('acctEmail').textContent = S.email;
  $('acct').hidden = false;
  fatal('');
  try {
    S.me = await office.me();
  } catch (e) {
    if (e && e.status === 401) { logout(); toast('Sesi berakhir, silakan masuk lagi.', 'bad'); return; }
    S.me = null; // office service not deployed: the TTD hub still works on its own
  }
  if (S.me) await officeUI.enter(S.me); else showTTD();
}

function showTTD() {
  if (S.me) officeUI.setNav('ttd');
  renderHome();
  screen('scHome');
}

// The device key is created the first time it is needed (signing / approving),
// not at login — a plain requester never has to make a PIN.
async function ensureDevice() {
  if (S.cert && S.cert.state === 'active') return true;
  fatal('');
  try {
    S.cert = await prepareDevice();
  } catch (e) {
    S.cert = { state: 'none' };
    if (e && e.status === 401) { logout(); toast('Sesi berakhir, silakan masuk lagi.', 'bad'); return false; }
    fatal(friendly(e));
    return false;
  }
  renderHome();
  if (S.cert.state === 'active') return true;
  toast(S.cert.state === 'pending'
    ? 'Sertifikat belum terbit. Pastikan akun disetujui admin, lalu coba lagi.'
    : 'Perangkat belum siap menandatangani.', 'bad');
  return false;
}

// ---------- device enrollment (port of appcore.EnsureEnrolled/CertificateStatus) ----------
function deviceLabel() {
  const ua = navigator.userAgent;
  const br = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : '';
  return 'Web ' + br + (os ? ' / ' + os : '');
}

async function prepareDevice() {
  let rec = await vault.load(S.email);
  const devices = await api.listDevices();
  const known = rec && devices.some((d) => d.device_id === rec.deviceId);

  let freshPIN = null; // PIN typed while creating the key; reused once below, then dropped
  if (!rec || !known) {
    if (rec) toast('Perangkat ini tidak dikenal server — membuat kunci baru.');
    const got = await pinDialog({
      title: 'Buat PIN untuk kunci tanda tangan',
      text: 'Kunci dibuat di browser ini dan tidak pernah dikirim ke server. PIN melindunginya (min. 6 karakter). ' +
        'Jika PIN lupa, kunci tidak bisa dipulihkan — Anda harus mendaftarkan ulang perangkat.',
      confirm: true,
    });
    if (!got) throw new Error('Pembuatan kunci dibatalkan. Masuk lagi untuk mencoba.');
    freshPIN = got.pin;
    rec = await enrollDevice(got.pin);
  }
  S.rec = rec;

  // Root CA: trust on first use, then pinned. A different root later is refused.
  const rootPEM = await api.rootCA();
  const fp = await signer.call('certFingerprint', { pem: rootPEM });
  if (!rec.rootPEM) {
    rec.rootPEM = rootPEM; rec.rootFingerprint = fp;
    await vault.patch(S.email, { rootPEM, rootFingerprint: fp });
  } else if (rec.rootFingerprint !== fp) {
    return { state: 'rootchanged' };
  }
  $('rootFp').textContent = 'Root CA (SHA-256): ' + rec.rootFingerprint;
  try {
    const chainPEM = await api.chain();
    if (chainPEM && chainPEM !== rec.chainPEM) { rec.chainPEM = chainPEM; await vault.patch(S.email, { chainPEM }); }
  } catch { /* keep the cached chain */ }

  return certificateStatus(freshPIN);
}

async function enrollDevice(pin) {
  const label = deviceLabel();
  const { blob, csr } = await signer.call('enroll', {
    pin, request: { common_name: label, device_label: label, platform: 'web' },
  });
  const deviceId = await api.createDevice(label, 'web');
  const enrollmentId = await api.submitCSR(deviceId, csr);
  const rec = { keyBlob: blob, deviceId, enrollmentId, createdAt: Date.now() };
  await vault.save(S.email, rec);
  vault.requestPersistence();
  return { ...rec, rootPEM: '', chainPEM: '' };
}

async function certificateStatus(pinHint) {
  const rec = S.rec;
  if (rec.certPEM) {
    try {
      const info = JSON.parse(await signer.call('checkDeviceCertificate', { pem: rec.certPEM }));
      return { state: 'active', info };
    } catch { /* expired or otherwise unusable: look for a newer one */ }
  }
  const pem = await api.deviceCertificate(rec.deviceId);
  if (pem === null) return { state: 'pending' };
  const info = JSON.parse(await signer.call('checkDeviceCertificate', { pem })
    .catch((e) => { throw new Error('server mengirim sertifikat yang tidak dapat dipakai: ' + e.message); }));
  // The issued certificate MUST belong to the key on this device (Rencana V1 §14).
  const args = { blob: rec.keyBlob, certPEM: pem };
  if (pinHint) {
    args.pin = pinHint;
  } else {
    const got = await pinDialog({
      title: 'Aktifkan sertifikat',
      text: 'Sertifikat baru diterbitkan. Masukkan PIN untuk memastikan sertifikat itu cocok dengan kunci di perangkat ini.',
      verify: async (pin) => { await signer.call('checkPIN', { blob: rec.keyBlob, pin }); },
    });
    if (!got) return { state: 'pending' };
    args.pin = got.pin;
  }
  if (!(await signer.call('certMatchesKey', args))) {
    throw new Error('sertifikat yang diterbitkan TIDAK cocok dengan kunci di perangkat ini — ditolak.');
  }
  rec.certPEM = pem; rec.certSerial = info.serial_number;
  await vault.patch(S.email, { certPEM: pem, certSerial: info.serial_number });
  return { state: 'active', info };
}

function renderHome() {
  const c = S.cert || { state: 'none' };
  const active = c.state === 'active';
  $('homeNote').textContent = '';
  if (active) {
    $('homeSub').textContent = 'Perangkat terverifikasi dan siap menandatangani.';
    $('homeNote').textContent = c.info && c.info.serial_number ? 'Sertifikat: ' + c.info.serial_number : '';
  } else if (c.state === 'pending') {
    $('homeSub').textContent = 'Sertifikat belum terbit. Pastikan akun sudah disetujui admin, lalu muat ulang halaman atau masuk lagi.';
  } else if (c.state === 'rootchanged') {
    $('homeSub').textContent = 'PERINGATAN: Root CA di server berbeda dari yang dipercaya perangkat ini. Penandatanganan dinonaktifkan.';
    fatal('Root CA berubah sejak pendaftaran perangkat. Jika perubahan ini sah (rotasi CA), gunakan “Reset perangkat ini” lalu daftarkan ulang.');
  } else {
    $('homeSub').textContent = 'Kunci tanda tangan dibuat di browser ini saat pertama kali Anda menandatangani.';
  }
}

$('goSign').addEventListener('click', async () => { if (!(await ensureDevice())) return; resetSign(); screen('scSign'); });
$('goVerify').addEventListener('click', () => { resetVerify(); screen('scVerify'); });
$('goHistory').addEventListener('click', () => showHistory());
$('signBack').addEventListener('click', () => screen('scHome'));
$('placeBack').addEventListener('click', () => { if (S.approval) officeUI.openTx(S.approval.txId); else screen('scSign'); });
$('verifyBack').addEventListener('click', () => screen('scHome'));
$('histBack').addEventListener('click', () => screen('scHome'));

// ---------- account menu ----------
function logout() {
  api.setToken('');
  signer.shutdown();
  S.email = ''; S.rec = null; S.cert = null; S.file = null; S.me = null; S.approval = null;
  officeUI.leave();
  try { sessionStorage.removeItem('pqc_email'); } catch { /* ignore */ }
  clearOut();
  $('acct').hidden = true; $('lpw').value = '';
  fatal('');
  screen('scAuth'); tab('login');
}

$('acctBtn').addEventListener('click', () => { $('acctMenu').hidden = !$('acctMenu').hidden; });
document.addEventListener('click', (e) => { if (!$('acct').contains(e.target)) $('acctMenu').hidden = true; });
$('acctMenu').addEventListener('click', async (e) => {
  const act = e.target.dataset && e.target.dataset.act; if (!act) return;
  $('acctMenu').hidden = true;
  try {
    if (act === 'logout') return logout();
    if (act === 'history') return showHistory();
    if (act === 'pin') return changePIN();
    if (act === 'report') {
      if (!S.rec) return toast('Belum ada perangkat terdaftar di browser ini.');
      await api.reportLost(S.rec.deviceId);
      return toast('Perangkat dilaporkan hilang. Admin perlu mencabut sertifikatnya.', 'ok');
    }
    if (act === 'reset') {
      if (!confirm('Hapus kunci & sertifikat di perangkat ini? Kunci tidak bisa dipulihkan; Anda perlu masuk lagi untuk membuat yang baru.')) return;
      await vault.remove(S.email);
      toast('Perangkat direset.', 'ok');
      return logout();
    }
  } catch (err) { toast(friendly(err), 'bad'); }
});

async function changePIN() {
  if (!S.rec) return toast('Belum ada kunci di browser ini. Kunci dibuat saat pertama kali menandatangani.');
  const got = await pinDialog({
    title: 'Ubah PIN', text: 'Kunci dibungkus ulang dengan PIN baru tanpa dibuka.', old: true, confirm: true,
    verify: async (pin, oldPin) => {
      const blob = await signer.call('changePIN', { blob: S.rec.keyBlob, oldPIN: oldPin, newPIN: pin });
      await vault.save(S.email, { ...S.rec, keyBlob: blob });
      S.rec.keyBlob = blob;
    },
  });
  if (got) toast('PIN diubah.', 'ok');
}

// ---------- sign ----------
let pdfDoc = null, pdfPage = 1, pdfPages = 1, savedStamps = [], placeInit = '';

function clearOut() {
  if (S.outUrl) { URL.revokeObjectURL(S.outUrl); S.outUrl = ''; }
}

function resetSign() {
  S.file = null; S.approval = null; clearOut();
  $('btnRetryApproval').hidden = true;
  $('inName').textContent = 'Pilih berkas PDF…'; $('inName').classList.remove('fn');
  $('btnPlace').disabled = true;
  $('signMsg').textContent = ''; $('placeMsg').textContent = '';
  $('signResult').hidden = true; $('signResult').innerHTML = '';
  pdfDoc = null; pdfPage = 1; pdfPages = 1; placeInit = '';
}

activatable($('pickIn'), async () => {
  try {
    const f = await pickPDF(); if (!f) return;
    $('signMsg').textContent = '';
    // One document, one signature: refuse an already-signed PDF up front.
    const n = await signer.call('listSignatures', { pdf: f.bytes.slice() }, { timeoutMs: 30000 });
    if (n > 0) {
      S.file = null; $('btnPlace').disabled = true;
      $('signMsg').textContent = 'Dokumen ini sudah memiliki tanda tangan digital — satu dokumen hanya boleh ditandatangani sekali; pilih PDF yang belum ditandatangani.';
      return;
    }
    S.file = f;
    $('inName').textContent = f.name; $('inName').classList.add('fn');
    $('btnPlace').disabled = false;
  } catch (e) { $('signMsg').textContent = friendly(e); }
});

async function renderQrPage(n) {
  if (!pdfDoc) return;
  pdfPage = Math.min(Math.max(1, n), pdfPages);
  const pg = await pdfDoc.getPage(pdfPage);
  const base = pg.getViewport({ scale: 1 });
  const vp = pg.getViewport({ scale: STAGE_W / base.width });
  const dpr = window.devicePixelRatio || 1;
  const cv = $('qrCanvas');
  cv.width = Math.round(vp.width * dpr); cv.height = Math.round(vp.height * dpr);
  cv.style.width = vp.width + 'px'; cv.style.height = vp.height + 'px';
  const ctx = cv.getContext('2d'); ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  await pg.render({ canvasContext: ctx, viewport: vp }).promise;
  if (document.activeElement !== $('qrPageInput')) $('qrPageInput').value = pdfPage;
  $('qrPageInput').max = pdfPages;
  $('qrPageTotal').textContent = pdfPages;
  $('qrPrev').disabled = pdfPage <= 1; $('qrNext').disabled = pdfPage >= pdfPages;
  placeDefaultBox(vp.width, vp.height);
  refreshStampUI();
}

function placeDefaultBox(sw, sh) {
  const box = $('qrBox');
  if (placeInit === S.file.name) { clampBox(); return; }
  const w = Math.round(0.26 * sw), h = Math.round(w * STAMP_ASPECT);
  box.style.width = w + 'px'; box.style.height = h + 'px';
  box.style.left = Math.round(sw - w - 0.10 * sw) + 'px';
  box.style.top = Math.round(sh - h - 0.10 * sh) + 'px';
  placeInit = S.file.name;
  clampBox();
  // bring the (default bottom-right) box into view inside the preview scroller
  const sc = document.querySelector('.qr-scroll');
  sc.scrollTop = Math.max(0, box.offsetTop - sc.clientHeight / 2);
}

function clampBox() {
  const st = $('qrStage'), box = $('qrBox');
  const sw = st.clientWidth, sh = st.clientHeight;
  let w = Math.min(box.offsetWidth, sw), h = w * STAMP_ASPECT;
  if (h > sh) { h = sh; w = h / STAMP_ASPECT; }
  const l = Math.min(Math.max(0, box.offsetLeft), sw - w);
  const t = Math.min(Math.max(0, box.offsetTop), sh - h);
  box.style.width = Math.round(w) + 'px'; box.style.height = Math.round(h) + 'px';
  box.style.left = Math.round(l) + 'px'; box.style.top = Math.round(t) + 'px';
}

(function wireDrag() {
  const st = $('qrStage'), box = $('qrBox');
  let mode = null, sx = 0, sy = 0, ox = 0, oy = 0, ow = 0;
  const start = (e, m) => {
    mode = m; sx = e.clientX; sy = e.clientY;
    ox = box.offsetLeft; oy = box.offsetTop; ow = box.offsetWidth;
    if (box.setPointerCapture) box.setPointerCapture(e.pointerId);
    e.preventDefault(); e.stopPropagation();
  };
  $('qrHandle').addEventListener('pointerdown', (e) => start(e, 'resize'));
  box.addEventListener('pointerdown', (e) => { if (e.target !== $('qrHandle')) start(e, 'move'); });
  window.addEventListener('pointermove', (e) => {
    if (!mode) return;
    const sw = st.clientWidth, sh = st.clientHeight;
    if (mode === 'move') {
      box.style.left = Math.min(Math.max(0, ox + e.clientX - sx), sw - box.offsetWidth) + 'px';
      box.style.top = Math.min(Math.max(0, oy + e.clientY - sy), sh - box.offsetHeight) + 'px';
    } else {
      let w = Math.min(Math.max(0.08 * sw, ow + e.clientX - sx), sw - ox);
      let h = w * STAMP_ASPECT;
      if (oy + h > sh) { h = sh - oy; w = h / STAMP_ASPECT; }
      box.style.width = Math.round(w) + 'px'; box.style.height = Math.round(h) + 'px';
    }
  });
  window.addEventListener('pointerup', () => { mode = null; });
})();

$('qrPrev').addEventListener('click', () => renderQrPage(pdfPage - 1));
$('qrNext').addEventListener('click', () => renderQrPage(pdfPage + 1));
function jumpToTypedPage() {
  const n = parseInt($('qrPageInput').value, 10);
  if (!pdfDoc || Number.isNaN(n)) { $('qrPageInput').value = pdfPage; return; }
  const c = Math.min(Math.max(1, n), pdfPages);
  if (c === pdfPage) { $('qrPageInput').value = pdfPage; return; }
  renderQrPage(c);
}
$('qrPageInput').addEventListener('change', jumpToTypedPage);
$('qrPageInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); $('qrPageInput').blur(); jumpToTypedPage(); } });

function refreshStampUI() {
  $('stampCount').textContent = savedStamps.length + 1;
  document.querySelectorAll('.qr-marker').forEach((m) => m.remove());
  const st = $('qrStage'); const sw = st.clientWidth, sh = st.clientHeight;
  savedStamps.filter((s) => s.page === pdfPage).forEach((s) => {
    const m = document.createElement('div');
    m.className = 'qr-marker';
    m.style.left = (s.x * sw) + 'px'; m.style.top = (s.y * sh) + 'px';
    m.style.width = (s.w * sw) + 'px'; m.style.height = (s.w * sw * STAMP_ASPECT) + 'px';
    st.appendChild(m);
  });
}

function qrPlacement() {
  if (!pdfDoc) return { page: 0, x: 0.62, y: 0.80, w: 0.26 };
  const st = $('qrStage'), box = $('qrBox');
  const sw = st.clientWidth, sh = st.clientHeight;
  return { page: pdfPage, x: box.offsetLeft / sw, y: box.offsetTop / sh, w: box.offsetWidth / sw };
}

$('btnAddStamp').addEventListener('click', () => {
  savedStamps.push(qrPlacement());
  const box = $('qrBox'), st = $('qrStage');
  box.style.left = Math.max(0, Math.min(box.offsetLeft - 28, st.clientWidth - box.offsetWidth)) + 'px';
  box.style.top = Math.max(0, Math.min(box.offsetTop - 28, st.clientHeight - box.offsetHeight)) + 'px';
  refreshStampUI();
  toast('Titik QR ditambahkan.', 'ok');
});

$('btnPlace').addEventListener('click', () => openPlacement());

async function openPlacement() {
  $('signMsg').textContent = '';
  placeInit = ''; pdfDoc = null; savedStamps = []; refreshStampUI();
  screen('scPlace');
  $('signResult').hidden = true;
  if (!pdfjs) { $('qrHelp').textContent = 'Pratinjau tidak tersedia; QR akan ditaruh di kanan bawah halaman terakhir.'; return; }
  $('qrHelp').textContent = 'Memuat pratinjau…';
  try {
    pdfDoc = await pdfjs.getDocument({ data: S.file.bytes.slice(), isEvalSupported: false }).promise;
    pdfPages = pdfDoc.numPages;
    await renderQrPage(pdfPages); // default to the last page
    $('qrHelp').textContent = 'Seret kotak QR ke kolom tanda tangan. Tarik titik sudut untuk ukuran.';
  } catch {
    pdfDoc = null;
    $('qrHelp').textContent = 'Pratinjau gagal dimuat; QR akan ditaruh di kanan bawah halaman terakhir.';
  }
}

$('btnSign').addEventListener('click', () => withBtn($('btnSign'), async () => {
  $('placeMsg').textContent = ''; $('signResult').hidden = true;
  try { await doSign(); } catch (e) { $('placeMsg').textContent = friendly(e); }
}));

function step(text) { $('qrHelp').textContent = text; }

// Port of appcore.signPDF. The order matters: the server draws the QR stamp
// BEFORE the device signs, so the stamp is inside the signed byte range.
async function doSign() {
  if (!S.cert || S.cert.state !== 'active') throw new Error('Sertifikat perangkat belum aktif.');
  const rec = S.rec;
  const pdf = S.file.bytes;
  const reason = $('sreason').value.trim();
  const place = $('splace').value.trim();
  const placements = savedStamps.concat([qrPlacement()]);

  // PIN first: a wrong PIN must not leave a reserved id behind.
  const got = await pinDialog({
    title: 'Masukkan PIN', text: 'PIN membuka kunci tanda tangan di perangkat ini untuk satu kali penandatanganan.',
    verify: async (pin) => { await signer.call('checkPIN', { blob: rec.keyBlob, pin }); },
  });
  if (!got) return;
  let pin = got.pin;

  try {
    step('Menghitung hash dokumen…');
    const originalHash = await signer.call('sha512', { data: pdf.slice() });
    step('Memesan ID verifikasi…');
    const res = await api.reserve(rec.deviceId, originalHash, S.file.name);

    step('Server menempelkan QR…');
    let toSign;
    try {
      toSign = await api.stamp(res.public_id, pdf, placements, reason, place);
    } catch (e) {
      if (!api.isTooLarge(e)) throw new Error('penempelan QR: ' + e.message);
      toSign = pdf; // too big for a server-drawn stamp (docs/large-files.md)
    }

    step('Menandatangani di perangkat…');
    const out = await signer.call('sign', {
      blob: rec.keyBlob, pin, pdf: toSign, chainPEM: rec.certPEM + rec.chainPEM, rootPEM: rec.rootPEM,
      options: { reason, public_id: res.public_id, verification_url: res.verification_url },
    }, { timeoutMs: 180000 });

    step('Mengirim dokumen bertanda tangan…');
    let status = 'submitted';
    let accepted = false;
    try {
      const sub = await api.submitDocument(res.public_id, out.signedPdf);
      status = sub.status || status;
      accepted = sub.status === 'accepted';
      if (status === 'stored_unverified') status = 'tersimpan — TIDAK diverifikasi server (berkas besar); verifikasi manual lewat halaman verifikasi';
    } catch (e) { status = 'hanya lokal (unggah gagal: ' + e.message + ')'; }

    clearOut();
    const name = S.file.name.replace(/\.pdf$/i, '') + '-bertandatangan.pdf';
    S.outUrl = URL.createObjectURL(new Blob([out.signedPdf], { type: 'application/pdf' }));
    showSignResult(res, status, name);
    toast('Berhasil ditandatangani.', 'ok');
    if (S.approval) await finishApproval(res.public_id, accepted);
  } finally {
    pin = null; // the PIN is not kept past this operation
    $('qrHelp').textContent = 'Seret kotak QR ke kolom tanda tangan. Tarik titik sudut untuk ukuran.';
  }
}

function showSignResult(res, status, fileName) {
  const box = $('signResult');
  box.innerHTML = '<div class="verdict ok"><span class="mark">✓</span> Dokumen ditandatangani</div><dl class="kv">' +
    row('Status server', status) + row('ID verifikasi', res.public_id, true) + row('Tautan / QR', res.verification_url, true) + '</dl>';
  const a = document.createElement('a');
  a.className = 'btn dl'; a.href = S.outUrl; a.download = fileName; a.textContent = '⬇ Unduh PDF bertanda tangan';
  box.appendChild(a);
  box.hidden = false;
}

// ---------- approving a request with a TTD signature ----------
// The request's PDF is signed with the normal pipeline above (reserve -> server
// stamp -> sign in the worker -> submit); then the resulting TTD public id is
// reported to the office service, which checks it with the TTD server.
async function startApproval(a) {
  if (!(await ensureDevice())) return;
  let bytes;
  try { bytes = await office.downloadDoc(a.docId); } catch (e) { toast(friendly(e), 'bad'); return; }
  try {
    const n = await signer.call('listSignatures', { pdf: bytes.slice() }, { timeoutMs: 30000 });
    if (n > 0) { toast('Lampiran sudah memiliki tanda tangan digital; tidak dapat ditandatangani lagi.', 'bad'); return; }
  } catch (e) { toast(friendly(e), 'bad'); return; }
  resetSign();
  S.file = { name: a.fileName, bytes };
  S.approval = { ...a, pid: null };
  $('sreason').value = ('Persetujuan: ' + a.title).slice(0, 120);
  openPlacement();
}

async function finishApproval(pid, accepted) {
  const a = S.approval; a.pid = pid;
  if (!accepted) {
    $('placeMsg').textContent = 'Tanda tangan belum diterima server, persetujuan tidak dikirim.';
    return;
  }
  try {
    await office.decide(a.txId, { decision: 'approve', ttd_public_id: pid });
    S.approval = null;
    toast('Transaksi disetujui.', 'ok');
    await officeUI.openTx(a.txId);
    officeUI.refreshInboxCount();
  } catch (e) {
    $('placeMsg').textContent = friendly(e) + ' — tanda tangan sudah dibuat (ID ' + pid + '); klik “Kirim ulang persetujuan”.';
    $('btnRetryApproval').hidden = false;
  }
}

$('btnRetryApproval').addEventListener('click', () => withBtn($('btnRetryApproval'), async () => {
  if (!S.approval || !S.approval.pid) return;
  $('placeMsg').textContent = '';
  $('btnRetryApproval').hidden = true;
  await finishApproval(S.approval.pid, true);
}));

const officeUI = office.initOffice({ $, esc, toast, screen, friendly, withBtn, pickPDF, activatable, startApproval, showTTD });

// ---------- verify (local, against the pinned Root CA) ----------
function resetVerify() {
  $('vName').textContent = 'Pilih berkas PDF…'; $('vName').classList.remove('fn');
  $('verifyResult').hidden = true; $('verifyResult').innerHTML = '';
}

activatable($('pickVerify'), async () => {
  const out = $('verifyResult');
  try {
    const f = await pickPDF(); if (!f) return;
    $('vName').textContent = f.name; $('vName').classList.add('fn');
    out.hidden = false; out.innerHTML = '<div class="hint">Memeriksa…</div>';
    let crlPEM = '';
    try { crlPEM = await api.crl(); } catch { /* verify without a CRL, the verdict says so */ }
    const rootPEM = (S.rec && S.rec.rootPEM) || await api.rootCA(); // pinned root when this browser has a device
    const raw = await signer.call('verify', { pdf: f.bytes, rootPEM, crlPEM }, { timeoutMs: 60000 });
    out.innerHTML = renderVerdict(raw);
  } catch (e) {
    out.hidden = false;
    out.innerHTML = '<div class="verdict bad"><span class="mark">✕</span> Gagal memverifikasi</div><div class="hint">' + esc(friendly(e)) + '</div>';
  }
});

function renderVerdict(input) {
  let top;
  try { top = typeof input === 'string' ? JSON.parse(input) : input; } catch { return "<div class='hint'>Hasil tidak terbaca.</div>"; }
  // Local verify returns the core result directly; the public /verify wraps it
  // as { verification, registered, record }.
  const o = top.verification || top;
  const sigs = o.signatures || [];
  const rec = top.record || {};
  const storedOnly = rec.verification_status === 'stored_unverified' || rec.certificate_status === 'not_server_verified';
  const storedBanner = storedOnly
    ? '<div class="hint mt14">⚠ Berkas ini terlalu besar untuk diverifikasi otomatis oleh server saat diserahkan — server hanya menyimpan salinan &amp; mencatat SHA-512-nya. Pemeriksaan kriptografis di atas dijalankan ulang sekarang atas berkas ini.</div>'
    : '';
  if (o.valid && sigs.length) {
    const s = sigs[0];
    const subj = s.subject || '';
    const name = (subj.match(/CN=([^,]+)/) || [, '-'])[1];
    const org = (subj.match(/O=([^,]+)/) || [, '-'])[1];
    const pid = String(s.contact || '').replace('pqc-public-id:', '');
    return '<div class="verdict ok"><span class="mark">✓</span> Tanda tangan SAH</div><dl class="kv">' +
      row('Penanda tangan', name) + row('Instansi', org) + row('Algoritma', s.algorithm) +
      row('Alasan', s.reason || '-') + row('Waktu (klaim perangkat)', s.client_claimed_signing_time) +
      row('No. sertifikat', s.certificate_serial, true) + row('Rantai tepercaya', s.trusted_chain ? 'ya' : 'TIDAK') +
      row('Sertifikat dicabut', s.revoked ? 'YA' : 'tidak') +
      (top.registered === true ? row('Terdaftar di server', storedOnly ? 'ya (disimpan, tidak diverifikasi server)' : 'ya') : '') +
      (pid ? row('ID verifikasi', pid, true) : '') + '</dl>' + storedBanner +
      '<p class="note">Waktu di atas berasal dari jam perangkat penandatangan, bukan stempel waktu tepercaya.</p>';
  }
  const errs = o.errors || (sigs[0] && sigs[0].errors) || [];
  return '<div class="verdict bad"><span class="mark">✕</span> Tanda tangan TIDAK sah / tidak ditemukan</div>' +
    (errs.length ? '<ul class="hint">' + errs.map((x) => '<li>' + esc(x) + '</li>').join('') + '</ul>'
      : '<div class="hint">Dokumen tidak memuat tanda tangan ML-DSA-65 yang valid.</div>');
}

function row(k, v, mono) {
  if (v == null || v === '') return '';
  return '<dt>' + esc(k) + '</dt><dd' + (mono ? ' class="mono"' : '') + '>' + esc(v) + '</dd>';
}

// ---------- history ----------
async function showHistory() {
  screen('scHistory');
  const body = $('histBody');
  body.innerHTML = '<p class="hint mt0">Memuat…</p>';
  try {
    const list = await api.mySignatures();
    if (!list.length) { body.innerHTML = '<p class="hint mt0">Belum ada tanda tangan.</p>'; return; }
    const g = (r, a, b) => (r[a] != null ? r[a] : r[b]);
    body.innerHTML = '<table class="hist"><thead><tr><th>Waktu</th><th>ID verifikasi</th><th>Status</th><th>Sertifikat</th></tr></thead><tbody>' +
      list.slice().reverse().map((r) => {
        const id = g(r, 'PublicID', 'public_id');
        return '<tr><td>' + esc(new Date(g(r, 'CreatedAt', 'created_at')).toLocaleString('id-ID')) + '</td>' +
          '<td class="mono"><a href="/v/' + encodeURIComponent(id) + '" target="_blank" rel="noopener noreferrer">' + esc(id) + '</a></td>' +
          '<td>' + esc(g(r, 'VerificationStatus', 'verification_status')) + '</td>' +
          '<td class="mono">' + esc(g(r, 'CertSerial', 'cert_serial')) + '</td></tr>';
      }).join('') + '</tbody></table>';
  } catch (e) { body.innerHTML = '<p class="hint mt0">' + esc(friendly(e)) + '</p>'; }
}

// ---------- init ----------
async function init() {
  $('verTag').textContent = APP_VERSION;
  $('insecure').hidden = vault.hasWebCrypto();
  try { $('lemail').value = sessionStorage.getItem('pqc_email') || ''; } catch { /* ignore */ }
  // Resume a session that survived a page reload (token is per tab).
  let email = '';
  try { email = sessionStorage.getItem('pqc_email') || ''; } catch { /* ignore */ }
  if (api.hasToken() && email) {
    S.email = email;
    enterApp();
  }
}
init();

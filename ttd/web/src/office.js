// Office (transaction) screens: list, create, detail + timeline, approval
// inbox, roles. Talks to /office/* — the transaction service behind the TTD
// server, reached through the same origin and session as everything else.
//
// The approval step reuses the TTD signing pipeline that lives in app.js: this
// module never touches a key. It hands the request's PDF to `startApproval`
// (dependency-injected to avoid a circular import) and later reports the
// resulting TTD public id to the server, which verifies it with the TTD server.
import * as api from './api.js';

const o = (method, path, opts) => api.request(method, '/office' + path, opts);

export const me = () => o('GET', '/me');
export const listTx = (scope, status) => {
  const q = new URLSearchParams({ scope });
  if (status) q.set('status', status);
  return o('GET', '/transactions?' + q).then((r) => r.transactions || []);
};
export const getTx = (id) => o('GET', '/transactions/' + encodeURIComponent(id));
export function createTx(f, file) {
  const fd = new FormData();
  for (const k of ['title', 'category', 'amount', 'description']) fd.append(k, f[k]);
  fd.append('file', new Blob([file.bytes], { type: 'application/pdf' }), file.name);
  return o('POST', '/transactions', { body: fd });
}
const act = (id, what) => o('POST', `/transactions/${encodeURIComponent(id)}/${what}`);
export const submitTx = (id) => act(id, 'submit');
export const completeTx = (id) => act(id, 'complete');
export const cancelTx = (id) => act(id, 'cancel');
export const decide = (id, body) => o('POST', `/transactions/${encodeURIComponent(id)}/decision`,
  { body: JSON.stringify(body), type: 'application/json' });
export const downloadDoc = (id) => o('GET', '/documents/' + encodeURIComponent(id), { raw: 'bytes' });
export const listRoles = () => o('GET', '/roles').then((r) => r.roles || []);
export const setRole = (id, role, email, name) => o('PUT', '/roles/' + encodeURIComponent(id),
  { body: JSON.stringify({ role, email, name }), type: 'application/json' });

// ---- presentation helpers ----
const STATUS = {
  DRAFT: ['Draf', 'neutral'], VERIFIED: ['Menunggu persetujuan', 'warn'], ENDORSED: ['Disetujui', 'ok'],
  COMMITTED: ['Selesai', 'ok'], REJECTED: ['Ditolak', 'bad'], CANCELLED: ['Dibatalkan', 'neutral'],
  SETTLED: ['Selesai', 'ok'], SUPERSEDED: ['Digantikan', 'neutral'], REVOKED: ['Dicabut', 'bad'],
};
const EVENT = {
  CREATED: 'Pengajuan dibuat', SUBMITTED: 'Dikirim untuk persetujuan',
  APPROVED_SIGNED: 'Disetujui dan ditandatangani (TTD)', REJECTED: 'Ditolak',
  COMPLETED: 'Diselesaikan', CANCELLED: 'Dibatalkan',
};
const CATEGORY = { pengadaan: 'Pengadaan', 'perjalanan-dinas': 'Perjalanan dinas', reimbursement: 'Reimbursement', lainnya: 'Lainnya' };
const ROLE = { requester: 'Pemohon', approver: 'Penyetuju', auditor: 'Auditor' };
const rupiah = new Intl.NumberFormat('id-ID', { style: 'currency', currency: 'IDR', maximumFractionDigits: 0 });

export function initOffice(d) {
  const { $, esc, toast, screen, friendly, withBtn, pickPDF, activatable } = d;
  let state = null; // { me, scope, openId }

  const fmtDate = (v) => { try { return new Date(v).toLocaleString('id-ID', { dateStyle: 'medium', timeStyle: 'short' }); } catch { return String(v || ''); } };
  const badge = (status) => { const [t, k] = STATUS[status] || [status, 'neutral']; return `<span class="pill ${k}">${esc(t)}</span>`; };
  const ledgerBadge = (l) => {
    if (!l) return '';
    if (l.state === 'recorded') return '<span class="pill ok" title="Semua peristiwa sudah tercatat di blockchain">Tercatat di ledger</span>';
    if (l.state === 'failed') return '<span class="pill bad" title="Pengiriman ke ledger gagal berulang kali">Ledger: gagal</span>';
    return l.enabled
      ? '<span class="pill warn" title="Menunggu dicatat di blockchain">Antre ke ledger</span>'
      : '<span class="pill neutral" title="Jaringan blockchain belum dihubungkan; peristiwa tersimpan dan bertanda tangan, menunggu dicatat">Ledger belum terhubung</span>';
  };
  const dl = (rows) => '<dl class="kv">' + rows.filter(([, v]) => v != null && v !== '').map(([k, v, mono]) =>
    `<dt>${esc(k)}</dt><dd${mono ? ' class="mono"' : ''}>${esc(v)}</dd>`).join('') + '</dl>';

  // ---------- navigation ----------
  function setNav(active) {
    document.querySelectorAll('#nav [data-nav]').forEach((b) => b.classList.toggle('on', b.dataset.nav === active));
  }

  async function enter(meInfo) {
    state = { me: meInfo, scope: 'mine' };
    const role = meInfo.office_role;
    const seesAll = meInfo.is_admin || role === 'approver' || role === 'auditor';
    $('nav').hidden = false;
    $('navInbox').hidden = role !== 'approver';
    $('navRoles').hidden = !meInfo.is_admin;
    const sel = $('txScope');
    sel.innerHTML = '<option value="mine">Pengajuan saya</option>' +
      (seesAll ? '<option value="all">Semua transaksi</option>' : '') +
      (role === 'approver' ? '<option value="inbox">Menunggu persetujuan saya</option>' : '');
    state.scope = role === 'approver' ? 'inbox' : (meInfo.is_admin ? 'all' : 'mine');
    sel.value = state.scope;
    $('txRole').textContent = ROLE[role] || role;
    await showList();
    refreshInboxCount();
  }

  function leave() { state = null; $('nav').hidden = true; }

  async function refreshInboxCount() {
    if (!state || state.me.office_role !== 'approver') return;
    try {
      const n = (await listTx('inbox')).length;
      $('inboxCount').textContent = n ? String(n) : '';
      $('inboxCount').hidden = !n;
    } catch { /* badge only */ }
  }

  // ---------- list ----------
  async function showList() {
    screen('scTx'); setNav(state.scope === 'inbox' ? 'inbox' : 'tx');
    const box = $('txList');
    box.innerHTML = '<p class="hint mt0">Memuat…</p>';
    try {
      const rows = await listTx(state.scope, $('txStatus').value);
      if (!rows.length) {
        box.innerHTML = '<p class="hint mt0">' + (state.scope === 'inbox' ? 'Tidak ada pengajuan yang menunggu persetujuan Anda.' : 'Belum ada transaksi.') + '</p>';
        return;
      }
      box.innerHTML = '<table class="hist"><thead><tr><th>Judul</th><th>Status</th><th>Nominal</th><th>Pemohon</th><th>Diperbarui</th></tr></thead><tbody>' +
        rows.map((r) => `<tr class="click" data-open="${esc(r.id)}" tabindex="0">
          <td><b>${esc(r.title)}</b><div class="faint">${esc(CATEGORY[r.category] || r.category)}</div></td>
          <td>${badge(r.status)}<div class="mt4">${ledgerBadge(r.ledger)}</div></td>
          <td>${esc(rupiah.format(r.amount))}</td><td>${esc(r.created_by_name)}</td><td>${esc(fmtDate(r.updated_at))}</td></tr>`).join('') +
        '</tbody></table>';
    } catch (e) { box.innerHTML = '<p class="hint mt0">' + esc(friendly(e)) + '</p>'; }
  }

  $('txList').addEventListener('click', (e) => { const tr = e.target.closest('[data-open]'); if (tr) openTx(tr.dataset.open); });
  $('txList').addEventListener('keydown', (e) => { if (e.key === 'Enter') { const tr = e.target.closest('[data-open]'); if (tr) openTx(tr.dataset.open); } });
  $('txScope').addEventListener('change', () => { state.scope = $('txScope').value; showList(); });
  $('txStatus').addEventListener('change', () => showList());

  // ---------- create ----------
  let newFile = null;
  function showNew() {
    newFile = null;
    $('txForm').reset();
    $('txFileName').textContent = 'Pilih lampiran PDF…'; $('txFileName').classList.remove('fn');
    $('txNewMsg').textContent = '';
    screen('scTxNew'); setNav('tx');
  }
  $('txNew').addEventListener('click', showNew);
  $('txNewBack').addEventListener('click', () => showList());
  activatable($('txPick'), async () => {
    const f = await pickPDF(); if (!f) return;
    newFile = f; $('txFileName').textContent = f.name; $('txFileName').classList.add('fn');
  });

  async function saveNew(andSubmit, btn) {
    $('txNewMsg').textContent = '';
    const f = {
      title: $('txTitle').value.trim(), category: $('txCategory').value,
      amount: $('txAmount').value.replace(/[^\d]/g, ''), description: $('txDesc').value.trim(),
    };
    if (f.title.length < 3) { $('txNewMsg').textContent = 'Judul minimal 3 karakter.'; return; }
    if (f.amount === '') { $('txNewMsg').textContent = 'Isi nominal (rupiah).'; return; }
    if (!newFile) { $('txNewMsg').textContent = 'Lampirkan berkas PDF.'; return; }
    await withBtn(btn, async () => {
      try {
        const { id } = await createTx(f, newFile);
        if (andSubmit) await submitTx(id);
        toast(andSubmit ? 'Pengajuan dikirim untuk persetujuan.' : 'Draf disimpan.', 'ok');
        await openTx(id);
      } catch (e) { $('txNewMsg').textContent = friendly(e); }
    });
  }
  $('txSaveDraft').addEventListener('click', () => saveNew(false, $('txSaveDraft')));
  $('txSaveSend').addEventListener('click', () => saveNew(true, $('txSaveSend')));

  // ---------- detail ----------
  async function openTx(id) {
    screen('scTxDetail'); setNav(state.scope === 'inbox' ? 'inbox' : 'tx');
    $('txDetail').innerHTML = '<p class="hint mt0">Memuat…</p>';
    $('txActions').innerHTML = ''; $('txActMsg').textContent = '';
    try { renderDetail(await getTx(id)); }
    catch (e) { $('txDetail').innerHTML = '<p class="hint mt0">' + esc(friendly(e)) + '</p>'; }
  }

  function renderDetail(det) {
    const t = det.transaction, p = det.permissions;
    const attachment = det.documents.find((x) => x.kind === 'attachment');
    const decision = det.events.find((e) => e.type === 'REJECTED');

    const docs = det.documents.map((x) => `<tr><td>${x.kind === 'signed' ? 'PDF bertanda tangan (TTD)' : 'Lampiran asli'}</td>
      <td>${esc(x.file_name)}</td><td class="mono">${esc(x.sha512.slice(0, 24))}…</td>
      <td><button type="button" class="btn secondary sm" data-doc="${esc(x.id)}" data-name="${esc(x.file_name)}">Unduh</button></td></tr>`).join('');
    const timeline = det.events.map((e) => {
      const extra = [];
      if (e.payload && e.payload.reason) extra.push('Alasan: ' + e.payload.reason);
      if (e.payload && e.payload.ttd_public_id) extra.push('ID verifikasi TTD: ' + e.payload.ttd_public_id);
      const chain = e.recorded_on_ledger
        ? `<span class="pill ok">Blok ${esc(e.fabric_block_number ?? '?')}</span>`
        : `<span class="pill neutral">${det.ledger.enabled ? 'antre' : 'belum dicatat'}</span>`;
      return `<li><div class="tl-h"><b>${esc(EVENT[e.type] || e.type)}</b> ${chain}</div>
        <div class="faint">${esc(e.actor_name)} · ${esc(fmtDate(e.at))} · #${e.sequence}</div>
        ${extra.map((x) => `<div>${esc(x)}</div>`).join('')}
        <div class="mono faint">hash ${esc(e.payload_hash.slice(0, 20))}…</div></li>`;
    }).join('');

    $('txDetail').innerHTML = `
      <div class="detail-head"><div><h2 class="h2">${esc(t.title)}</h2>
        <div>${badge(t.status)} ${ledgerBadge(det.ledger)}</div></div></div>
      ${dl([['Kategori', CATEGORY[t.category] || t.category], ['Nominal', rupiah.format(t.amount)], ['Pemohon', t.created_by_name],
        ['Dibuat', fmtDate(t.created_at)], ['Keterangan', t.description], ['ID transaksi', t.id, true]])}
      ${decision && decision.payload && decision.payload.reason ? `<div class="banner bad mt14">Ditolak: ${esc(decision.payload.reason)}</div>` : ''}
      ${det.ttd ? `<div class="banner ok mt14">Disetujui dengan tanda tangan digital pasca-kuantum. Periksa keasliannya:
        <a href="${esc('/v/' + encodeURIComponent(det.ttd.public_id))}" target="_blank" rel="noopener noreferrer">${esc(det.ttd.public_id)}</a></div>` : ''}
      <h3 class="h3">Dokumen</h3>
      <table class="hist"><thead><tr><th>Jenis</th><th>Berkas</th><th>SHA-512</th><th></th></tr></thead><tbody>${docs}</tbody></table>
      <h3 class="h3">Riwayat</h3><ol class="timeline">${timeline}</ol>
      <p class="note">Setiap peristiwa ditandatangani hybrid (Ed25519 + ML-DSA-65) dan berantai hash. ${det.ledger.enabled
        ? 'Pencatatan ke blockchain berjalan lewat antrean.'
        : 'Jaringan blockchain belum dihubungkan pada instalasi ini: peristiwa tersimpan lengkap dan menunggu dicatat.'}</p>`;

    const bar = $('txActions'); bar.innerHTML = '';
    const add = (label, cls, fn) => {
      const b = document.createElement('button');
      b.type = 'button'; b.className = 'btn ' + cls; b.textContent = label;
      b.addEventListener('click', () => withBtn(b, fn));
      bar.appendChild(b);
    };
    const run = async (fn, okMsg) => {
      $('txActMsg').textContent = '';
      try { await fn(); toast(okMsg, 'ok'); await openTx(t.id); refreshInboxCount(); }
      catch (e) { $('txActMsg').textContent = friendly(e); }
    };
    if (p.can_approve) {
      add('Setujui & tanda tangani', '', async () => {
        if (!attachment) { $('txActMsg').textContent = 'Lampiran tidak ditemukan.'; return; }
        $('txActMsg').textContent = '';
        await d.startApproval({ txId: t.id, title: t.title, docId: attachment.id, fileName: attachment.file_name });
      });
      add('Tolak', 'secondary', async () => {
        const reason = await askReason();
        if (reason) await run(() => decide(t.id, { decision: 'reject', reason }), 'Pengajuan ditolak.');
      });
    }
    if (p.can_submit) add('Kirim untuk persetujuan', '', () => run(() => submitTx(t.id), 'Dikirim untuk persetujuan.'));
    if (p.can_complete) add('Tandai selesai', '', () => run(() => completeTx(t.id), 'Transaksi diselesaikan.'));
    if (p.can_cancel) add('Batalkan', 'secondary', async () => {
      if (confirm('Batalkan pengajuan ini?')) await run(() => cancelTx(t.id), 'Pengajuan dibatalkan.');
    });
  }

  $('txDetail').addEventListener('click', async (e) => {
    const b = e.target.closest('[data-doc]'); if (!b) return;
    try {
      const bytes = await downloadDoc(b.dataset.doc);
      const url = URL.createObjectURL(new Blob([bytes], { type: 'application/pdf' }));
      const a = document.createElement('a'); a.href = url; a.download = b.dataset.name || 'dokumen.pdf';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } catch (err) { toast(friendly(err), 'bad'); }
  });
  $('txDetailBack').addEventListener('click', () => showList());

  function askReason() {
    const dlg = $('reasonDlg');
    $('reasonText').value = ''; $('reasonMsg').textContent = '';
    return new Promise((resolve) => {
      const done = (v) => { $('reasonForm').onsubmit = null; $('reasonCancel').onclick = null; dlg.oncancel = null; if (dlg.open) dlg.close(); resolve(v); };
      $('reasonCancel').onclick = () => done(null);
      dlg.oncancel = (e) => { e.preventDefault(); done(null); };
      $('reasonForm').onsubmit = (e) => {
        e.preventDefault();
        const v = $('reasonText').value.trim();
        if (v.length < 3) { $('reasonMsg').textContent = 'Alasan wajib diisi (minimal 3 karakter).'; return; }
        done(v);
      };
      dlg.showModal(); $('reasonText').focus();
    });
  }

  // ---------- roles (admin) ----------
  async function showRoles() {
    screen('scRoles'); setNav('roles');
    const box = $('rolesBody');
    box.innerHTML = '<p class="hint mt0">Memuat…</p>';
    try {
      const [accounts, roles] = await Promise.all([
        api.request('GET', '/api/v1/admin/accounts').then((r) => (Array.isArray(r) ? r : r.accounts || [])),
        listRoles(),
      ]);
      const cur = new Map(roles.map((r) => [r.account_id, r.role]));
      const users = accounts.filter((a) => (a.role || 'user') === 'user' && a.status === 'active');
      if (!users.length) { box.innerHTML = '<p class="hint mt0">Belum ada akun pegawai yang aktif.</p>'; return; }
      box.innerHTML = '<table class="hist"><thead><tr><th>Pegawai</th><th>Peran</th><th></th></tr></thead><tbody>' +
        users.map((a) => {
          const id = a.account_id || a.id; const role = cur.get(id) || 'requester';
          return `<tr><td><b>${esc(a.full_name || a.email)}</b><div class="faint">${esc(a.email)}</div></td>
            <td><select data-role-for="${esc(id)}">${Object.keys(ROLE).map((r) => `<option value="${r}"${r === role ? ' selected' : ''}>${ROLE[r]}</option>`).join('')}</select></td>
            <td><button type="button" class="btn secondary sm" data-save="${esc(id)}" data-email="${esc(a.email)}" data-name="${esc(a.full_name || a.email)}">Simpan</button></td></tr>`;
        }).join('') + '</tbody></table>';
    } catch (e) { box.innerHTML = '<p class="hint mt0">' + esc(friendly(e)) + '</p>'; }
  }
  $('rolesBody').addEventListener('click', async (e) => {
    const b = e.target.closest('[data-save]'); if (!b) return;
    const sel = document.querySelector(`[data-role-for="${CSS.escape(b.dataset.save)}"]`);
    await withBtn(b, async () => {
      try { await setRole(b.dataset.save, sel.value, b.dataset.email, b.dataset.name); toast('Peran disimpan.', 'ok'); }
      catch (err) { toast(friendly(err), 'bad'); }
    });
  });

  // ---------- top navigation ----------
  $('nav').addEventListener('click', (e) => {
    const b = e.target.closest('[data-nav]'); if (!b || !state) return;
    switch (b.dataset.nav) {
      case 'tx': state.scope = state.me.is_admin ? 'all' : 'mine'; $('txScope').value = state.scope; return showList();
      case 'inbox': state.scope = 'inbox'; $('txScope').value = 'inbox'; return showList();
      case 'ttd': setNav('ttd'); return d.showTTD();
      case 'roles': return showRoles();
    }
  });

  return { enter, leave, openTx, showList, refreshInboxCount, setNav };
}

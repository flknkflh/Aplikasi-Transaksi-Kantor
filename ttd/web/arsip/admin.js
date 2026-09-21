// Central-admin screens: the archive (list, detail, verification, download) and
// offices / members. Only an account with the admin role reaches these — the
// ledger service enforces it; hiding the buttons is only convenience.
'use strict';
import * as api from './api.js';

const PAGE = 25;

export function initAdmin(d) {
  const { $, esc, toast, screen, friendly, withBtn, fmtBytes, fmtDate, row, checksHTML, ledgerBadge, activatable, setNav } = d;
  const q = { offset: 0, total: 0 };
  let officeList = [];

  // ---------- archive list ----------
  function enter() { showArchive(); }

  async function loadOffices() {
    officeList = (await api.get('/office/archive/offices')).offices || [];
    const sel = $('arOrg'), cur = sel.value;
    sel.innerHTML = '<option value="">Semua kantor</option>' + officeList.map((o) => `<option value="${esc(o.id)}">${esc(o.name)}</option>`).join('');
    sel.value = cur;
  }

  async function showArchive() {
    screen('scArchive'); setNav('archive');
    try { await loadOffices(); } catch { /* the list still works without the filter */ }
    try {
      const st = await api.get('/office/archive/stats');
      $('arStats').textContent = st.items + ' kiriman · ' + fmtBytes(st.bytes) + ' · ' + st.last_24h + ' dalam 24 jam terakhir';
    } catch { $('arStats').textContent = ''; }
    await loadList();
  }

  async function loadList() {
    const box = $('arList');
    box.innerHTML = '<p class="hint mt0">Memuat…</p>';
    const p = new URLSearchParams({ limit: String(PAGE), offset: String(q.offset) });
    if ($('arOrg').value) p.set('org', $('arOrg').value);
    if ($('arQ').value.trim()) p.set('q', $('arQ').value.trim());
    if ($('arFrom').value) p.set('from', $('arFrom').value);
    if ($('arTo').value) p.set('to', $('arTo').value);
    try {
      const r = await api.get('/office/archive/items?' + p);
      q.total = r.total;
      if (!r.items.length) { box.innerHTML = '<p class="hint mt0">Belum ada kiriman yang cocok.</p>'; $('arPager').hidden = true; return; }
      box.innerHTML = '<table class="hist"><thead><tr><th>Diterima</th><th>Kantor</th><th>Pengirim</th><th>Berkas</th><th>Ukuran</th><th>Blockchain</th></tr></thead><tbody>' +
        r.items.map((it) => `<tr class="click" data-open="${esc(it.id)}" tabindex="0">
          <td>${esc(fmtDate(it.received_at))}</td><td>${esc(it.organization_name)}</td><td>${esc(it.sender_name)}</td>
          <td><b>${esc(it.file_name)}</b><div class="mono faint">${esc(it.sha256.slice(0, 16))}…</div></td>
          <td>${esc(fmtBytes(it.size_bytes))}</td><td>${ledgerBadge(it.ledger)}</td></tr>`).join('') + '</tbody></table>';
      const from = q.offset + 1, to = q.offset + r.items.length;
      $('arPager').hidden = q.total <= PAGE;
      $('arPage').textContent = from + '–' + to + ' dari ' + q.total;
      $('arPrev').disabled = q.offset === 0; $('arNext').disabled = to >= q.total;
    } catch (e) { box.innerHTML = '<p class="hint mt0">' + esc(friendly(e)) + '</p>'; }
  }
  $('arGo').addEventListener('click', () => { q.offset = 0; loadList(); });
  $('arQ').addEventListener('keydown', (e) => { if (e.key === 'Enter') { q.offset = 0; loadList(); } });
  $('arOrg').addEventListener('change', () => { q.offset = 0; loadList(); });
  $('arPrev').addEventListener('click', () => { q.offset = Math.max(0, q.offset - PAGE); loadList(); });
  $('arNext').addEventListener('click', () => { q.offset += PAGE; loadList(); });
  const open = (e) => { const tr = e.target.closest('[data-open]'); if (tr) showItem(tr.dataset.open); };
  $('arList').addEventListener('click', open);
  $('arList').addEventListener('keydown', (e) => { if (e.key === 'Enter') open(e); });

  // ---------- detail ----------
  let current = null;
  async function showItem(id) {
    screen('scItem'); setNav('archive');
    $('itBody').innerHTML = '<p class="hint mt0">Memuat…</p>';
    $('itActions').innerHTML = ''; $('itVerify').innerHTML = ''; $('itMsg').textContent = '';
    try {
      const it = current = await api.get('/office/archive/items/' + encodeURIComponent(id));
      const timeline = it.events.map((e) => `<li><div class="tl-h"><b>${esc(e.type)}</b>
        ${e.recorded_on_ledger ? `<span class="pill ok">Blok ${esc(e.fabric_block_number ?? '?')}</span>` : '<span class="pill neutral">belum di blockchain</span>'}</div>
        <div class="faint">${esc(e.actor_name)} · ${esc(fmtDate(e.at))} · #${e.sequence}</div>
        <div class="mono faint">hash ${esc(e.payload_hash.slice(0, 24))}…</div></li>`).join('');
      $('itBody').innerHTML = `
        <h2 class="h2">${esc(it.file_name)}</h2>
        <div>${ledgerBadge(it.ledger)}</div>
        <dl class="kv">
          ${row('Kantor', it.organization_name)}${row('Pengirim', it.sender_name + ' (' + it.sender_email + ')')}
          ${row('Diterima', fmtDate(it.received_at))}${row('Ukuran', fmtBytes(it.size_bytes) + ' (' + it.size_bytes.toLocaleString('id-ID') + ' byte)')}
          ${row('Jenis', it.media_type)}${row('Keterangan', it.description)}
          ${row('Alamat IP pengirim', it.client_ip)}${row('Peramban', it.user_agent)}
          ${row('Nomor bukti', it.receipt_id, true)}${row('ID transaksi', it.transaction_id, true)}
        </dl>
        <div class="hashbox"><b>SHA-256</b> ${esc(it.sha256)}</div>
        <div class="hashbox mt4"><b>SHA-512</b> ${esc(it.sha512)}</div>
        <h3 class="h3">Riwayat berantai hash</h3><ol class="timeline">${timeline}</ol>`;
      const bar = $('itActions');
      const add = (label, cls, fn) => {
        const b = document.createElement('button');
        b.type = 'button'; b.className = 'btn ' + cls; b.textContent = label;
        b.addEventListener('click', () => withBtn(b, fn));
        bar.appendChild(b);
      };
      add('Verifikasi tanda tangan', '', () => verify(false));
      add('Verifikasi + cek berkas tersimpan', 'secondary', () => verify(true));
      add('Unduh berkas', 'secondary', download);
    } catch (e) { $('itBody').innerHTML = '<p class="hint mt0">' + esc(friendly(e)) + '</p>'; }
  }
  async function verify(deep) {
    $('itMsg').textContent = '';
    try {
      const v = await api.post('/office/archive/items/' + encodeURIComponent(current.id) + '/verify' + (deep ? '?deep=1' : ''));
      $('itVerify').innerHTML = `<div class="verdict ${v.ok ? 'ok' : 'bad'} mt14"><span class="mark">${v.ok ? '✓' : '✕'}</span> ${v.ok ? 'Semua pemeriksaan lolos' : 'ADA PEMERIKSAAN YANG GAGAL'}</div>` + checksHTML(v);
    } catch (e) { $('itMsg').textContent = friendly(e); }
  }
  // A one-time link lets the browser stream even a multi-gigabyte file natively.
  async function download() {
    $('itMsg').textContent = '';
    try {
      const t = await api.post('/office/archive/items/' + encodeURIComponent(current.id) + '/ticket');
      const a = document.createElement('a');
      a.href = t.url; a.rel = 'noopener';
      document.body.appendChild(a); a.click(); a.remove();
      toast('Unduhan dimulai.', 'ok');
    } catch (e) { $('itMsg').textContent = friendly(e); }
  }
  $('itBack').addEventListener('click', () => showArchive());

  // ---------- offices & members ----------
  async function showOffices() {
    screen('scOffices'); setNav('offices');
    $('ofMsg').textContent = '';
    await refreshOffices();
  }

  async function refreshOffices() {
    try {
      const [offices, members, accounts] = await Promise.all([
        api.get('/office/archive/offices'),
        api.get('/office/archive/members'),
        api.get('/api/v1/admin/accounts').catch(() => ({ accounts: [] })),
      ]);
      officeList = offices.offices || [];
      $('ofList').innerHTML = officeList.length
        ? '<table class="hist"><thead><tr><th>Kantor</th><th>Pengguna</th><th>Kiriman</th><th>Total ukuran</th></tr></thead><tbody>' +
          officeList.map((o) => `<tr><td><b>${esc(o.name)}</b></td><td>${o.members}</td><td>${o.items}</td><td>${esc(fmtBytes(o.bytes))}</td></tr>`).join('') + '</tbody></table>'
        : '<p class="hint mt0">Belum ada kantor. Tambahkan kantor pertama di bawah.</p>';

      // Merge TTD accounts (who may log in) with what the archive knows about them.
      const known = new Map((members.members || []).map((m) => [m.account_id, m]));
      const list = Array.isArray(accounts) ? accounts : accounts.accounts || [];
      const people = list.filter((a) => (a.role || 'user') === 'user' && a.status === 'active').map((a) => {
        const id = a.account_id || a.id, k = known.get(id) || {};
        return { id, email: a.email, name: a.full_name || a.email, office: k.organization_id || '' };
      });
      for (const m of members.members || []) if (!people.some((p) => p.id === m.account_id)) people.push({ id: m.account_id, email: m.email, name: m.name, office: m.organization_id || '' });
      $('mbList').innerHTML = people.length
        ? '<table class="hist"><thead><tr><th>Pengguna</th><th>Kantor</th><th></th></tr></thead><tbody>' + people.map((p) => `<tr>
            <td><b>${esc(p.name)}</b><div class="faint">${esc(p.email)}</div></td>
            <td><select data-mb="${esc(p.id)}"><option value="">— belum ditetapkan —</option>${officeList.map((o) => `<option value="${esc(o.id)}"${o.id === p.office ? ' selected' : ''}>${esc(o.name)}</option>`).join('')}</select></td>
            <td><button type="button" class="btn secondary sm" data-save="${esc(p.id)}" data-email="${esc(p.email)}" data-name="${esc(p.name)}">Simpan</button></td></tr>`).join('') + '</tbody></table>'
        : '<p class="hint mt0">Belum ada pengguna aktif. Setujui akun di konsol admin.</p>';
    } catch (e) { $('mbList').innerHTML = '<p class="hint mt0">' + esc(friendly(e)) + '</p>'; }
  }
  $('ofAdd').addEventListener('click', () => withBtn($('ofAdd'), async () => {
    $('ofMsg').textContent = '';
    try { await api.post('/office/archive/offices', { name: $('ofName').value.trim() }); $('ofName').value = ''; toast('Kantor ditambahkan.', 'ok'); await refreshOffices(); }
    catch (e) { $('ofMsg').textContent = friendly(e); }
  }));
  $('mbList').addEventListener('click', async (e) => {
    const b = e.target.closest('[data-save]'); if (!b) return;
    const sel = document.querySelector(`[data-mb="${CSS.escape(b.dataset.save)}"]`);
    await withBtn(b, async () => {
      try { await api.put('/office/archive/members/' + encodeURIComponent(b.dataset.save), { organization_id: sel.value, email: b.dataset.email, name: b.dataset.name }); toast('Tersimpan.', 'ok'); await refreshOffices(); }
      catch (err) { toast(friendly(err), 'bad'); }
    });
  });

  return { enter, showArchive, showOffices };
}

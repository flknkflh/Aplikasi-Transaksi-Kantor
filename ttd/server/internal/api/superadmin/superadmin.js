// Super-admin page. A separate login (password -> authenticator code) and one
// job: create and manage ADMIN accounts. The session token lives in memory only
// (not even sessionStorage): closing or reloading the tab logs out, and the server
// ends the session after 15 minutes regardless.
'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  let token = '', challenge = '', expiresAt = 0, timerId = 0, username = '';

  function screen(id) {
    document.querySelectorAll('.screen').forEach((s) => s.classList.remove('active'));
    $(id).classList.add('active');
  }
  let toastT;
  function toast(t, k) {
    const e = $('toast'); e.textContent = t; e.className = 'show ' + (k || '');
    clearTimeout(toastT); toastT = setTimeout(() => { e.className = ''; }, k === 'bad' ? 5000 : 2600);
  }

  async function call(method, path, body, auth) {
    const headers = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (auth && token) headers.Authorization = 'Bearer ' + token;
    let r;
    try { r = await fetch('/api/v1/superadmin' + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'omit', cache: 'no-store' }); }
    catch { throw Object.assign(new Error('Tidak bisa terhubung ke server.'), { status: 0 }); }
    const text = await r.text();
    let data = {}; try { data = text ? JSON.parse(text) : {}; } catch { data = { error: text }; }
    if (!r.ok) {
      if (r.status === 401 && auth) { logout('Sesi berakhir. Masuk lagi.'); }
      const e = new Error(data.error || r.statusText); e.status = r.status; e.data = data; throw e;
    }
    return data;
  }

  // ---------- session ----------
  function startSession(tok, secs) {
    token = tok; expiresAt = Date.now() + secs * 1000;
    $('who').hidden = false; $('whoName').textContent = username;
    clearInterval(timerId);
    timerId = setInterval(tick, 1000); tick();
    showHome();
  }
  function tick() {
    const left = Math.max(0, Math.round((expiresAt - Date.now()) / 1000));
    $('timer').textContent = Math.floor(left / 60) + ':' + String(left % 60).padStart(2, '0');
    if (left <= 0) logout('Sesi berakhir. Masuk lagi.');
  }
  function logout(msg) {
    token = ''; challenge = ''; clearInterval(timerId);
    $('who').hidden = true;
    for (const id of ['lPass', 'cCode', 'suNew', 'suNew2', 'suCode', 'nPass', 'pCur', 'pNew']) $(id).value = '';
    $('nDone').hidden = true; $('fEnrol').hidden = true; $('fSetup').hidden = false;
    screen('scLogin');
    if (msg) $('lMsg').textContent = msg;
  }
  $('btnOut').addEventListener('click', () => logout(''));

  // ---------- step 1: password ----------
  $('fLogin').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('lMsg').textContent = '';
    username = $('lUser').value.trim();
    $('lGo').disabled = true;
    try {
      const r = await call('POST', '/login', { username, password: $('lPass').value });
      challenge = r.challenge; $('lPass').value = '';
      if (r.step === 'setup') {
        $('suPwBox').hidden = !r.must_change;
        $('suSub').textContent = r.must_change ? 'Ganti kata sandi awal, lalu daftarkan aplikasi authenticator.' : 'Daftarkan aplikasi authenticator untuk akun ini.';
        $('suGo').textContent = r.must_change ? 'Lanjut ke authenticator' : 'Buat kode authenticator';
        $('suMsg').textContent = '';
        screen('scSetup');
        $(r.must_change ? 'suNew' : 'suGo').focus();
      } else {
        $('cMsg').textContent = ''; $('cCode').value = '';
        screen('scCode'); $('cCode').focus();
      }
    } catch (err) { $('lMsg').textContent = err.data && err.data.retry_after ? err.message + ' (coba lagi ' + Math.ceil(err.data.retry_after / 60) + ' menit lagi)' : err.message; }
    finally { $('lGo').disabled = false; }
  });

  // ---------- step 2a: authenticator code ----------
  $('fCode').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('cMsg').textContent = '';
    $('cGo').disabled = true;
    try {
      const r = await call('POST', '/verify', { challenge, code: $('cCode').value });
      $('cCode').value = ''; startSession(r.access_token, r.expires_in);
    } catch (err) {
      $('cMsg').textContent = err.data && err.data.retry_after ? err.message + ' (coba lagi ' + Math.ceil(err.data.retry_after / 60) + ' menit lagi)' : err.message;
      if (err.status === 401 && /habis|tidak valid/.test(err.message)) logout(err.message);
    } finally { $('cGo').disabled = false; }
  });
  $('cBack').addEventListener('click', () => logout(''));

  // ---------- step 2b: first login ----------
  $('fSetup').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('suMsg').textContent = '';
    const needPw = !$('suPwBox').hidden;
    if (needPw && $('suNew').value !== $('suNew2').value) { $('suMsg').textContent = 'Pengulangan kata sandi tidak sama.'; return; }
    $('suGo').disabled = true;
    try {
      const r = await call('POST', '/setup/begin', { challenge, new_password: needPw ? $('suNew').value : '' });
      $('suNew').value = ''; $('suNew2').value = '';
      $('suQr').src = r.qr_png || ''; $('suQr').hidden = !r.qr_png;
      $('suSecret').textContent = r.secret;
      $('fSetup').hidden = true; $('fEnrol').hidden = false; $('enMsg').textContent = ''; $('suCode').focus();
    } catch (err) {
      $('suMsg').textContent = err.message;
      if (err.status === 401) logout(err.message);
    } finally { $('suGo').disabled = false; }
  });
  $('fEnrol').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('enMsg').textContent = '';
    $('suConfirm').disabled = true;
    try {
      const r = await call('POST', '/setup/confirm', { challenge, code: $('suCode').value });
      $('suCode').value = ''; $('suSecret').textContent = ''; $('suQr').src = '';
      $('fEnrol').hidden = true; $('fSetup').hidden = false;
      startSession(r.access_token, r.expires_in);
      toast('Authenticator aktif. Sandi baru berlaku untuk login berikutnya.', 'ok');
    } catch (err) { $('enMsg').textContent = err.message; }
    finally { $('suConfirm').disabled = false; }
  });

  // ---------- console ----------
  function randomPassword() {
    const alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%*-_';
    const b = new Uint8Array(20); crypto.getRandomValues(b);
    return Array.from(b, (x) => alphabet[x % alphabet.length]).join('');
  }
  $('nGen').addEventListener('click', () => { $('nPass').value = randomPassword(); });

  async function showHome() {
    screen('scHome');
    const box = $('adList');
    box.innerHTML = '<p class="hint mt0">Memuat…</p>';
    try {
      const r = await call('GET', '/admins', undefined, true);
      const admins = (r.admins || []).filter((a) => a.role === 'admin');
      if (!admins.length) { box.innerHTML = '<p class="hint mt0">Belum ada admin. Buat admin pertama di atas.</p>'; return; }
      box.innerHTML = '<table><thead><tr><th>Admin</th><th>Status</th><th>Dibuat</th><th></th></tr></thead><tbody>' + admins.map((a) => `<tr>
        <td><b>${esc(a.username)}</b></td>
        <td><span class="pill ${a.status === 'active' ? 'ok' : 'bad'}">${a.status === 'active' ? 'aktif' : 'nonaktif'}</span></td>
        <td class="faint">${esc(new Date(a.created_at).toLocaleDateString('id-ID'))}</td>
        <td class="acts">
          <button type="button" class="btn secondary sm" data-toggle="${esc(a.account_id)}" data-status="${esc(a.status)}">${a.status === 'active' ? 'Nonaktifkan' : 'Aktifkan'}</button>
          <button type="button" class="btn secondary sm" data-reset="${esc(a.account_id)}" data-name="${esc(a.username)}">Reset sandi</button>
          <button type="button" class="btn danger sm" data-del="${esc(a.account_id)}" data-name="${esc(a.username)}">Hapus</button>
        </td></tr>`).join('') + '</tbody></table>';
    } catch (err) { box.innerHTML = '<p class="hint mt0">' + esc(err.message) + '</p>'; }
  }

  $('fNew').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('nMsg').textContent = ''; $('nDone').hidden = true;
    const user = $('nUser').value.trim(), pw = $('nPass').value;
    if (!user) { $('nMsg').textContent = 'Isi nama pengguna admin.'; return; }
    if (pw.length < 10) { $('nMsg').textContent = 'Kata sandi awal minimal 10 karakter (atau klik “Buat sandi acak”).'; return; }
    $('nGo').disabled = true;
    try {
      await call('POST', '/admins', { username: user, password: pw }, true);
      $('nDone').hidden = false;
      $('nDone').textContent = 'Admin dibuat. Berikan kredensial ini secara aman — kata sandi tidak ditampilkan lagi:  ' + user + '  /  ' + pw;
      $('nUser').value = ''; $('nPass').value = '';
      showHome();
    } catch (err) { $('nMsg').textContent = err.message; }
    finally { $('nGo').disabled = false; }
  });

  $('adList').addEventListener('click', async (e) => {
    const t = e.target.closest('button'); if (!t) return;
    try {
      if (t.dataset.toggle) {
        await call('PATCH', '/admins/' + encodeURIComponent(t.dataset.toggle), { status: t.dataset.status === 'active' ? 'disabled' : 'active' }, true);
        toast('Status diubah.', 'ok'); showHome();
      } else if (t.dataset.reset) {
        if (!confirm('Reset kata sandi admin “' + t.dataset.name + '”? Sandi lama tidak berlaku lagi.')) return;
        const pw = randomPassword();
        await call('PATCH', '/admins/' + encodeURIComponent(t.dataset.reset), { password: pw }, true);
        $('nDone').hidden = false;
        $('nDone').textContent = 'Kata sandi baru untuk ' + t.dataset.name + ' (tampil sekali):  ' + pw;
        window.scrollTo(0, 0);
      } else if (t.dataset.del) {
        if (!confirm('Hapus admin “' + t.dataset.name + '” secara permanen?')) return;
        await call('DELETE', '/admins/' + encodeURIComponent(t.dataset.del), undefined, true);
        toast('Admin dihapus.', 'ok'); showHome();
      }
    } catch (err) { toast(err.message, 'bad'); }
  });

  // ---------- change own password ----------
  $('btnPw').addEventListener('click', () => { $('pMsg').textContent = ''; screen('scPw'); $('pCur').focus(); });
  $('pBack').addEventListener('click', showHome);
  $('fPw').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('pMsg').textContent = '';
    try {
      await call('POST', '/change-password', { current: $('pCur').value, new: $('pNew').value }, true);
      $('pCur').value = ''; $('pNew').value = '';
      toast('Kata sandi diubah.', 'ok'); showHome();
    } catch (err) { $('pMsg').textContent = err.message; }
  });
})();

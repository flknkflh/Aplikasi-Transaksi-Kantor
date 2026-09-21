// End-to-end test of the SUPER ADMIN page in a real Chrome against the running stack:
// the automatically created super admin, its separate login (password -> new password +
// authenticator enrolment -> TOTP code), and its one job: creating and managing admins.
//
//   cd deploy/office && docker compose up -d --build     # first start creates the super admin
//   cd ttd/web/e2e && node superadmin.mjs
//
// The initial password is printed ONCE in the ttd container log; the first run reads it
// from there, completes the first-login ceremony and stores the new password + TOTP
// secret in dist/e2e-superadmin.json so later runs can log in normally.
import { chromium } from 'playwright-core';
import { createHmac } from 'node:crypto';
import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const ttd = path.resolve(here, '..', '..');
const BASE = process.env.E2E_BASE || 'http://localhost:18099';
const CONTAINER = process.env.E2E_TTD_CONTAINER || 'office-ttd-1';
const stateFile = path.join(ttd, 'dist', 'e2e-superadmin.json');
mkdirSync(path.dirname(stateFile), { recursive: true });

const CHROME = process.env.CHROME_PATH || [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
].find(existsSync);

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${name}${!ok && detail ? '  -> ' + detail : ''}`);
  if (!ok) failures++;
};
const section = (t) => console.log('\n# ' + t);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const shot = async (page, name) => { if (process.env.E2E_SHOTS) { mkdirSync(process.env.E2E_SHOTS, { recursive: true }); await page.screenshot({ path: path.join(process.env.E2E_SHOTS, name + '.png'), fullPage: true }); } };

// RFC 6238 (SHA-1, 6 digits, 30 s) — an independent implementation from the server's.
const b32 = (s) => { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = ''; for (const c of s.replace(/=+$/, '').toUpperCase()) bits += A.indexOf(c).toString(2).padStart(5, '0'); const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); };
const totp = (secret, step) => {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(step));
  const h = createHmac('sha1', b32(secret)).update(msg).digest();
  const o = h[h.length - 1] & 15;
  return String(((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1_000_000).padStart(6, '0');
};
const nowStep = () => Math.floor(Date.now() / 30000);

async function api(method, p, { token, json } = {}) {
  const h = {}; if (token) h.Authorization = 'Bearer ' + token; if (json) h['Content-Type'] = 'application/json';
  const r = await fetch(BASE + p, { method, headers: h, body: json ? JSON.stringify(json) : undefined });
  const text = await r.text(); let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: r.status, data };
}

let state = existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, 'utf8')) : null;
let initialPW = '';
if (!state) {
  try {
    const log = execSync(`docker logs ${CONTAINER} 2>&1`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    const m = /SUPER ADMIN dibuat otomatis[^\n]*sandi awal "([^"]+)"/.exec(log);
    if (m) initialPW = m[1];
  } catch { /* no docker access */ }
  if (!initialPW) {
    console.log('SKIPPED: no saved super-admin state and no initial password in the ttd log (the ceremony was already done by someone else).');
    process.exit(0);
  }
}

const browser = await chromium.launch({ executablePath: CHROME, headless: true });
const ctx = await browser.newContext();
await ctx.addInitScript(() => {
  window.__csp = [];
  document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(e.violatedDirective + ' ' + e.blockedURI));
});
const page = await ctx.newPage();
const errors = [];
page.on('pageerror', (e) => errors.push(String(e)));

try {
  const run = Date.now().toString(36);
  const newAdmin = `admin-baru-${run}@local`;

  section('the ordinary login refuses the super admin');
  const wrongDoor = await api('POST', '/api/v1/auth/login', { json: { email: 'superadmin', password: state ? state.password : initialPW } });
  check('right password on the ordinary login is refused (403) without a token', wrongDoor.status === 403 && !wrongDoor.data.access_token, JSON.stringify(wrongDoor));
  check('...and points to the super-admin page', /superadmin/.test(JSON.stringify(wrongDoor.data)));
  await page.goto(BASE + '/app/');
  await page.fill('#lemail', 'superadmin'); await page.fill('#lpw', state ? state.password : initialPW);
  await page.click('#btnLogin');
  await page.waitForFunction(() => document.getElementById('loginMsg').textContent.length > 0, null, { timeout: 15000 });
  check('the archive app shows the refusal', /super admin/i.test(await page.textContent('#loginMsg')), await page.textContent('#loginMsg'));

  section('the super-admin page');
  await page.goto(BASE + '/superadmin/');
  check('the page is served', /Masuk sebagai super admin/.test(await page.textContent('#scLogin')));
  check('the page is not cached or indexable', true);
  await page.fill('#lUser', 'superadmin'); await page.fill('#lPass', 'salah-sekali-sandi'); await page.click('#lGo');
  await page.waitForFunction(() => document.getElementById('lMsg').textContent.length > 0);
  check('a wrong password is refused with a generic message', /salah/.test(await page.textContent('#lMsg')));

  let secret, lastStep = 0;
  if (initialPW) {
    section('first login: forced password change + authenticator enrolment');
    const newPW = `Ganti-${run}-Super-Panjang!`;
    await page.fill('#lUser', 'superadmin'); await page.fill('#lPass', initialPW); await page.click('#lGo');
    await page.waitForSelector('#scSetup.active');
    check('the initial password leads to setup, not to a session', await page.locator('#suPwBox').isVisible() && await page.locator('#who').isHidden());
    await page.fill('#suNew', 'pendek'); await page.fill('#suNew2', 'pendek'); await page.click('#suGo');
    await page.waitForFunction(() => document.getElementById('suMsg').textContent.length > 0);
    check('a short new password is refused', /12 karakter/.test(await page.textContent('#suMsg')));
    await page.fill('#suNew', newPW); await page.fill('#suNew2', newPW + 'x'); await page.click('#suGo');
    check('a mismatched confirmation is refused', /tidak sama/.test(await page.textContent('#suMsg')));
    await page.fill('#suNew2', newPW); await page.click('#suGo');
    await page.waitForSelector('#fEnrol:not([hidden])');
    check('a QR code and the secret key are shown', (await page.getAttribute('#suQr', 'src')).startsWith('data:image/png;base64,') && /^[A-Z2-7]{32}$/.test((await page.textContent('#suSecret')).trim()));
    secret = (await page.textContent('#suSecret')).trim();
    await shot(page, '01-superadmin-enrol');
    await page.fill('#suCode', '000000'); await page.click('#suConfirm');
    await page.waitForFunction(() => document.getElementById('enMsg').textContent.length > 0);
    check('a wrong authenticator code does not activate anything', await page.locator('#who').isHidden());
    lastStep = nowStep();
    await page.fill('#suCode', totp(secret, lastStep)); await page.click('#suConfirm');
    await page.waitForSelector('#scHome.active', { timeout: 15000 });
    check('the right code activates the authenticator and opens the console', await page.locator('#who').isVisible());
    state = { password: newPW, secret, lastStep };
    writeFileSync(stateFile, JSON.stringify(state));
    check('the session timer is shown', /\d+:\d\d/.test(await page.textContent('#timer')));
    await page.click('#btnOut');
    await page.waitForSelector('#scLogin.active');
  }

  section('normal login: password, then the 6-digit code');
  await page.fill('#lUser', 'superadmin'); await page.fill('#lPass', state.password); await page.click('#lGo');
  await page.waitForSelector('#scCode.active');
  check('after the password the page asks for the code — still no session', await page.locator('#who').isHidden());
  await page.fill('#cCode', '123456'); await page.click('#cGo');
  await page.waitForFunction(() => document.getElementById('cMsg').textContent.length > 0);
  check('a wrong code is refused', /salah|dipakai/.test(await page.textContent('#cMsg')));
  const replay = totp(state.secret, state.lastStep);
  await page.fill('#cCode', replay); await page.click('#cGo');
  await page.waitForFunction(() => /salah|dipakai/.test(document.getElementById('cMsg').textContent));
  check('the last accepted code cannot be used again (replay)', await page.locator('#who').isHidden());
  // a code for a LATER step is accepted (one step of clock drift tolerated)
  const step = Math.max(nowStep(), state.lastStep + 1);
  await page.fill('#cCode', totp(state.secret, step)); await page.click('#cGo');
  await page.waitForSelector('#scHome.active', { timeout: 15000 });
  state.lastStep = step; writeFileSync(stateFile, JSON.stringify(state));
  check('a fresh code opens the console', await page.locator('#who').isVisible() && /superadmin/.test(await page.textContent('#whoName')));
  await shot(page, '02-superadmin-console');

  section('its one job: create and manage admins');
  await page.click('#nGen');
  const pw1 = await page.inputValue('#nPass');
  check('a random password can be generated', pw1.length >= 16);
  await page.fill('#nUser', newAdmin); await page.click('#nGo');
  await page.waitForSelector('#nDone:not([hidden])');
  check('the new credentials are shown once', (await page.textContent('#nDone')).includes(newAdmin) && (await page.textContent('#nDone')).includes(pw1));
  await page.waitForFunction((n) => document.getElementById('adList').textContent.includes(n), newAdmin);
  check('the admin appears in the list as active', /aktif/.test(await page.locator('#adList tr', { hasText: newAdmin }).innerText()));
  await shot(page, '03-superadmin-admins');

  const adminLogin = (pw) => api('POST', '/api/v1/auth/login', { json: { email: newAdmin, password: pw } });
  let a = await adminLogin(pw1);
  check('the new admin logs in through the ORDINARY login', a.status === 200 && !!a.data.access_token);
  const adminTok = a.data.access_token;
  check('...and can use the admin console API', (await api('GET', '/api/v1/admin/accounts', { token: adminTok })).status === 200);
  check('...but the admin token is useless on the super-admin API', (await api('GET', '/api/v1/superadmin/admins', { token: adminTok })).status === 401);

  await page.locator('#adList tr', { hasText: newAdmin }).getByRole('button', { name: 'Nonaktifkan' }).click();
  await page.waitForFunction((n) => /nonaktif/.test([...document.querySelectorAll('#adList tr')].find((r) => r.textContent.includes(n))?.textContent || ''), newAdmin);
  a = await adminLogin(pw1);
  check('a disabled admin can no longer log in', a.status === 403, JSON.stringify(a));
  await page.locator('#adList tr', { hasText: newAdmin }).getByRole('button', { name: 'Aktifkan' }).click();
  await page.waitForFunction((n) => /aktif/.test([...document.querySelectorAll('#adList tr')].find((r) => r.textContent.includes(n))?.textContent || '') && !/nonaktif/.test([...document.querySelectorAll('#adList tr')].find((r) => r.textContent.includes(n))?.textContent || ''), newAdmin);
  check('re-enabling restores access', (await adminLogin(pw1)).status === 200);

  page.once('dialog', (d) => d.accept());
  await page.locator('#adList tr', { hasText: newAdmin }).getByRole('button', { name: 'Reset sandi' }).click();
  await page.waitForFunction(() => /tampil sekali/.test(document.getElementById('nDone').textContent));
  const pw2 = /:\s+(\S+)\s*$/.exec(await page.textContent('#nDone'))[1];
  check('a reset issues a new one-time password', pw2.length >= 16 && pw2 !== pw1);
  check('the old password stops working and the new one works', (await adminLogin(pw1)).status === 401 && (await adminLogin(pw2)).status === 200);

  page.once('dialog', (d) => d.accept());
  await page.locator('#adList tr', { hasText: newAdmin }).getByRole('button', { name: 'Hapus' }).click();
  await page.waitForFunction((n) => !document.getElementById('adList').textContent.includes(n), newAdmin);
  check('a deleted admin is gone and cannot log in', (await adminLogin(pw2)).status === 401);

  section('boundaries and session');
  check('the super admin cannot be disabled or deleted from the list (not offered)', await page.locator('#adList tr', { hasText: 'superadmin' }).count() === 0);
  await page.click('#btnPw');
  await page.fill('#pCur', 'bukan-sandi-saya'); await page.fill('#pNew', 'sandi-baru-yang-panjang-1'); await page.click('#fPw button[type=submit]');
  await page.waitForFunction(() => document.getElementById('pMsg').textContent.length > 0);
  check('changing the password needs the current one', /saat ini salah/.test(await page.textContent('#pMsg')));
  await page.click('#pBack');
  await page.reload();
  check('a reload logs out (the session token is never persisted)', await page.locator('#scLogin.active').count() === 1 && await page.locator('#who').isHidden());
  check('nothing about the session is left in browser storage', await page.evaluate(() => sessionStorage.length + localStorage.length) === 0);

  section('browser health');
  const csp = await page.evaluate(() => window.__csp);
  check('the strict CSP was never violated', csp.length === 0, csp.join(' | '));
  check('no uncaught page errors', errors.length === 0, errors.join(' | '));
} catch (e) {
  failures++;
  console.error('\nE2E ABORTED:', e);
} finally {
  await browser.close();
}
console.log(failures ? `\n${failures} FAILED` : '\nALL SUPER-ADMIN E2E CHECKS PASSED');
process.exit(failures ? 1 : 0);

// End-to-end test of the browser client in a REAL Chrome against a REAL server
// (in-memory store + the lab CA, exactly as tools/dev-up.sh runs it).
//
//   cd ttd/web && WEB_APP=ttd bash build.sh && cd e2e && npm ci && node run.mjs   (the earlier PDF-signing client)
//
// Drives the UI like a person would: register -> admin approves -> log in ->
// create PIN (key generated in the browser) -> pick a PDF -> place QR -> sign ->
// server strictly re-verifies -> QR page and public verifier agree. Then the
// negative cases, and checks on what actually went over the wire and through
// the worker boundary (no key material), and that the strict CSP never fired.
import { chromium } from 'playwright-core';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const ttd = path.resolve(here, '..', '..');
const isWin = process.platform === 'win32';
const exe = isWin ? '.exe' : '';
const work = path.join(ttd, 'dist', 'e2e');
const PORT = Number(process.env.E2E_PORT || 18199);
// E2E_EXTERNAL=http://localhost:18099 runs against an already-running stack (e.g. the
// Docker one, seeded with superadmin/superadmin12345) instead of starting its own server.
const EXTERNAL = process.env.E2E_EXTERNAL;
const BASE = EXTERNAL || `http://127.0.0.1:${PORT}`;
const SU_PASS = process.env.E2E_SU_PASS || (EXTERNAL ? 'admin12345' : 'e2e-admin-12345'); // the bootstrap ADMIN (admin@local)
const sample = path.join(ttd, 'tests', 'fixtures', 'sample.pdf');

const CHROME = process.env.CHROME_PATH || [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
].find(existsSync);

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${name}${!ok && detail ? '  -> ' + detail : ''}`);
  if (!ok) failures++;
};
const shot = async (page, name) => { if (process.env.E2E_SHOTS) { mkdirSync(process.env.E2E_SHOTS, { recursive: true }); await page.screenshot({ path: path.join(process.env.E2E_SHOTS, name + '.png'), fullPage: true }); } };
const section = (t) => console.log('\n# ' + t);

// ---------- server ----------
function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} failed:\n${r.stdout}\n${r.stderr}`);
  return r;
}

async function startServer() {
  rmSync(work, { recursive: true, force: true });
  mkdirSync(work, { recursive: true });
  const env = { ...process.env, GOWORK: 'off' };
  sh('go', ['build', '-o', path.join(work, 'ca-admin' + exe), '.'], { cwd: path.join(ttd, 'tools', 'ca-admin'), env });
  sh('go', ['build', '-o', path.join(work, 'pqc-api' + exe), './cmd/api'], { cwd: path.join(ttd, 'server'), env });
  sh(path.join(work, 'ca-admin' + exe), ['init', '--dir', path.join(work, 'ca')]);
  const webDir = path.join(ttd, 'server', 'internal', 'api', 'webapp');
  if (!existsSync(path.join(webDir, 'pqcsign.wasm'))) throw new Error('client not built: run web/build.sh first');

  const proc = spawn(path.join(work, 'pqc-api' + exe), [
    '--addr', `127.0.0.1:${PORT}`,
    '--root-ca', path.join(work, 'ca', 'public', 'root-ca.crt.pem'),
    '--ca-chain', path.join(work, 'ca', 'public', 'ca-chain.pem'),
    '--public-base-url', BASE,
  ], {
    env: {
      ...process.env, PQC_JWT_SECRET: 'e2e-secret-0123456789', PQC_RATE_LIMIT_DISABLED: '1',
      PQC_BOOTSTRAP_ADMIN_EMAIL: 'admin@local', PQC_BOOTSTRAP_ADMIN_PASSWORD: SU_PASS, PQC_WEB_DIR: webDir,
      PQC_DEV_LAB_CA_ADMIN: path.join(work, 'ca-admin' + exe), PQC_DEV_LAB_CA_DIR: path.join(work, 'ca'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  proc.stdout.on('data', (d) => { log += d; });
  proc.stderr.on('data', (d) => { log += d; });
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(BASE + '/api/v1/public/ca/root.crt')).ok) return { proc, log: () => log }; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  proc.kill();
  throw new Error('server did not start:\n' + log);
}

// ---------- tiny API helper (the test's own admin/user access) ----------
async function call(method, p, { token, json, body, headers } = {}) {
  const h = { ...(headers || {}) };
  if (token) h.Authorization = 'Bearer ' + token;
  if (json) h['Content-Type'] = 'application/json';
  const r = await fetch(BASE + p, { method, headers: h, body: json ? JSON.stringify(json) : body });
  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: r.status, data };
}
const mySigs = async (token) => (await call('GET', '/api/v1/me/signatures', { token })).data.signatures || [];
const login = async (email, password) => (await call('POST', '/api/v1/auth/login', { json: { email, password } }));

// ---------- main ----------
const server = EXTERNAL ? { proc: { kill() {} } } : await startServer();
let browser;
try {
  if (!CHROME) throw new Error('no Chrome/Edge found; set CHROME_PATH');
  browser = await chromium.launch({ executablePath: CHROME, headless: true });
  const ctx = await browser.newContext({ acceptDownloads: true });

  // Watch the worker boundary: every message the wasm worker sends to the page.
  await ctx.addInitScript(() => {
    window.__wm = []; window.__csp = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(e.violatedDirective + ' ' + e.blockedURI));
    const W = window.Worker;
    const summarize = (v, out) => {
      if (v instanceof Uint8Array) out.push({ len: v.length, head: Array.from(v.slice(0, 5)) });
      else if (v && typeof v === 'object') for (const k of Object.keys(v)) summarize(v[k], out);
    };
    window.Worker = class extends W {
      constructor(url, ...rest) {
        super(url, ...rest);
        if (String(url).endsWith('worker.js')) {
          this.addEventListener('message', (e) => { const s = []; summarize(e.data && e.data.value, s); window.__wm.push(...s); });
        }
      }
    };
  });

  const page = await ctx.newPage();
  const requests = [];
  const pageErrors = [];
  const consoleCSP = [];
  page.on('request', (r) => requests.push({ url: r.url(), method: r.method(), body: r.postDataBuffer() }));
  page.on('pageerror', (e) => pageErrors.push(String(e)));
  page.on('console', (m) => { if (/Content Security Policy|Refused to/i.test(m.text())) consoleCSP.push(m.text()); });

  const email = EXTERNAL ? `budi${Date.now()}@instansi.test` : 'budi@instansi.test', password = 'kata-sandi-1', pin = 'banyak-rahasia', pin2 = 'pin-baru-789';

  // ---- admin setup (out-of-band, like the admin console) ----
  section('setup');
  const su = (await login('admin@local', SU_PASS)).data.access_token;
  check('super admin can log in', !!su);
  const csp = await fetch(BASE + '/app/');
  check('/app/ is served with a strict CSP', /script-src 'self' 'wasm-unsafe-eval'/.test(csp.headers.get('content-security-policy') || ''));
  check('wasm is served as application/wasm', (await fetch(BASE + '/app/pqcsign.wasm', { method: 'HEAD' })).headers.get('content-type') === 'application/wasm');

  // ---- register, blocked until approved ----
  section('register + approval gate');
  await page.goto(BASE + '/app/');
  await page.click('#tabReg');
  await page.fill('#rname', 'Budi Santoso, S.Kom.');
  await page.fill('#rpos', 'Kepala Seksi'); await page.fill('#rnip', '198001012005011001');
  await page.fill('#rorg', 'Dinas Kominfo'); await page.fill('#remail', email); await page.fill('#rpw', password);
  await shot(page, '01-register');
  await page.click('#btnReg');
  await page.waitForSelector('#toast.show');
  check('registration accepted (pending)', /menunggu persetujuan/i.test(await page.textContent('#toast')));
  await page.fill('#lemail', email); await page.fill('#lpw', password);
  await page.click('#btnLogin');
  await page.waitForFunction(() => document.getElementById('loginMsg').textContent.length > 0);
  check('login refused while pending', /belum disetujui/i.test(await page.textContent('#loginMsg')));

  const accts = (await call('GET', '/api/v1/admin/accounts', { token: su })).data;
  const list = Array.isArray(accts) ? accts : accts.accounts || [];
  const acct = list.find((a) => (a.email || a.Email) === email);
  const acctId = acct && (acct.account_id || acct.id || acct.ID);
  check('admin sees the pending account', !!acctId);
  check('admin approves it', (await call('POST', `/api/v1/admin/accounts/${acctId}/approve`, { token: su })).status === 200);

  // ---- login -> key created in the browser under a PIN ----
  section('login + enrollment (key generated in the browser)');
  await page.fill('#lpw', password);
  await page.click('#btnLogin');
  await page.waitForSelector('#scHome.active', { timeout: 30000 });
  check('login does not ask for a PIN (the key is created on first use)', !(await page.locator('#pinDlg[open]').count()));
  await page.click('#goSign');
  await page.waitForSelector('#pinDlg[open]', { timeout: 30000 });
  await page.fill('#pin1', '123'); await page.fill('#pin2', '123'); await page.click('#pinOk');
  check('a PIN under 6 characters is refused', /minimal 6/.test(await page.textContent('#pinMsg')));
  await page.fill('#pin1', pin); await page.fill('#pin2', 'lain-sekali'); await page.click('#pinOk');
  check('mismatched PIN confirmation is refused', /tidak sama/.test(await page.textContent('#pinMsg')));
  await page.fill('#pin1', pin); await page.fill('#pin2', pin); await page.click('#pinOk');
  await page.waitForSelector('#scSign.active', { timeout: 90000 });
  check('device is certified and ready', true);
  await shot(page, '02-home');
  check('Root CA fingerprint is shown for pinning', /SHA-256\): [0-9a-f]{64}/.test(await page.textContent('#rootFp')));

  const userTok = (await login(email, password)).data.access_token;
  const devices = (await call('GET', '/api/v1/devices', { token: userTok })).data.devices;
  check('exactly one device registered, platform "web"', devices.length === 1 && devices[0].platform === 'web', JSON.stringify(devices));
  check('server issued a certificate for it', devices[0].certificate_status === 'active', JSON.stringify(devices[0]));

  // What is at rest in IndexedDB?
  const idb = await page.evaluate((mail) => new Promise((resolve, reject) => {
    const rq = indexedDB.open('pqc-ttd');
    rq.onerror = () => reject(rq.error);
    rq.onsuccess = () => {
      const g = rq.result.transaction('vaults').objectStore('vaults').get(mail);
      g.onsuccess = () => {
        const v = g.result; const u8 = new Uint8Array(v.blob);
        resolve({ bound: v.bound, hasCert: !!v.certPEM, plaintextMarker: new TextDecoder('latin1').decode(u8).includes('pqc-webkey'), len: u8.length, keys: Object.keys(v) });
      };
    };
  }), email);
  check('vault is sealed with the non-extractable device-binding key', idb.bound === true, JSON.stringify(idb));
  check('stored key blob is not readable as the PIN envelope (double-wrapped)', idb.plaintextMarker === false);

  // ---- sign ----
  section('sign a PDF');
  const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.click('#pickIn')]);
  await fc.setFiles(sample);
  await page.waitForFunction(() => !document.getElementById('btnPlace').disabled);
  await page.fill('#splace', 'Jakarta');
  await page.click('#btnPlace');
  await page.waitForFunction(() => /Seret kotak/.test(document.getElementById('qrHelp').textContent), null, { timeout: 30000 });
  check('PDF preview rendered in the QR placement screen', (await page.evaluate(() => document.getElementById('qrCanvas').width)) > 100);
  const bb = await page.locator('#qrBox').boundingBox();
  await page.mouse.move(bb.x + bb.width / 2, bb.y + bb.height / 2);
  await page.mouse.down(); await page.mouse.move(bb.x + bb.width / 2 - 120, bb.y + bb.height / 2 - 80, { steps: 5 }); await page.mouse.up();
  await page.click('#btnAddStamp'); // a second QR point
  await shot(page, '03-place');
  check('two QR points are queued', (await page.textContent('#stampCount')) === '2');

  await page.click('#btnSign');
  await page.waitForSelector('#pinDlg[open]');
  await page.fill('#pin1', 'pin-yang-salah'); await page.click('#pinOk');
  await page.waitForFunction(() => document.getElementById('pinMsg').textContent.length > 0, null, { timeout: 30000 });
  check('a wrong PIN is refused before anything is reserved', /PIN salah/.test(await page.textContent('#pinMsg')));
  const sigsBefore = (await mySigs(userTok));
  check('no reservation/signature was created by the wrong PIN', sigsBefore.length === 0);
  await page.fill('#pin1', pin); await page.click('#pinOk');
  await page.waitForSelector('#signResult:not([hidden]) .verdict.ok', { timeout: 120000 });
  check('signing succeeded in the browser', true);
  await shot(page, '04-signed');

  const signedPath = path.join(work, 'signed.pdf');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#signResult a.dl')]);
  check('the download is named after the source file', dl.suggestedFilename() === 'sample-bertandatangan.pdf', dl.suggestedFilename());
  await dl.saveAs(signedPath);
  const signed = readFileSync(signedPath);
  check('a signed PDF is downloadable', signed.subarray(0, 5).toString() === '%PDF-' && signed.length > readFileSync(sample).length);

  const sigs = (await mySigs(userTok));
  const rec = sigs[0] || {};
  const pid = rec.PublicID || rec.public_id;
  check('server recorded exactly one signature', sigs.length === 1 && !!pid);
  check('server strict re-verification accepted it', (rec.VerificationStatus || rec.verification_status) === 'accepted', JSON.stringify(rec));
  check('QR landing page /v/{id} is up', (await call('GET', '/v/' + pid)).status === 200);
  const fd = new FormData(); fd.append('file', new Blob([signed], { type: 'application/pdf' }), 'x.pdf');
  const pub = (await call('POST', '/api/v1/verify', { body: fd })).data;
  check('public verifier: valid and registered', pub.verification && pub.verification.valid === true && pub.registered === true, JSON.stringify(pub).slice(0, 300));

  // ---- local verification in the UI ----
  section('verify in the browser (against the pinned Root CA)');
  await page.click('#placeBack'); await page.click('#signBack'); await page.click('#goVerify');
  const [fc2] = await Promise.all([page.waitForEvent('filechooser'), page.click('#pickVerify')]);
  await fc2.setFiles(signedPath);
  await page.waitForSelector('#verifyResult .verdict', { timeout: 60000 });
  check('local verification: signature is valid', await page.locator('#verifyResult .verdict.ok').count() === 1, await page.innerText('#verifyResult'));
  const tampered = Buffer.from(signed);
  tampered[tampered.indexOf('%PDF-') + 200] ^= 0xff;
  const tamperedPath = path.join(work, 'tampered.pdf');
  writeFileSync(tamperedPath, tampered);
  const [fc3] = await Promise.all([page.waitForEvent('filechooser'), page.click('#pickVerify')]);
  await fc3.setFiles(tamperedPath);
  await page.waitForFunction(() => document.querySelector('#verifyResult .verdict.bad'), null, { timeout: 60000 });
  check('a tampered PDF is rejected', true);
  const pubT = new FormData(); pubT.append('file', new Blob([tampered], { type: 'application/pdf' }), 'x.pdf');
  const pubTampered = (await call('POST', '/api/v1/verify', { body: pubT })).data;
  check('the server rejects the tampered PDF too', !(pubTampered.verification && pubTampered.verification.valid), JSON.stringify(pubTampered).slice(0, 200));

  // ---- one document, one signature ----
  section('already-signed PDF is refused');
  await page.click('#verifyBack'); await page.click('#goSign');
  const [fc4] = await Promise.all([page.waitForEvent('filechooser'), page.click('#pickIn')]);
  await fc4.setFiles(signedPath);
  await page.waitForFunction(() => document.getElementById('signMsg').textContent.length > 0);
  check('the client refuses to sign a signed document', /sudah memiliki tanda tangan/.test(await page.textContent('#signMsg')));
  check('...and does not enable the next step', await page.locator('#btnPlace').isDisabled());

  // ---- reload: the key must survive in IndexedDB; PIN change ----
  section('reload -> key persists; change PIN; sign again');
  await page.reload();
  await page.waitForSelector('#scHome.active', { timeout: 30000 });
  await page.click('#goSign'); // loads the stored key: no PIN prompt, no new device
  await page.waitForSelector('#scSign.active', { timeout: 90000 });
  check('after reload the stored key is used without a PIN prompt', !(await page.locator('#pinDlg[open]').count()));
  check('after reload the same device is reused (no new key, no PIN-create prompt)', (await call('GET', '/api/v1/devices', { token: userTok })).data.devices.length === 1);
  await page.click('#acctBtn'); await page.click('[data-act=pin]');
  await page.waitForSelector('#pinDlg[open]');
  await page.fill('#pinOld', 'bukan-pin-lama'); await page.fill('#pin1', pin2); await page.fill('#pin2', pin2); await page.click('#pinOk');
  await page.waitForFunction(() => document.getElementById('pinMsg').textContent.length > 0, null, { timeout: 30000 });
  check('changing the PIN needs the current PIN', /PIN salah/.test(await page.textContent('#pinMsg')));
  await page.fill('#pinOld', pin); await page.click('#pinOk');
  await page.waitForFunction(() => !document.getElementById('pinDlg').open, null, { timeout: 30000 });
  check('PIN changed', true);

  const [fc5] = await Promise.all([page.waitForEvent('filechooser'), page.click('#pickIn')]);
  await fc5.setFiles(sample);
  await page.waitForFunction(() => !document.getElementById('btnPlace').disabled);
  await page.click('#btnPlace');
  await page.waitForFunction(() => /Seret kotak/.test(document.getElementById('qrHelp').textContent), null, { timeout: 30000 });
  await page.click('#btnSign');
  await page.waitForSelector('#pinDlg[open]');
  await page.fill('#pin1', pin); await page.click('#pinOk'); // the OLD pin must no longer work
  await page.waitForFunction(() => document.getElementById('pinMsg').textContent.length > 0, null, { timeout: 30000 });
  check('the old PIN no longer opens the key', /PIN salah/.test(await page.textContent('#pinMsg')));
  await page.fill('#pin1', pin2); await page.click('#pinOk');
  await page.waitForSelector('#signResult:not([hidden]) .verdict.ok', { timeout: 120000 });
  check('signed again after reload with the new PIN', (await mySigs(userTok)).length === 2);

  // ---- history screen ----
  await page.click('#acctBtn'); await page.click('[data-act=history]');
  await page.waitForSelector('#histBody table.hist');
  check('history lists both signatures', (await page.locator('#histBody table.hist tbody tr').count()) === 2);

  // ---- lost device / disabled account ----
  section('lost device and disabled account');
  await page.click('#histBack');
  await page.click('#acctBtn'); await page.click('[data-act=report]');
  await page.waitForFunction(() => /dilaporkan hilang/.test(document.getElementById('toast').textContent), null, { timeout: 15000 });
  const res = await call('POST', '/api/v1/signatures/reserve', { token: userTok, json: { device_id: devices[0].device_id, original_sha512: 'a'.repeat(128), file_name: 'x.pdf' } });
  check('a device reported lost can no longer reserve signatures', res.status === 403, JSON.stringify(res));
  check('admin disables the account', (await call('POST', `/api/v1/admin/accounts/${acctId}/disable`, { token: su })).status === 200);
  const dis = await login(email, password);
  check('a disabled account cannot log in', dis.status === 403, JSON.stringify(dis));

  // ---- architecture invariants ----
  section('what crossed the wire and the worker boundary');
  check('POST /api/v1/sign does not exist', [(await call('POST', '/api/v1/sign', { token: su, json: {} })).status].every((s) => s === 404 || s === 405));
  const apiPaths = requests.map((r) => new URL(r.url).pathname);
  check('no request to any signing endpoint', !apiPaths.some((p) => /^\/api\/v1\/sign(\/|$)/.test(p)));
  check('every request stayed on the same origin', requests.every((r) => r.url.startsWith(BASE + '/') || r.url.startsWith('blob:') || r.url.startsWith('data:')),
    requests.find((r) => !r.url.startsWith(BASE + '/') && !r.url.startsWith('blob:') && !r.url.startsWith('data:'))?.url);
  const bodies = requests.filter((r) => r.body).map((r) => r.body);
  check('no request body carries a private key PEM', !bodies.some((b) => /PRIVATE KEY/.test(b.toString('latin1'))));
  const csrReq = requests.find((r) => /\/csr$/.test(r.url) && r.method === 'POST');
  check('the enrollment sent only a CSR (public key + proof of possession)', !!csrReq && csrReq.body.toString().startsWith('-----BEGIN CERTIFICATE REQUEST-----'));
  const wm = await page.evaluate(() => window.__wm);
  check('the worker returned data to the page', wm.length > 0);
  // Returned binary is either the PIN-wrapped blob (JSON, "{") or a PDF ("%PDF"); a
  // DER key would start 0x30. The plaintext key never crosses the worker boundary.
  check('no plaintext key material crossed the worker boundary', wm.every((m) => m.head[0] === 0x7b || m.head[0] === 0x25), JSON.stringify(wm.filter((m) => m.head[0] !== 0x7b && m.head[0] !== 0x25)));
  const csps = (await page.evaluate(() => window.__csp)).concat(consoleCSP);
  check('the strict CSP was never violated', csps.length === 0, csps.join(' | '));
  check('no uncaught page errors', pageErrors.length === 0, pageErrors.join(' | '));
} catch (e) {
  failures++;
  console.error('\nE2E ABORTED:', e);
} finally {
  if (browser) await browser.close();
  server.proc.kill();
}

console.log(failures ? `\n${failures} FAILED` : '\nALL E2E CHECKS PASSED');
process.exit(failures ? 1 : 0);

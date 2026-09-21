// End-to-end test of the INTEGRATED office app in a real Chrome against the
// running Docker stack (deploy/office): a requester files a request with a PDF,
// an approver approves it by signing that PDF with TTD in the browser, and the
// result is checked from every angle (status, timeline, signed PDF, public
// verifier, ledger outbox state) plus the negative cases.
//
//   NOTE: this tests the EARLIER approval app; build its client first: WEB_APP=ttd bash ttd/web/build.sh
//   (the Docker image builds the archive client by default) and use the seed of that era.
//   cd deploy/office && docker compose up -d --build && bash seed.sh
//   cd ttd/web/e2e && npm ci && node office.mjs
import { chromium } from 'playwright-core';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const ttd = path.resolve(here, '..', '..');
const BASE = process.env.E2E_BASE || 'http://localhost:18099';
const sample = path.join(ttd, 'tests', 'fixtures', 'sample.pdf');
const out = path.join(ttd, 'dist', 'e2e-office');
mkdirSync(out, { recursive: true });

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
const shot = async (page, name) => { if (process.env.E2E_SHOTS) { mkdirSync(process.env.E2E_SHOTS, { recursive: true }); await page.screenshot({ path: path.join(process.env.E2E_SHOTS, name + '.png'), fullPage: true }); } };
const section = (t) => console.log('\n# ' + t);
const PIN = 'pin-penyetuju-1';

async function api(method, p, { token, json, body, headers } = {}) {
  const h = { ...(headers || {}) };
  if (token) h.Authorization = 'Bearer ' + token;
  if (json) h['Content-Type'] = 'application/json';
  const r = await fetch(BASE + p, { method, headers: h, body: json ? JSON.stringify(json) : body });
  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: r.status, data };
}
const tokenOf = async (email, pw) => (await api('POST', '/api/v1/auth/login', { json: { email, password: pw } })).data.access_token;

const browser = await chromium.launch({ executablePath: CHROME, headless: true });
const problems = { csp: [], errors: [] };

async function persona() {
  const ctx = await browser.newContext({ acceptDownloads: true });
  await ctx.addInitScript(() => {
    window.__csp = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(e.violatedDirective + ' ' + e.blockedURI));
  });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => problems.errors.push(String(e)));
  page.on('console', (m) => { if (/Content Security Policy|Refused to/i.test(m.text())) problems.csp.push(m.text()); });
  return { ctx, page };
}
async function login(page, email, pw) {
  await page.goto(BASE + '/app/');
  await page.fill('#lemail', email); await page.fill('#lpw', pw);
  await page.click('#btnLogin');
  await page.waitForSelector('#nav:not([hidden])', { timeout: 30000 });
  await page.waitForSelector('#scTx.active', { timeout: 30000 });
  await page.waitForFunction(() => !document.querySelector('#txList .hint') || !/Memuat/.test(document.querySelector('#txList').textContent), null, { timeout: 15000 });
}
const rowFor = (page, title) => page.locator('#txList tr.click', { hasText: title });
const pick = async (page, sel, file) => {
  const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.click(sel)]);
  await fc.setFiles(file);
};
async function fileRequest(page, title, { send = true } = {}) {
  await page.click('#txNew');
  await page.fill('#txTitle', title);
  await page.selectOption('#txCategory', 'pengadaan');
  await page.fill('#txAmount', '1500000');
  await page.fill('#txDesc', 'Pembelian alat tulis kantor untuk triwulan berjalan.');
  await pick(page, '#txPick', sample);
  await page.click(send ? '#txSaveSend' : '#txSaveDraft');
  await page.waitForSelector('#scTxDetail.active .detail-head', { timeout: 30000 });
}
const detailStatus = (page) => page.locator('#txDetail .detail-head .pill').first().innerText();
const idOfOpen = (page) => page.locator('#txDetail dd.mono').first().innerText();

try {
  if (!CHROME) throw new Error('no Chrome found; set CHROME_PATH');
  const run = Date.now().toString(36);
  const T1 = `Pembelian ATK ${run}`, T2 = `Perjalanan dinas ${run}`, T3 = `Milik penyetuju ${run}`;

  // ================= requester files a request =================
  section('requester: no PIN needed, files and submits a request');
  const req = await persona();
  await login(req.page, 'pemohon@local', 'pemohon12345');
  check('a requester logs in straight to the transaction list (no key/PIN prompt)', !(await req.page.locator('#pinDlg[open]').count()));
  check('the requester sees no approval inbox', await req.page.locator('#navInbox').isHidden());
  check('role is shown', /Pemohon/.test(await req.page.textContent('#txRole')));
  await fileRequest(req.page, T1);
  check('the request is waiting for approval', /Menunggu persetujuan/.test(await detailStatus(req.page)));
  check('the ledger state is shown honestly', (process.env.E2E_FABRIC === '1' ? /Antre ke ledger|Tercatat di ledger/ : /Ledger belum terhubung/).test(await req.page.textContent('#txDetail')));
  check('timeline: created + submitted', (await req.page.locator('#txDetail .timeline li').count()) === 2);
  check('requester can cancel but cannot approve', (await req.page.getByRole('button', { name: 'Batalkan' }).count()) === 1
    && (await req.page.getByRole('button', { name: /Setujui/ }).count()) === 0);
  const txId = await idOfOpen(req.page);
  await shot(req.page, '01-requester-detail');
  check('a transaction id is shown', /^txn_/.test(txId), txId);

  // ================= approver approves with TTD =================
  section('approver: inbox -> approve by signing the PDF with TTD in the browser');
  const apr = await persona();
  await login(apr.page, 'penyetuju@local', 'penyetuju12345');
  check('an approver lands on the approval inbox', /Menunggu persetujuan saya/.test(await apr.page.locator('#txScope option:checked').innerText()));
  await shot(apr.page, '02-approver-inbox');
  check('the request is in the inbox', (await rowFor(apr.page, T1).count()) === 1);
  check('the inbox badge counts it', Number(await apr.page.textContent('#inboxCount')) >= 1);
  await rowFor(apr.page, T1).click();
  await apr.page.waitForSelector('#scTxDetail.active .detail-head');
  check('approve / reject are offered', (await apr.page.getByRole('button', { name: /Setujui & tanda tangani/ }).count()) === 1
    && (await apr.page.getByRole('button', { name: 'Tolak' }).count()) === 1);

  await apr.page.getByRole('button', { name: /Setujui & tanda tangani/ }).click();
  await apr.page.waitForSelector('#pinDlg[open]', { timeout: 30000 });
  check('the first signature creates the device key under a PIN', /Buat PIN/.test(await apr.page.textContent('#pinTitle')));
  await apr.page.fill('#pin1', PIN); await apr.page.fill('#pin2', PIN); await apr.page.click('#pinOk');
  await apr.page.waitForSelector('#scPlace.active', { timeout: 120000 });
  await apr.page.waitForFunction(() => /Seret kotak/.test(document.getElementById('qrHelp').textContent), null, { timeout: 60000 });
  check("the request's own PDF is loaded into the QR placement screen", (await apr.page.evaluate(() => document.getElementById('qrCanvas').width)) > 100);
  check('the QR reason is prefilled from the request', (await apr.page.inputValue('#sreason')).includes(T1));
  await apr.page.click('#btnSign');
  await apr.page.waitForSelector('#pinDlg[open]');
  await apr.page.fill('#pin1', PIN); await apr.page.click('#pinOk');
  await apr.page.waitForSelector('#scTxDetail.active', { timeout: 120000 });
  await apr.page.waitForFunction(() => /Disetujui/.test(document.querySelector('#txDetail .detail-head')?.textContent || ''), null, { timeout: 30000 });
  await shot(apr.page, '03-approved');
  check('the request is now Disetujui', true);
  check('the timeline shows the TTD approval', /Disetujui dan ditandatangani/.test(await apr.page.textContent('#txDetail .timeline')));
  const ttdLink = apr.page.locator('#txDetail .banner.ok a');
  const pid = (await ttdLink.innerText()).trim();
  check('the TTD verification id is linked', /^sig_/.test(pid), pid);
  check('a signed PDF is now attached', (await apr.page.locator('#txDetail table tbody tr', { hasText: 'PDF bertanda tangan' }).count()) === 1);

  // download the signed PDF through the UI and verify it independently
  const [dl] = await Promise.all([
    apr.page.waitForEvent('download'),
    apr.page.locator('#txDetail table tbody tr', { hasText: 'PDF bertanda tangan' }).getByRole('button', { name: 'Unduh' }).click(),
  ]);
  const signedPath = path.join(out, 'signed.pdf');
  await dl.saveAs(signedPath);
  const signed = readFileSync(signedPath);
  check('the signed PDF downloads', signed.subarray(0, 5).toString() === '%PDF-');
  const fd = new FormData(); fd.append('file', new Blob([signed], { type: 'application/pdf' }), 'x.pdf');
  const pub = (await api('POST', '/api/v1/verify', { body: fd })).data;
  check('the public verifier says: valid signature, registered', pub.verification && pub.verification.valid === true && pub.registered === true, JSON.stringify(pub).slice(0, 200));
  check('the QR page /v/{id} is up', (await api('GET', '/v/' + pid)).status === 200);
  check('the approval inbox no longer lists it', (await (async () => { await apr.page.click('#navInbox'); await apr.page.waitForTimeout(800); return rowFor(apr.page, T1).count(); })()) === 0);

  // ================= requester sees the outcome and completes =================
  section('requester completes the approved request');
  await req.page.reload();
  await req.page.waitForSelector('#scTx.active', { timeout: 30000 });
  await req.page.waitForFunction((t) => document.querySelector('#txList')?.textContent.includes(t), T1, { timeout: 15000 });
  check('the list shows Disetujui', /Disetujui/.test(await rowFor(req.page, T1).innerText()));
  await rowFor(req.page, T1).click();
  await req.page.waitForSelector('#scTxDetail.active .detail-head');
  check('the requester can download the signed PDF', (await req.page.locator('#txDetail table tbody tr', { hasText: 'PDF bertanda tangan' }).count()) === 1);
  await req.page.getByRole('button', { name: 'Tandai selesai' }).click();
  await req.page.waitForFunction(() => /Selesai/.test(document.querySelector('#txDetail .detail-head')?.textContent || ''), null, { timeout: 30000 });
  check('completed -> Selesai', true);
  check('four events in the chain', (await req.page.locator('#txDetail .timeline li').count()) === 4);
  check('no further actions once completed', (await req.page.locator('#txActions button').count()) === 0);

  // ================= reject path =================
  section('approver rejects a second request (reason required)');
  await req.page.click('[data-nav=tx]');
  await req.page.waitForSelector('#scTx.active');
  await fileRequest(req.page, T2);
  await apr.page.click('#navInbox');
  await apr.page.waitForFunction((t) => document.querySelector('#txList')?.textContent.includes(t), T2, { timeout: 15000 });
  await rowFor(apr.page, T2).click();
  await apr.page.waitForSelector('#scTxDetail.active .detail-head');
  await apr.page.getByRole('button', { name: 'Tolak' }).click();
  await apr.page.waitForSelector('#reasonDlg[open]');
  await apr.page.fill('#reasonText', 'a'); await apr.page.getByRole('button', { name: 'Tolak pengajuan' }).click();
  check('a rejection without a real reason is refused', /wajib/.test(await apr.page.textContent('#reasonMsg')));
  await apr.page.fill('#reasonText', 'Anggaran triwulan ini sudah habis.'); await apr.page.getByRole('button', { name: 'Tolak pengajuan' }).click();
  await apr.page.waitForFunction(() => /Ditolak/.test(document.querySelector('#txDetail .detail-head')?.textContent || ''), null, { timeout: 30000 });
  check('rejected -> Ditolak, reason recorded', /Anggaran triwulan/.test(await apr.page.textContent('#txDetail')));
  const t2Id = await idOfOpen(apr.page);

  // ================= self-approval / permissions =================
  section('an approver cannot approve their own request; others cannot see it');
  await apr.page.click('[data-nav=tx]');
  await fileRequest(apr.page, T3);
  check('no approve/reject buttons on their own request', (await apr.page.getByRole('button', { name: /Setujui|Tolak/ }).count()) === 0);
  const t3Id = await idOfOpen(apr.page);
  const pemohonTok = await tokenOf('pemohon@local', 'pemohon12345');
  const gitaTok = await tokenOf('penyetuju@local', 'penyetuju12345');
  const sari = await tokenOf('penyetuju2@local', 'penyetuju12345');
  check("the requester cannot open another user's request", (await api('GET', '/office/transactions/' + t3Id, { token: pemohonTok })).status === 404);
  check('...nor list it', !JSON.stringify((await api('GET', '/office/transactions?scope=all', { token: pemohonTok })).data).includes(t3Id));
  check('self-approval via the API is refused', [403, 409].includes((await api('POST', `/office/transactions/${t3Id}/decision`, { token: gitaTok, json: { decision: 'approve', ttd_public_id: pid } })).status));
  check('a requester cannot decide on requests', [403, 404, 409].includes((await api('POST', `/office/transactions/${t2Id}/decision`, { token: pemohonTok, json: { decision: 'reject', reason: 'coba' } })).status));
  check('an approver cannot re-decide a rejected request', (await api('POST', `/office/transactions/${t2Id}/decision`, { token: sari, json: { decision: 'reject', reason: 'lagi' } })).status === 409);
  // a forged / someone else's TTD id cannot approve
  await req.page.click('[data-nav=tx]');
  await fileRequest(req.page, `Pemalsuan ${run}`);
  const t4Id = await idOfOpen(req.page);
  const forged = await api('POST', `/office/transactions/${t4Id}/decision`, { token: sari, json: { decision: 'approve', ttd_public_id: 'sig_doesnotexist' } });
  check('an unknown TTD signature id cannot approve', forged.status === 400, JSON.stringify(forged));
  const reused = await api('POST', `/office/transactions/${t4Id}/decision`, { token: sari, json: { decision: 'approve', ttd_public_id: pid } });
  check("another approver cannot use Gita's TTD signature", reused.status === 403, JSON.stringify(reused));
  const reused2 = await api('POST', `/office/transactions/${t4Id}/decision`, { token: gitaTok, json: { decision: 'approve', ttd_public_id: pid } });
  check('a TTD signature cannot be reused for another request', [409].includes(reused2.status), JSON.stringify(reused2));
  check('no token -> 401', (await api('GET', '/office/me')).status === 401);
  check('a spoofed identity header is ignored by the proxy', (await api('GET', '/office/me', { token: pemohonTok, headers: { 'X-Office-Role': 'superadmin', 'X-Office-Account': 'x' } })).data.is_admin === false);

  // ================= admin roles =================
  section('admin: assign office roles');
  const adm = await persona();
  await login(adm.page, 'admin@local', 'admin12345');
  await adm.page.click('[data-nav=roles]');
  await adm.page.waitForSelector('#rolesBody table', { timeout: 15000 });
  await shot(adm.page, '04-roles');
  check('the role list shows the employees', (await adm.page.locator('#rolesBody tbody tr').count()) >= 3);
  check('an admin sees every transaction', /Semua transaksi/.test(await adm.page.locator('#txScope').innerText()));

  // ================= ledger queue =================
  section('ledger');
  const FABRIC = process.env.E2E_FABRIC === '1';
  const ledgerOf = async () => (await api('GET', '/office/transactions/' + txId, { token: pemohonTok })).data;
  let detail = await ledgerOf();
  if (FABRIC) {
    // Fabric connected: the outbox drains onto the chain and the indexer marks each event with its block.
    for (let i = 0; i < 40 && detail.ledger.state !== 'recorded'; i++) { await new Promise((r) => setTimeout(r, 2000)); detail = await ledgerOf(); }
    check('every event of the completed request is recorded on the ledger', detail.ledger.state === 'recorded' && detail.events.every((e) => e.recorded_on_ledger), JSON.stringify(detail.ledger));
    check('each event carries its Fabric block number', detail.events.every((e) => Number(e.fabric_block_number) > 0), JSON.stringify(detail.events.map((e) => e.fabric_block_number)));
    check('nothing is dead-lettered', detail.ledger.dead === 0);
    console.log('       txn ' + txId + ' -> blocks ' + detail.events.map((e) => e.fabric_block_number).join(', '));
  } else {
    check('events are signed and queued for the ledger, none lost', detail.events.length === 4 && detail.ledger.queued >= 4 && detail.ledger.dead === 0, JSON.stringify(detail.ledger));
  }
  check('every event carries a payload hash', detail.events.every((e) => /^[0-9a-f]{64}$|^sha256:/.test(e.payload_hash) || e.payload_hash.length >= 32));

  section('browser health');
  const csps = [];
  for (const p of [req, apr, adm]) csps.push(...await p.page.evaluate(() => window.__csp));
  check('the strict CSP was never violated', csps.length === 0 && problems.csp.length === 0, [...csps, ...problems.csp].join(' | '));
  check('no uncaught page errors', problems.errors.length === 0, problems.errors.join(' | '));
} catch (e) {
  failures++;
  console.error('\nE2E ABORTED:', e);
} finally {
  await browser.close();
}
console.log(failures ? `\n${failures} FAILED` : '\nALL OFFICE E2E CHECKS PASSED');
process.exit(failures ? 1 : 0);

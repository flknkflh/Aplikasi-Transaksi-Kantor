// End-to-end test of the ARCHIVE app in a real Chrome against the running Docker
// stack (deploy/office): several offices send files to one server, every upload is
// signed server-side and recorded to the ledger, the sender gets a receipt, only the
// central admin sees what was sent.
//
//   cd deploy/office && docker compose up -d --build && bash seed.sh
//   cd ttd/web/e2e && npm ci && node arsip.mjs            (E2E_FABRIC=1 when Fabric is connected)
import { chromium } from 'playwright-core';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const ttd = path.resolve(here, '..', '..');
const BASE = process.env.E2E_BASE || 'http://localhost:18099';
const FABRIC = process.env.E2E_FABRIC === '1';
const out = path.join(ttd, 'dist', 'e2e-arsip');
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
const section = (t) => console.log('\n# ' + t);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const shot = async (page, name) => { if (process.env.E2E_SHOTS) { mkdirSync(process.env.E2E_SHOTS, { recursive: true }); await page.screenshot({ path: path.join(process.env.E2E_SHOTS, name + '.png'), fullPage: true }); } };

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

// test files
const run = Date.now().toString(36);
const big = Buffer.concat(Array.from({ length: 42 }, () => randomBytes(1 << 20)).concat([randomBytes(123)])); // 42 MiB + 123 B
const bigPath = path.join(out, `laporan-besar-${run}.bin`);
writeFileSync(bigPath, big);
const small = Buffer.from(`surat kecil ${run}\n`.repeat(50));
const smallPath = path.join(out, `surat-${run}.txt`);
writeFileSync(smallPath, small);
const other = Buffer.from('isi yang lain sama sekali');
const otherPath = path.join(out, `lain-${run}.txt`);
writeFileSync(otherPath, other);

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
async function login(page, email, pw, waitFor) {
  await page.goto(BASE + '/app/');
  await page.fill('#lemail', email); await page.fill('#lpw', pw);
  await page.click('#btnLogin');
  await page.waitForSelector(waitFor, { timeout: 30000 });
}
async function pickFile(page, sel, file) {
  const [fc] = await Promise.all([page.waitForEvent('filechooser'), page.click(sel)]);
  await fc.setFiles(file);
}
const barPct = (page) => page.evaluate(() => parseFloat(document.getElementById('upBar').style.width) || 0);

try {
  if (!CHROME) throw new Error('no Chrome found; set CHROME_PATH');

  // ---- a repeatable starting point: baru@local has no office (earlier runs may have assigned one) ----
  {
    const t = await tokenOf('admin@local', 'admin12345');
    const accs = (await api('GET', '/api/v1/admin/accounts', { token: t })).data;
    const baru = (Array.isArray(accs) ? accs : accs.accounts).find((x) => x.email === 'baru@local');
    await api('PUT', '/office/archive/members/' + (baru.account_id || baru.id), { token: t, json: { organization_id: '' } });
  }

  // ================= the server is named before anyone logs in =================
  section('server tujuan is shown before login');
  const anon = await persona();
  await anon.page.goto(BASE + '/app/');
  await anon.page.waitForFunction(() => document.getElementById('sbName').textContent !== '…', null, { timeout: 15000 });
  check('the login page names the server it belongs to', /Arsip Pusat/.test(await anon.page.textContent('#sbName')), await anon.page.textContent('#sbName'));
  check('...and its address (host:port)', (await anon.page.textContent('#sbHost')).includes(new URL(BASE).host));
  check('a plain-HTTP server is flagged', await anon.page.locator('#sbInsecure').isVisible() === (new URL(BASE).protocol === 'http:'));
  await shot(anon.page, '01-login');

  // ================= an account without an office cannot send =================
  section('an approved account with no office is told so');
  const nb = await persona();
  await login(nb.page, 'baru@local', 'pengirim12345', '#scUpload.active');
  check('the page explains the account has no office yet', await nb.page.locator('#upNoOffice').isVisible());
  await pickFile(nb.page, '#upPick', smallPath).catch(() => {});
  check('sending stays disabled', await nb.page.locator('#upGo').isDisabled());

  // ================= sender A: big file, network failure, pause/resume =================
  section('sender A: 42 MiB upload with a dropped request and a pause/resume');
  const A = await persona();
  await login(A.page, 'pengirim.a@local', 'pengirim12345', '#scUpload.active');
  check('the sender sees who and where they send to', /Dina Pratiwi/.test(await A.page.textContent('#upWho')) && /Kantor Cabang A/.test(await A.page.textContent('#upWho')) && /Arsip Pusat/.test(await A.page.textContent('#upWho')));
  check('a sender has no archive/admin navigation', await A.page.locator('#navArchive').isHidden() && await A.page.locator('#navOffices').isHidden());
  await pickFile(A.page, '#upPick', bigPath);
  check('the chosen file is described', /42\.1|42\.0/.test(await A.page.textContent('#upMeta')) || /MiB/.test(await A.page.textContent('#upMeta')));
  await A.page.fill('#upDesc', 'Laporan triwulan III');

  let patches = 0, dropped = false;
  await A.page.route('**/office/archive/uploads/*', async (route) => {
    if (route.request().method() !== 'PATCH') return route.continue();
    patches++;
    if (patches === 3 && !dropped) { dropped = true; return route.abort('connectionreset'); } // the network fails once
    await sleep(150);
    return route.continue();
  });
  await A.page.click('#upGo');
  await A.page.waitForFunction(() => parseFloat(document.getElementById('upBar').style.width) >= 20, null, { timeout: 60000 });
  await A.page.click('#upPause');
  await sleep(600);
  const pausedAt = await barPct(A.page);
  check('pausing keeps the upload (button becomes Lanjutkan)', /Lanjutkan/.test(await A.page.textContent('#upPause')) && pausedAt < 100);
  await A.page.unroute('**/office/archive/uploads/*');
  await A.page.click('#upPause'); // Lanjutkan
  await A.page.waitForSelector('#scReceipt.active', { timeout: 120000 });
  check('the upload finished despite one dropped request and a pause', dropped);

  const rid = (await A.page.locator('#rcBody dl.kv dd.mono').first().innerText()).trim();
  check('a receipt number is issued', /^rcp_[a-z0-9]{20,}$/.test(rid), rid);
  const hashes = await A.page.locator('#rcBody .hashbox').allInnerTexts();
  check('the receipt shows the SHA-256 of the file — equal to the local hash', hashes[0].includes(sha256(big)), hashes[0]);
  const body = await A.page.textContent('#rcBody');
  check('the receipt names sender, office and file', /Dina Pratiwi/.test(body) && /Kantor Cabang A/.test(body) && body.includes(path.basename(bigPath)));
  check('...and the exact size, the description and the server', body.replace(/[.s]/g, '').includes(String(big.length)) && /Laporan triwulan III/.test(body) && /Arsip Pusat/.test(body));
  check('the signature scheme is shown', /Ed25519 \+ ML-DSA-65/.test(body));
  await shot(A.page, '02-receipt');
  const [dl] = await Promise.all([A.page.waitForEvent('download'), A.page.click('#rcJson')]);
  const jsonPath = path.join(out, 'bukti.json');
  await dl.saveAs(jsonPath);
  const receipt = JSON.parse(readFileSync(jsonPath, 'utf8'));
  check('the downloadable receipt is signed by the server (hybrid)', receipt.server_signature.algorithm_suite === 'HYBRID_ED25519_MLDSA65_V1' && receipt.server_signature.pqc_signature.length > 4000);
  check('...and carries the sender\'s hybrid signature over the manifest', receipt.body.sender_signature.algorithm_suite === 'HYBRID_ED25519_MLDSA65_V1' && receipt.body.manifest.sha256 === sha256(big));
  check('the chain of three events is listed', receipt.body.events.map((e) => e.type).join(',') === 'UPLOAD_RECEIVED,INTEGRITY_VERIFIED,ARCHIVED');

  // ================= sender A again: reload in the middle, resume =================
  section('sender A: reload mid-upload, pick the same file, continue from where the server left off');
  await A.page.click('#rcAgain');
  await A.page.waitForSelector('#scUpload.active');
  await pickFile(A.page, '#upPick', bigPath);
  await A.page.fill('#upDesc', 'unggahan yang terpotong');
  await A.page.route('**/office/archive/uploads/*', async (route) => { if (route.request().method() === 'PATCH') await sleep(500); await route.continue(); });
  await A.page.click('#upGo');
  await A.page.waitForFunction(() => parseFloat(document.getElementById('upBar').style.width) >= 30, null, { timeout: 60000 });
  await A.page.reload(); // the tab is gone mid-upload
  await A.page.waitForSelector('#scUpload.active', { timeout: 30000 });
  check('after a reload the page remembers the unfinished upload', await A.page.locator('#upPending').isVisible() && (await A.page.textContent('#upPending')).includes(path.basename(bigPath)));
  const offsets = [];
  A.page.on('request', (r) => { if (r.method() === 'PATCH') offsets.push(Number(r.headers()['upload-offset'])); });
  await pickFile(A.page, '#upPick', bigPath);
  check('choosing the same file says it will be continued', /dilanjutkan/.test(await A.page.textContent('#upMeta')));
  await A.page.click('#upGo');
  await A.page.waitForSelector('#scReceipt.active', { timeout: 120000 });
  check('the resumed upload did NOT start over (first chunk offset > 0)', offsets.length > 0 && offsets[0] > 0, JSON.stringify(offsets));
  const rid2 = (await A.page.locator('#rcBody dl.kv dd.mono').first().innerText()).trim();
  check('the resumed file is archived with the correct hash', (await A.page.locator('#rcBody .hashbox').first().innerText()).includes(sha256(big)));

  // ================= sender B: small file =================
  section('sender B (another office) sends a small file');
  const B = await persona();
  await login(B.page, 'pengirim.b@local', 'pengirim12345', '#scUpload.active');
  await pickFile(B.page, '#upPick', smallPath);
  await B.page.click('#upGo');
  await B.page.waitForSelector('#scReceipt.active', { timeout: 60000 });
  const ridB = (await B.page.locator('#rcBody dl.kv dd.mono').first().innerText()).trim();
  check('B receives a receipt for a small file', /^rcp_/.test(ridB));

  // ================= access control =================
  section('a sender sees only their own receipt and nothing else');
  const tokA = await tokenOf('pengirim.a@local', 'pengirim12345');
  const tokB = await tokenOf('pengirim.b@local', 'pengirim12345');
  check('B cannot read A\'s receipt', (await api('GET', '/office/archive/receipts/' + rid, { token: tokB })).status === 404);
  check('A can re-read their own receipt', (await api('GET', '/office/archive/receipts/' + rid, { token: tokA })).status === 200);
  for (const p of ['/office/archive/items', '/office/archive/stats', '/office/archive/offices', '/office/archive/members']) {
    check(`a sender cannot call ${p}`, (await api('GET', p, { token: tokA })).status === 403);
  }
  check('unauthenticated calls are refused', (await api('GET', '/office/archive/config')).status === 401);
  // a corrupted transfer is refused and archives nothing
  const st = await api('POST', '/office/archive/uploads', { token: tokA, json: { file_name: 'rusak.bin', size: 1000 } });
  await api('PATCH', '/office/archive/uploads/' + st.data.upload_id, { token: tokA, body: randomBytes(1000), headers: { 'Upload-Offset': '0', 'Content-Type': 'application/octet-stream' } });
  const bad = await api('POST', `/office/archive/uploads/${st.data.upload_id}/complete`, { token: tokA, json: { client_sha256: sha256(Buffer.from('bukan')) } });
  check('a transfer whose hash disagrees is refused (422)', bad.status === 422, JSON.stringify(bad));
  await api('DELETE', '/office/archive/uploads/' + st.data.upload_id, { token: tokA });

  // ================= public receipt check =================
  section('anyone with the receipt number can check it — no login');
  const pub = await persona();
  await pub.page.goto(BASE + '/app/#r=' + rid);
  await pub.page.waitForSelector('#vResult .verdict', { timeout: 30000 });
  check('the public check says the receipt is genuine', await pub.page.locator('#vResult .verdict.ok').count() === 1, await pub.page.innerText('#vResult'));
  check('every verification check passed (manifest, sender + server signatures, chain)', (await pub.page.locator('#vResult .checks li.ok').count()) >= 4 && (await pub.page.locator('#vResult .checks li.no').count()) === 0);
  const pubText = await pub.page.textContent('#vResult');
  check('the public view does not expose the sender\'s e-mail or IP', !/@local/.test(pubText) && !/\d+\.\d+\.\d+\.\d+/.test(pubText));
  await pickFile(pub.page, '#vPick', bigPath);
  await pub.page.waitForFunction(() => /SAMA PERSIS|BERBEDA/.test(document.getElementById('vHashStat')?.textContent || ''), null, { timeout: 60000 });
  check('the same file matches', /SAMA PERSIS/.test(await pub.page.textContent('#vHashStat')));
  await pickFile(pub.page, '#vPick', otherPath);
  await pub.page.waitForFunction(() => /BERBEDA/.test(document.getElementById('vHashStat')?.textContent || ''), null, { timeout: 30000 });
  check('a different file does not match', /BERBEDA/.test(await pub.page.textContent('#vHashStat')));
  await pub.page.goto(BASE + '/app/#r=rcp_tidakada');
  await pub.page.reload();
  await pub.page.waitForFunction(() => /tidak ditemukan/.test(document.getElementById('vResult')?.textContent || ''), null, { timeout: 15000 });
  check('an unknown receipt number is reported', true);

  // ================= central admin =================
  section('central admin: sees every office, verifies, downloads');
  const adm = await persona();
  await login(adm.page, 'admin@local', 'admin12345', '#scArchive.active');
  await adm.page.waitForSelector('#arList table', { timeout: 30000 });
  check('the admin lands on the archive with navigation to offices', await adm.page.locator('#navOffices').isVisible());
  const rows = await adm.page.locator('#arList tbody tr').allInnerTexts();
  check('the archive lists both offices\' uploads', rows.some((r) => r.includes('Kantor Cabang A') && r.includes(path.basename(bigPath))) && rows.some((r) => r.includes('Kantor Cabang B') && r.includes(path.basename(smallPath))));
  await shot(adm.page, '03-archive');
  await adm.page.selectOption('#arOrg', { label: 'Kantor Cabang B' });
  await adm.page.waitForFunction((n) => [...document.querySelectorAll('#arList tbody tr')].every((r) => r.textContent.includes('Kantor Cabang B')) && document.querySelectorAll('#arList tbody tr').length > 0, null, { timeout: 15000 });
  check('filtering by office narrows the list', true);
  await adm.page.selectOption('#arOrg', '');
  await adm.page.fill('#arQ', path.basename(bigPath));
  await adm.page.click('#arGo');
  await adm.page.waitForFunction((n) => document.querySelectorAll('#arList tbody tr').length === 2 && [...document.querySelectorAll('#arList tbody tr')].every((r) => r.textContent.includes(n)), path.basename(bigPath), { timeout: 15000 });
  check('searching by file name finds the two uploads of that file', true);

  await adm.page.locator('#arList tbody tr').first().click();
  await adm.page.waitForSelector('#scItem.active #itBody .hashbox', { timeout: 15000 });
  const detail = await adm.page.textContent('#itBody');
  check('the detail shows sender, office, IP and hashes', /Dina Pratiwi/.test(detail) && /Kantor Cabang A/.test(detail) && detail.includes(sha256(big)) && /IP pengirim/.test(detail));
  check('the timeline has the three chained events', (await adm.page.locator('#itBody .timeline li').count()) === 3);
  await shot(adm.page, '04-detail');
  await adm.page.getByRole('button', { name: 'Verifikasi + cek berkas tersimpan' }).click();
  await adm.page.waitForSelector('#itVerify .verdict', { timeout: 60000 });
  check('verification (signatures, chain, receipt, stored file) passes', await adm.page.locator('#itVerify .verdict.ok').count() === 1, await adm.page.innerText('#itVerify'));
  check('all six checks are listed and green', (await adm.page.locator('#itVerify .checks li.ok').count()) === 6);
  const [file] = await Promise.all([adm.page.waitForEvent('download', { timeout: 60000 }), adm.page.getByRole('button', { name: 'Unduh berkas' }).click()]);
  const dlPath = path.join(out, 'diunduh.bin');
  await file.saveAs(dlPath);
  check('the downloaded file is byte-identical to what was uploaded', sha256(readFileSync(dlPath)) === sha256(big));
  check('the download keeps the original name', file.suggestedFilename() === path.basename(bigPath), file.suggestedFilename());

  // ================= offices & members via the UI =================
  section('central admin: adds an office and assigns the unassigned user');
  await adm.page.click('#itBack');
  await adm.page.click('[data-nav=offices]');
  await adm.page.waitForSelector('#mbList table', { timeout: 15000 });
  const office = `Kantor Baru ${run}`;
  await adm.page.fill('#ofName', office); await adm.page.click('#ofAdd');
  await adm.page.waitForFunction((n) => document.getElementById('ofList').textContent.includes(n), office, { timeout: 15000 });
  check('a new office appears in the list', true);
  const sel = adm.page.locator('#mbList tr', { hasText: 'baru@local' }).locator('select');
  await sel.selectOption({ label: office });
  await adm.page.locator('#mbList tr', { hasText: 'baru@local' }).getByRole('button', { name: 'Simpan' }).click();
  await adm.page.waitForFunction(() => /Tersimpan/.test(document.getElementById('toast').textContent), null, { timeout: 10000 });
  check('the user is assigned to it', true);
  await shot(adm.page, '05-offices');

  const nb2 = await persona();
  await login(nb2.page, 'baru@local', 'pengirim12345', '#scUpload.active');
  check('the newly assigned user can now send', await nb2.page.locator('#upNoOffice').isHidden());
  await pickFile(nb2.page, '#upPick', smallPath);
  await nb2.page.click('#upGo');
  await nb2.page.waitForSelector('#scReceipt.active', { timeout: 60000 });
  check('...under the new office', new RegExp(office).test(await nb2.page.textContent('#rcBody')));

  // ================= ledger =================
  section('ledger');
  const tokAdmin = await tokenOf('admin@local', 'admin12345');
  const items = (await api('GET', '/office/archive/items?limit=50', { token: tokAdmin })).data.items;
  const mine = items.find((i) => i.receipt_id === rid);
  check('the archive item is linked to a ledger transaction', !!mine && /^txn_/.test(mine.transaction_id));
  if (FABRIC) {
    let it = mine;
    for (let i = 0; i < 40 && it.ledger.state !== 'recorded'; i++) {
      await sleep(2000);
      it = (await api('GET', '/office/archive/items?limit=50', { token: tokAdmin })).data.items.find((x) => x.receipt_id === rid);
    }
    check('all three events are recorded on the blockchain', it.ledger.state === 'recorded', JSON.stringify(it.ledger));
    const det = (await api('GET', '/office/archive/items/' + mine.id, { token: tokAdmin })).data;
    check('each event carries its Fabric block number', det.events.length === 3 && det.events.every((e) => Number(e.fabric_block_number) > 0), JSON.stringify(det.events.map((e) => e.fabric_block_number)));
    console.log('       ' + mine.transaction_id + ' -> blocks ' + det.events.map((e) => e.fabric_block_number).join(', '));
  } else {
    check('events are queued for the ledger, none dead-lettered', mine.ledger.dead === 0 && mine.ledger.queued >= 3, JSON.stringify(mine.ledger));
  }

  section('browser health');
  const csps = [];
  for (const p of [anon, nb, A, B, pub, adm, nb2]) csps.push(...await p.page.evaluate(() => window.__csp).catch(() => []));
  check('the strict CSP was never violated', csps.length === 0 && problems.csp.length === 0, [...csps, ...problems.csp].join(' | '));
  check('no uncaught page errors', problems.errors.length === 0, problems.errors.join(' | '));
} catch (e) {
  failures++;
  console.error('\nE2E ABORTED:', e);
} finally {
  await browser.close();
}
console.log(failures ? `\n${failures} FAILED` : '\nALL ARCHIVE E2E CHECKS PASSED');
process.exit(failures ? 1 : 0);

// Runs the REAL pqcsign.wasm (built by web/build.sh) under Node and drives it
// through the same JavaScript API the browser worker uses. This is the check
// that the JS<->Go marshalling, the Promise/rejection behaviour and the PIN
// envelope work in WebAssembly — not just in the native Go tests.
//
//   node --test web/test/wasm.test.mjs        (from the ttd/ directory)
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const ttd = path.resolve(here, '..', '..');
const webapp = path.join(ttd, 'server', 'internal', 'api', 'webapp');
const require = createRequire(import.meta.url);

let api; // globalThis.pqcsign

before(async () => {
  // Same shims wasm_exec_node.js installs.
  globalThis.require = require;
  globalThis.fs = require('node:fs');
  globalThis.path = require('node:path');
  globalThis.TextEncoder = TextEncoder;
  globalThis.TextDecoder = TextDecoder;
  require(path.join(webapp, 'wasm_exec.js'));

  const go = new globalThis.Go();
  const bytes = readFileSync(path.join(webapp, 'pqcsign.wasm'));
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
  const ready = new Promise((resolve) => { globalThis.__pqcsignReady = resolve; });
  go.run(instance); // blocks forever on the Go side; do not await
  await ready;
  api = globalThis.pqcsign;
});

const enc = new TextEncoder();
const rejection = async (p) => { try { await p; } catch (e) { return e; } assert.fail('expected the promise to reject'); };

test('exposes the bridge ABI version', () => {
  assert.equal(api.version(), 'webbridge/1');
});

test('generateKey / exportPublicKey produce a key and a PEM public key, and no PEM private key', async () => {
  const key = await api.generateKey();
  assert.ok(key instanceof Uint8Array && key.length > 0);
  const pub = await api.exportPublicKey(key);
  assert.match(pub, /BEGIN PUBLIC KEY/);
  assert.doesNotMatch(pub, /PRIVATE KEY/);
});

test('PIN envelope: round trip, wrong PIN, short PIN, change PIN — with error codes', async () => {
  const key = await api.generateKey();
  const t0 = performance.now();
  const blob = await api.protectKey(key, 'sandi-rahasia');
  const t1 = performance.now();
  console.log(`      (Argon2id 64 MiB, t=3 inside wasm: protect ${(t1 - t0).toFixed(0)} ms)`);

  // The blob must not contain the plaintext key.
  assert.equal(Buffer.from(blob).includes(Buffer.from(key)), false);

  const back = await api.unprotectKey(blob, 'sandi-rahasia');
  assert.deepEqual(Buffer.from(back), Buffer.from(key));

  assert.equal((await rejection(api.unprotectKey(blob, 'salah-pin'))).code, 'wrong_pin');
  assert.equal((await rejection(api.protectKey(key, '123'))).code, 'pin_too_short');
  assert.equal((await rejection(api.unprotectKey(enc.encode('{}'), 'sandi-rahasia'))).code, 'unsupported');

  const changed = await api.changePIN(blob, 'sandi-rahasia', 'sandi-baru-1');
  assert.equal((await rejection(api.unprotectKey(changed, 'sandi-rahasia'))).code, 'wrong_pin');
  assert.deepEqual(Buffer.from(await api.unprotectKey(changed, 'sandi-baru-1')), Buffer.from(key));
});

test('bad argument types reject cleanly instead of crashing the module', async () => {
  const e1 = await rejection(api.exportPublicKey('not bytes'));
  assert.match(e1.message, /Uint8Array/);
  const e2 = await rejection(api.createCSR(await api.generateKey(), 42));
  assert.match(e2.message, /string/);
  // module still alive afterwards
  assert.equal(api.version(), 'webbridge/1');
});

test('full enrollment + signing in wasm: CSR -> lab CA -> certMatchesKey -> signPDF -> verifyPDF; tampering is caught', async () => {
  const key = await api.generateKey();
  const csr = await api.createCSR(key, JSON.stringify({ common_name: 'x', platform: 'web' }));
  assert.match(csr, /BEGIN CERTIFICATE REQUEST/);
  assert.doesNotMatch(csr, /PRIVATE KEY/);

  // A throwaway lab CA issues the certificate (the server's online CA does this in production).
  const issued = spawnSync('go', ['run', './cmd/labissue'], {
    cwd: path.join(ttd, 'core'), input: csr, env: { ...process.env, GOWORK: 'off' }, encoding: 'utf8',
  });
  assert.equal(issued.status, 0, issued.stderr);
  const { root_pem: rootPEM, chain_pem: chainPEM } = JSON.parse(issued.stdout);

  assert.equal(await api.certMatchesKey(key, chainPEM), true);
  const otherKey = await api.generateKey();
  assert.equal(await api.certMatchesKey(otherKey, chainPEM), false);

  const pdf = new Uint8Array(readFileSync(path.join(ttd, 'tests', 'fixtures', 'sample.pdf')));
  const t0 = performance.now();
  const { signedPdf, result } = await api.signPDF(pdf, key, chainPEM,
    JSON.stringify({ signer_name: 'Pengguna Uji', public_id: 'sig_nodewasm', reason: 'uji' }));
  console.log(`      (signPDF in wasm: ${(performance.now() - t0).toFixed(0)} ms, ${signedPdf.length} bytes out)`);
  assert.ok(signedPdf instanceof Uint8Array && signedPdf.length > pdf.length);
  const sr = JSON.parse(result);
  assert.equal(sr.algorithm, 'ML-DSA-65');
  assert.equal(sr.public_id, 'sig_nodewasm');
  assert.equal(sr.pdf_profile.length > 0, true);

  const verdict = JSON.parse(await api.verifyPDF(signedPdf, rootPEM, null));
  assert.equal(verdict.valid, true, JSON.stringify(verdict));
  assert.equal(verdict.signatures[0].trusted_chain, true);

  // Flip one byte inside the signed range -> must not verify.
  const tampered = new Uint8Array(signedPdf);
  tampered[Buffer.from(tampered).indexOf('%PDF-') + 200] ^= 0xff;
  let tamperedValid = false;
  try { tamperedValid = JSON.parse(await api.verifyPDF(tampered, rootPEM, null)).valid; } catch { /* parse error == rejected */ }
  assert.equal(tamperedValid, false);

  // A different Root CA must not be trusted.
  const other = spawnSync('go', ['run', './cmd/labissue'], {
    cwd: path.join(ttd, 'core'), input: csr, env: { ...process.env, GOWORK: 'off' }, encoding: 'utf8',
  });
  const otherRoot = JSON.parse(other.stdout).root_pem;
  let wrongRootValid = false;
  try { wrongRootValid = JSON.parse(await api.verifyPDF(signedPdf, otherRoot, null)).valid; } catch { /* rejected */ }
  assert.equal(wrongRootValid, false);
});

test('signPDF refuses a non-PDF and malformed options', async () => {
  const key = await api.generateKey();
  const e1 = await rejection(api.signPDF(enc.encode('not a pdf'), key, 'x', ''));
  assert.ok(e1.message.length > 0);
  const e2 = await rejection(api.signPDF(new Uint8Array([1, 2, 3]), key, 'x', '{bad json'));
  assert.match(e2.message, /options/i);
});

test('sha512Hex, certFingerprint, checkDeviceCertificate and listSignatures work in wasm', async () => {
  assert.equal(await api.sha512Hex(enc.encode('abc')),
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f');

  const key = await api.generateKey();
  const csr = await api.createCSR(key, JSON.stringify({ common_name: 'x', platform: 'web' }));
  const issued = spawnSync('go', ['run', './cmd/labissue'], {
    cwd: path.join(ttd, 'core'), input: csr, env: { ...process.env, GOWORK: 'off' }, encoding: 'utf8',
  });
  assert.equal(issued.status, 0, issued.stderr);
  const { root_pem: rootPEM, chain_pem: chainPEM } = JSON.parse(issued.stdout);

  assert.equal((await api.certFingerprint(rootPEM)).length, 64);
  const info = JSON.parse(await api.checkDeviceCertificate(chainPEM));
  assert.equal(info.is_ca, false);
  assert.equal(info.has_document_signing_eku, true);
  assert.equal((await rejection(api.checkDeviceCertificate(rootPEM))).message.length > 0, true);

  const pdf = new Uint8Array(readFileSync(path.join(ttd, 'tests', 'fixtures', 'sample.pdf')));
  assert.equal(await api.listSignatures(pdf), 0);
  const { signedPdf } = await api.signPDF(pdf, key, chainPEM, '{"public_id":"sig_list"}');
  assert.equal(await api.listSignatures(signedPdf), 1);
});

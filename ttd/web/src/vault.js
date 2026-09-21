// Per-account storage of the device key in IndexedDB.
//
// What is stored is NEVER the plaintext key. The blob is already
// Argon2id(PIN) + AES-256-GCM (core/webkeys). When WebCrypto is available
// (secure context: https or localhost) it is additionally sealed with a
// NON-EXTRACTABLE AES-GCM "device-binding key" that lives in IndexedDB as an
// opaque CryptoKey — the browser analogue of DPAPI / Android Keystore on the
// other clients: a copied IndexedDB file cannot be opened elsewhere, and script
// on the page can use but never read the binding key.
//
// Clearing site data destroys the key. That is by design; recovery is the same
// report-lost / re-enroll flow the other clients use.
'use strict';

const DB_NAME = 'pqc-ttd';
const DB_VERSION = 1;
const enc = new TextEncoder();

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('meta')) db.createObjectStore('meta');
      if (!db.objectStoreNames.contains('vaults')) db.createObjectStore('vaults');
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('IndexedDB tidak tersedia'));
  });
}

async function tx(store, mode, fn) {
  const db = await open();
  try {
    return await new Promise((resolve, reject) => {
      const t = db.transaction(store, mode);
      const r = fn(t.objectStore(store));
      t.oncomplete = () => resolve(r && r.result);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
  } finally { db.close(); }
}

const normEmail = (e) => String(e || '').trim().toLowerCase();

export const hasWebCrypto = () => !!(globalThis.crypto && crypto.subtle && globalThis.isSecureContext);

async function bindingKey(create) {
  let k = await tx('meta', 'readonly', (s) => s.get('binding'));
  if (!k && create) {
    k = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    await tx('meta', 'readwrite', (s) => s.put(k, 'binding'));
  }
  return k || null;
}

const aad = (email) => enc.encode('pqc-ttd-vault/v1|' + normEmail(email));

async function seal(email, blob) {
  if (!hasWebCrypto()) return { bound: false, blob: blob.slice().buffer };
  const key = await bindingKey(true);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(email) }, key, blob);
  return { bound: true, iv, blob: ct };
}

async function unseal(email, rec) {
  if (!rec.bound) return new Uint8Array(rec.blob);
  if (!hasWebCrypto()) throw new Error('kunci terikat ke perangkat ini dan hanya bisa dibuka lewat HTTPS atau localhost');
  const key = await bindingKey(false);
  if (!key) throw new Error('kunci pengikat perangkat hilang — data situs dihapus? Lakukan reset perangkat lalu daftarkan ulang.');
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.iv, additionalData: aad(email) }, key, rec.blob));
  } catch {
    throw new Error('vault rusak atau bukan milik akun ini');
  }
}

// Ask the browser not to evict the vault under storage pressure.
export async function requestPersistence() {
  try { return !!(navigator.storage && navigator.storage.persist && await navigator.storage.persist()); }
  catch { return false; }
}

// A vault record: { email, bound, iv?, blob, deviceId, enrollmentId, certPEM,
// chainPEM, rootPEM, rootFingerprint, certSerial, createdAt, updatedAt }.
export async function load(email) {
  const rec = await tx('vaults', 'readonly', (s) => s.get(normEmail(email)));
  if (!rec) return null;
  return { ...rec, keyBlob: await unseal(email, rec) };
}

// Peek without unsealing (cheap; no WebCrypto needed).
export async function exists(email) {
  return !!(await tx('vaults', 'readonly', (s) => s.getKey(normEmail(email))));
}

export async function save(email, v) {
  const { keyBlob, ...rest } = v;
  const sealed = await seal(email, keyBlob);
  const rec = { ...rest, email: normEmail(email), bound: sealed.bound, iv: sealed.iv, blob: sealed.blob, updatedAt: Date.now() };
  if (!rec.createdAt) rec.createdAt = rec.updatedAt;
  await tx('vaults', 'readwrite', (s) => s.put(rec, normEmail(email)));
}

// Update non-secret fields (certificate, ids) without re-sealing the key.
export async function patch(email, fields) {
  const cur = await tx('vaults', 'readonly', (s) => s.get(normEmail(email)));
  if (!cur) throw new Error('vault tidak ditemukan');
  await tx('vaults', 'readwrite', (s) => s.put({ ...cur, ...fields, updatedAt: Date.now() }, normEmail(email)));
}

export async function remove(email) {
  await tx('vaults', 'readwrite', (s) => s.delete(normEmail(email)));
}

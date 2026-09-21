// Typed client for the receiver API (upstream docs/api.md). Port of the
// desktop apiclient: it moves bytes and performs no crypto. Same-origin only —
// the page is served by the API server, so there is no server-URL setting and
// no CORS. The access token lives in sessionStorage (dies with the tab).
'use strict';

const CHUNK = 8 << 20; // above this, use resumable /api/v1/uploads

export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

let token = '';
try { token = sessionStorage.getItem('pqc_token') || ''; } catch { /* storage blocked */ }

export function setToken(t) {
  token = t || '';
  try { if (token) sessionStorage.setItem('pqc_token', token); else sessionStorage.removeItem('pqc_token'); } catch { /* ignore */ }
}
export const hasToken = () => !!token;

async function req(method, path, { body, type, raw } = {}) {
  const headers = {};
  if (type) headers['Content-Type'] = type;
  if (token) headers.Authorization = 'Bearer ' + token;
  let resp;
  try {
    resp = await fetch(path, { method, headers, body, credentials: 'omit', cache: 'no-store' });
  } catch {
    throw new ApiError(0, 'Tidak bisa terhubung ke server.');
  }
  if (!resp.ok) {
    let msg = (await resp.text().catch(() => '')).trim();
    try { const j = JSON.parse(msg); if (j.error) msg = j.error; } catch { /* plain text */ }
    if (resp.status === 401 && token) setToken('');
    throw new ApiError(resp.status, msg || resp.statusText);
  }
  if (raw === 'bytes') return new Uint8Array(await resp.arrayBuffer());
  if (raw === 'text') return resp.text();
  const text = await resp.text();
  return text ? JSON.parse(text) : {};
}

const json = (method, path, obj) => req(method, path, { body: JSON.stringify(obj || {}), type: 'application/json' });

export const isTooLarge = (e) => e instanceof ApiError && e.status === 413;

// ---- auth ----
export const register = (f) => json('POST', '/api/v1/auth/register', {
  email: f.email, password: f.password, full_name: f.fullName, organization: f.org,
  display_name: f.fullName, position: f.position, nip: f.nip,
});

export async function login(email, password) {
  const out = await json('POST', '/api/v1/auth/login', { email, password });
  if (!out.access_token) throw new Error('login: respons tanpa access_token');
  setToken(out.access_token);
}

// ---- devices & enrollment ----
export const listDevices = async () => (await req('GET', '/api/v1/devices')).devices || [];
export const createDevice = async (label, platform) =>
  (await json('POST', '/api/v1/devices', { label, platform })).device_id;
export const submitCSR = async (deviceId, csrPEM) =>
  (await req('POST', '/api/v1/devices/' + deviceId + '/csr', { body: csrPEM, type: 'application/x-pem-file' })).enrollment_id;
export const reportLost = (deviceId) => req('POST', '/api/v1/devices/' + deviceId + '/report-lost');

// Resolves to null while the CA has not issued a certificate (404).
export async function deviceCertificate(deviceId) {
  try { return await req('GET', '/api/v1/devices/' + deviceId + '/certificate', { raw: 'text' }); }
  catch (e) { if (e instanceof ApiError && e.status === 404) return null; throw e; }
}

// ---- public CA material ----
export const rootCA = () => req('GET', '/api/v1/public/ca/root.crt', { raw: 'text' });
export const chain = () => req('GET', '/api/v1/public/ca/chain.pem', { raw: 'text' });
export const crl = () => req('GET', '/api/v1/public/ca/crl.pem', { raw: 'text' });

// ---- signatures ----
export const reserve = (deviceId, originalSHA512, fileName) =>
  json('POST', '/api/v1/signatures/reserve', { device_id: deviceId, original_sha512: originalSHA512, file_name: fileName });

async function uploadBytes(data) {
  const { upload_id: id } = await req('POST', '/api/v1/uploads');
  if (!id) throw new Error('respons unggah tanpa upload_id');
  for (let off = 0; off < data.length;) {
    const end = Math.min(off + CHUNK, data.length);
    const r = await req('PATCH', '/api/v1/uploads/' + id + '?offset=' + off,
      { body: data.subarray(off, end), type: 'application/octet-stream' });
    if (!(r.received > off)) throw new Error('unggah macet di offset ' + off);
    off = r.received;
  }
  return id;
}

// placements: [{page,x,y,w}] page-relative, origin top-left, fractions of [0,1].
export async function stamp(publicId, pdf, placements, reason, issuedPlace) {
  const q = new URLSearchParams();
  if (reason) q.set('reason', reason);
  if (issuedPlace) q.set('issued_place', issuedPlace);
  q.set('stamps', JSON.stringify(placements));
  if (placements.length === 1) { // single-placement params kept for compatibility
    const p = placements[0];
    if (p.page > 0) q.set('page', String(p.page));
    q.set('x', p.x.toFixed(4)); q.set('y', p.y.toFixed(4)); q.set('w', p.w.toFixed(4));
  }
  const base = '/api/v1/signatures/' + publicId + '/stamp';
  if (pdf.length > CHUNK) {
    q.set('upload_id', await uploadBytes(pdf));
    return req('POST', base + '?' + q, { raw: 'bytes' });
  }
  return req('POST', base + '?' + q, { body: pdf, type: 'application/pdf', raw: 'bytes' });
}

export async function submitDocument(publicId, signedPDF) {
  const path = '/api/v1/signatures/' + publicId + '/document';
  if (signedPDF.length > CHUNK) return req('PUT', path + '?upload_id=' + await uploadBytes(signedPDF));
  return req('PUT', path, { body: signedPDF, type: 'application/pdf' });
}

export const mySignatures = async () => (await req('GET', '/api/v1/me/signatures')).signatures || [];

// Public verifier: no account needed. Returns { verification, registered, record }.
export function verifyPublic(pdf) {
  const fd = new FormData();
  fd.append('file', new Blob([pdf], { type: 'application/pdf' }), 'document.pdf');
  return req('POST', '/api/v1/verify', { body: fd });
}

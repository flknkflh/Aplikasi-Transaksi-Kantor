// Same-origin API client. The access token lives in sessionStorage (dies with the
// tab). No credentials are ever sent cross-origin: the page is served by the very
// server it talks to (that server's address is shown on screen).
'use strict';

export class ApiError extends Error {
  constructor(status, message, body) { super(message); this.status = status; this.body = body || {}; }
}

let token = '';
try { token = sessionStorage.getItem('arsip_token') || ''; } catch { /* storage blocked */ }

export function setToken(t) {
  token = t || '';
  try { if (token) sessionStorage.setItem('arsip_token', token); else sessionStorage.removeItem('arsip_token'); } catch { /* ignore */ }
}
export const hasToken = () => !!token;

export async function request(method, path, { body, type, headers, raw, signal } = {}) {
  const h = { ...(headers || {}) };
  if (type) h['Content-Type'] = type;
  if (token) h.Authorization = 'Bearer ' + token;
  let resp;
  try {
    resp = await fetch(path, { method, headers: h, body, credentials: 'omit', cache: 'no-store', signal });
  } catch (e) {
    if (e && e.name === 'AbortError') throw e;
    throw new ApiError(0, 'Tidak bisa terhubung ke server.');
  }
  if (!resp.ok) {
    const text = (await resp.text().catch(() => '')).trim();
    let parsed = {}, msg = text;
    try { parsed = JSON.parse(text); if (parsed.error) msg = parsed.error; } catch { /* plain text */ }
    if (resp.status === 401 && token) setToken('');
    throw new ApiError(resp.status, msg || resp.statusText, parsed);
  }
  if (raw === 'text') return resp.text();
  const text = await resp.text();
  return text ? JSON.parse(text) : {};
}

const json = (method, path, obj) => request(method, path, { body: JSON.stringify(obj || {}), type: 'application/json' });
export const get = (path) => request('GET', path);
export const post = (path, obj) => json('POST', path, obj);
export const put = (path, obj) => json('PUT', path, obj);

export const serverInfo = () => get('/api/v1/public/server');
export const register = (f) => post('/api/v1/auth/register', {
  email: f.email, password: f.password, full_name: f.fullName, organization: f.org, display_name: f.fullName,
});
export async function login(email, password) {
  const out = await post('/api/v1/auth/login', { email, password });
  if (!out.access_token) throw new Error('login: respons tanpa access_token');
  setToken(out.access_token);
}

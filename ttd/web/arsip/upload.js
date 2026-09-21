// Resumable chunked upload of any file, of any size, to /office/archive/uploads.
//
//  - the file is read in slices (never loaded whole), so multi-gigabyte files work;
//  - the browser hashes the bytes as they go (SHA-256) and sends that hash when
//    finishing: the server refuses the upload if its own hash differs, so a corrupted
//    transfer can never be archived as if it were fine;
//  - the server tells us how much it has (Upload-Offset); after a dropped connection,
//    a reload or a paused upload we ask for that offset and continue from there;
//  - an unfinished upload is remembered (localStorage) so it can be resumed after
//    reloading the page — the user picks the same file again (browsers cannot
//    reopen a file by themselves).
'use strict';
import * as api from './api.js';
import { Sha256 } from './sha256.js';

const PENDING_KEY = 'arsip_pending_upload';

export function pendingUpload(userId) {
  try {
    const p = JSON.parse(localStorage.getItem(PENDING_KEY) || 'null');
    return p && p.user === userId ? p : null;
  } catch { return null; }
}
export function clearPending() { try { localStorage.removeItem(PENDING_KEY); } catch { /* ignore */ } }
function savePending(p) { try { localStorage.setItem(PENDING_KEY, JSON.stringify(p)); } catch { /* ignore */ } }

export const sameFile = (p, file) => p && file && p.name === file.name && p.size === file.size && p.lastModified === file.lastModified;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class Uploader {
  // opts: { userId, description, resume: pendingObject|null, onProgress({sent,total,phase,speed}) }
  constructor(file, opts) {
    this.file = file;
    this.opts = opts;
    this.abortCtl = new AbortController();
    this.uploadId = null;
    this.paused = false;
  }

  pause() { this.paused = true; this.abortCtl.abort(); }

  async cancel() {
    this.pause();
    if (this.uploadId) { try { await api.request('DELETE', '/office/archive/uploads/' + this.uploadId); } catch { /* already gone */ } }
    clearPending();
  }

  _progress(sent, phase) {
    const now = performance.now();
    if (!this._t0) { this._t0 = now; this._b0 = sent; }
    const dt = (now - this._t0) / 1000;
    const speed = dt > 0.5 ? Math.max(0, sent - this._b0) / dt : 0;
    if (this.opts.onProgress) this.opts.onProgress({ sent, total: this.file.size, phase, speed });
  }

  async _slice(from, to) {
    return new Uint8Array(await this.file.slice(from, to).arrayBuffer());
  }

  // Runs until the server has issued a receipt (resolves to the receipt response).
  async run() {
    const { file, opts } = this;
    const cfg = await api.get('/office/archive/config');
    const chunk = cfg.chunk_size || (8 << 20);

    let offset = 0;
    if (opts.resume && sameFile(opts.resume, file)) {
      this.uploadId = opts.resume.uploadId;
      try {
        offset = (await api.get('/office/archive/uploads/' + this.uploadId)).offset;
      } catch (e) {
        if (!(e instanceof api.ApiError) || e.status !== 404) throw e;
        this.uploadId = null; // the server forgot it (expired): start over
      }
    }
    if (!this.uploadId) {
      const created = await api.post('/office/archive/uploads', {
        file_name: file.name, size: file.size, media_type: file.type || 'application/octet-stream', description: opts.description || '',
      });
      this.uploadId = created.upload_id;
      offset = 0;
    }
    savePending({ user: opts.userId, uploadId: this.uploadId, name: file.name, size: file.size, lastModified: file.lastModified });

    let sha = new Sha256();
    let hashed = 0;
    const hashTo = async (target) => {
      if (hashed > target) { sha = new Sha256(); hashed = 0; } // server is behind us: recompute
      while (hashed < target) {
        if (this.abortCtl.signal.aborted) throw new DOMException('dijeda', 'AbortError');
        const end = Math.min(hashed + chunk, target);
        sha.update(await this._slice(hashed, end));
        hashed = end;
        this._progress(hashed, 'hash');
      }
    };

    let failures = 0;
    while (offset < file.size) {
      if (this.abortCtl.signal.aborted) throw new DOMException('dijeda', 'AbortError');
      await hashTo(offset); // (only does work on resume, or after the server reported an earlier offset)
      const end = Math.min(offset + chunk, file.size);
      const buf = await this._slice(offset, end);
      try {
        const r = await api.request('PATCH', '/office/archive/uploads/' + this.uploadId, {
          body: buf, type: 'application/offset+octet-stream', headers: { 'Upload-Offset': String(offset) }, signal: this.abortCtl.signal,
        });
        sha.update(buf); hashed = end; offset = r.offset; failures = 0;
        this._progress(offset, 'upload');
      } catch (e) {
        if (e && e.name === 'AbortError') throw e;
        if (e instanceof api.ApiError && e.status === 409 && typeof e.body.offset === 'number') { offset = e.body.offset; continue; }
        if (e instanceof api.ApiError && e.status >= 400 && e.status < 500 && e.status !== 408 && e.status !== 429) throw e;
        if (++failures > 8) throw e;
        await sleep(Math.min(30000, 1000 * 2 ** failures));
        try { offset = (await api.get('/office/archive/uploads/' + this.uploadId)).offset; } catch { /* retry the loop */ }
      }
    }

    await hashTo(file.size);
    const clientSha256 = sha.digestHex();
    this._progress(file.size, 'finish');
    const receipt = await api.post('/office/archive/uploads/' + this.uploadId + '/complete', { client_sha256: clientSha256 });
    clearPending();
    receipt._client_sha256 = clientSha256;
    return receipt;
  }
}

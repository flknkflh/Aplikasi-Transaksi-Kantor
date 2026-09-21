// Incremental SHA-256 in plain JavaScript. crypto.subtle.digest() cannot be fed
// in pieces (it needs the whole file in memory) and does not exist on plain-HTTP
// origins, but archive files can be many gigabytes and the server may be reached
// over a LAN address. Verified against node:crypto in web/test/sha256.test.mjs.
'use strict';

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export class Sha256 {
  constructor() {
    this.h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    this.buf = new Uint8Array(64);
    this.n = 0;          // bytes buffered (< 64)
    this.len = 0;        // total bytes
    this.w = new Uint32Array(64);
  }

  _block(b, o) {
    const w = this.w, h = this.h;
    for (let i = 0; i < 16; i++, o += 4) w[i] = (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3];
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15], c = w[i - 2];
      const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
      const s1 = ((c >>> 17) | (c << 15)) ^ ((c >>> 19) | (c << 13)) ^ (c >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let a = h[0], b1 = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const mj = (a & b1) ^ (a & c) ^ (b1 & c);
      const t2 = (S0 + mj) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b1; b1 = a; a = (t1 + t2) | 0;
    }
    h[0] = (h[0] + a) | 0; h[1] = (h[1] + b1) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
  }

  update(data) {
    let i = 0;
    const len = data.length;
    this.len += len;
    if (this.n) {
      const take = Math.min(64 - this.n, len);
      this.buf.set(data.subarray(0, take), this.n);
      this.n += take; i = take;
      if (this.n < 64) return this;
      this._block(this.buf, 0); this.n = 0;
    }
    for (; i + 64 <= len; i += 64) this._block(data, i);
    if (i < len) { this.buf.set(data.subarray(i), 0); this.n = len - i; }
    return this;
  }

  // Returns the lowercase hex digest; the instance must not be used afterwards.
  digestHex() {
    const bits = this.len * 8;
    const pad = new Uint8Array(((this.n < 56 ? 56 : 120) - this.n) + 8);
    pad[0] = 0x80;
    const hi = Math.floor(bits / 0x100000000), lo = bits >>> 0;
    const p = pad.length - 8;
    pad[p] = hi >>> 24; pad[p + 1] = hi >>> 16; pad[p + 2] = hi >>> 8; pad[p + 3] = hi;
    pad[p + 4] = lo >>> 24; pad[p + 5] = lo >>> 16; pad[p + 6] = lo >>> 8; pad[p + 7] = lo;
    const total = this.len;
    this.update(pad);
    this.len = total;
    let out = '';
    for (const v of this.h) out += (v >>> 0).toString(16).padStart(8, '0');
    return out;
  }
}

// Hash a File/Blob in slices without loading it all; onProgress(bytesDone).
export async function sha256File(file, { sliceSize = 8 << 20, onProgress, signal } = {}) {
  const s = new Sha256();
  for (let off = 0; off < file.size; off += sliceSize) {
    if (signal && signal.aborted) throw new DOMException('dibatalkan', 'AbortError');
    s.update(new Uint8Array(await file.slice(off, Math.min(off + sliceSize, file.size)).arrayBuffer()));
    if (onProgress) onProgress(Math.min(off + sliceSize, file.size));
  }
  return s.digestHex();
}

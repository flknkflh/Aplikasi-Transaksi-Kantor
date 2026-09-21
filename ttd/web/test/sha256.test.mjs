// The browser's incremental SHA-256 must equal the platform's for every input
// shape, especially around the 55/56/63/64-byte padding boundaries and when the
// data is fed in awkward pieces (the uploader hashes in 8 MiB chunks).
//   node --test web/test/sha256.test.mjs        (from the ttd/ directory)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { Sha256 } from '../arsip/sha256.js';

const ref = (b) => createHash('sha256').update(b).digest('hex');
const mine = (b, piece) => {
  const s = new Sha256();
  for (let i = 0; i < b.length; i += piece) s.update(new Uint8Array(b.subarray(i, Math.min(i + piece, b.length))));
  return s.digestHex();
};

test('known vectors', () => {
  assert.equal(new Sha256().digestHex(), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(new Sha256().update(new TextEncoder().encode('abc')).digestHex(), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('matches node:crypto for every length across the padding boundaries and any piece size', () => {
  for (let n = 0; n <= 200; n++) {
    const b = randomBytes(n);
    for (const piece of [1, 7, 63, 64, 65, 1000]) assert.equal(mine(b, piece), ref(b), `n=${n} piece=${piece}`);
  }
});

test('matches for a large input fed in 8 MiB-like chunks', () => {
  const b = randomBytes(20_000_003);
  assert.equal(mine(b, 8 << 20), ref(b));
});

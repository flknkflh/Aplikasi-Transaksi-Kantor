// Web Worker that hosts pqcsign.wasm (the same Go `core` the desktop/Android
// clients use). It is the ONLY place a private key ever exists in plaintext:
// composite operations below unwrap the PIN-protected blob, use the key for one
// operation and zero it again before replying. The page never receives it.
//
// Terminating this worker (signer.js does so on timeout) aborts a hostile PDF
// that hangs the parser (upstream security finding SF-1).
'use strict';

importScripts('wasm_exec.js');

let ready = null;

function boot() {
  if (ready) return ready;
  ready = new Promise((resolve, reject) => {
    self.__pqcsignReady = resolve;
    const go = new Go();
    WebAssembly.instantiateStreaming(fetch('pqcsign.wasm'), go.importObject)
      .then(({ instance }) => { go.run(instance); })
      .catch(reject);
  });
  return ready;
}

const wipe = (u8) => { if (u8 && u8.fill) u8.fill(0); };

// Errors cross postMessage as plain objects (Error instances lose `code`).
function pack(err) {
  return { message: (err && err.message) || String(err), code: (err && err.code) || '' };
}

const ops = {
  version: () => self.pqcsign.version(),

  // New device key, wrapped under the PIN, plus the CSR proving possession.
  async enroll({ pin, request }) {
    const key = await pqcsign.generateKey();
    try {
      const publicKeyPEM = await pqcsign.exportPublicKey(key);
      const csr = await pqcsign.createCSR(key, JSON.stringify(request));
      const blob = await pqcsign.protectKey(key, pin);
      return { blob, csr, publicKeyPEM };
    } finally { wipe(key); }
  },

  // Verifies the PIN without doing anything else (used before a reservation is made).
  async checkPIN({ blob, pin }) {
    wipe(await pqcsign.unprotectKey(blob, pin));
    return true;
  },

  // The issued certificate must belong to the key held on this device.
  async certMatchesKey({ blob, pin, certPEM }) {
    const key = await pqcsign.unprotectKey(blob, pin);
    try { return await pqcsign.certMatchesKey(key, certPEM); } finally { wipe(key); }
  },

  // Sign, then verify the result against the pinned Root CA before returning
  // it (upstream: local verification before upload, Rencana V1 §15.2 step 10).
  async sign({ blob, pin, pdf, chainPEM, rootPEM, options, verify }) {
    const key = await pqcsign.unprotectKey(blob, pin);
    let out;
    try {
      if (!(await pqcsign.certMatchesKey(key, chainPEM))) {
        throw new Error('sertifikat tidak cocok dengan kunci di perangkat ini');
      }
      out = await pqcsign.signPDF(pdf, key, chainPEM, JSON.stringify(options || {}));
    } finally { wipe(key); }
    let verdict = null;
    if (verify !== false) {
      verdict = JSON.parse(await pqcsign.verifyPDF(out.signedPdf, rootPEM, null));
      if (!verdict.valid) {
        const first = verdict.signatures && verdict.signatures[0] && verdict.signatures[0].errors;
        throw new Error('verifikasi lokal gagal, tidak diunggah: ' + ((first && first[0]) || 'tidak valid'));
      }
    }
    return { signedPdf: out.signedPdf, result: JSON.parse(out.result), verdict };
  },

  changePIN: ({ blob, oldPIN, newPIN }) => pqcsign.changePIN(blob, oldPIN, newPIN),
  verify: ({ pdf, rootPEM, crlPEM }) => pqcsign.verifyPDF(pdf, rootPEM, crlPEM || null),
  sha512: ({ data }) => pqcsign.sha512Hex(data),
  certFingerprint: ({ pem }) => pqcsign.certFingerprint(pem),
  checkDeviceCertificate: ({ pem }) => pqcsign.checkDeviceCertificate(pem),
  listSignatures: ({ pdf }) => pqcsign.listSignatures(pdf),
};

self.onmessage = async (ev) => {
  const { id, op, args } = ev.data;
  try {
    await boot();
    const fn = ops[op];
    if (!fn) throw new Error('operasi tidak dikenal: ' + op);
    const value = await fn(args || {});
    // Transfer big binary results instead of copying them.
    const transfer = [];
    if (value && value.signedPdf) transfer.push(value.signedPdf.buffer);
    self.postMessage({ id, ok: true, value }, transfer);
  } catch (e) {
    self.postMessage({ id, ok: false, error: pack(e) });
  }
};

// Promise RPC to worker.js. If an operation exceeds its timeout the worker is
// terminated and a fresh one is started on the next call: this is how a hostile
// or corrupt PDF that hangs the parser is aborted (SF-1).
'use strict';

let worker = null;
let seq = 0;
const pending = new Map();

function spawn() {
  const w = new Worker('worker.js');
  w.onmessage = (ev) => {
    const { id, ok, value, error } = ev.data;
    const p = pending.get(id);
    if (!p) return;
    pending.delete(id);
    clearTimeout(p.timer);
    if (ok) return p.resolve(value);
    const e = new Error(error.message);
    if (error.code) e.code = error.code;
    p.reject(e);
  };
  w.onerror = (ev) => failAll(new Error('worker gagal: ' + (ev.message || 'kesalahan tidak diketahui')));
  return w;
}

function failAll(err) {
  for (const [id, p] of pending) { clearTimeout(p.timer); p.reject(err); pending.delete(id); }
  if (worker) { worker.terminate(); worker = null; }
}

// call(op, args, { timeoutMs, transfer })
export function call(op, args, opts = {}) {
  const timeoutMs = opts.timeoutMs || 120000;
  if (!worker) worker = spawn();
  const id = ++seq;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      failAll(new Error('operasi melebihi batas waktu dan dihentikan (' + op + ')'));
    }, timeoutMs);
    pending.set(id, { resolve, reject, timer });
    worker.postMessage({ id, op, args }, opts.transfer || []);
  });
}

// Drop the worker (and with it any wasm memory) — used on logout/lock.
export function shutdown() { failAll(new Error('dihentikan')); }

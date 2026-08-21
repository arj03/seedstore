// Test-only host-owned instance of the reputation WASM (README §13, §17). Lets a
// test drive the decayed-reciprocity counters directly — it is pure (no host
// calls), so it instantiates with only the env imports. The runtime never uses
// this: a node reaches reputation as an installed kernel handler over MODULE_CALL
// (host/storage-node.ts score()), so this client lives with its test. The ABI
// (op-tag layout) is owned by assembly/reputation/index.ts.
//
// The module is now a PURE TRANSFORM — the client holds per-peer accumulators
// (serve, miss, last) in a Map, and the module computes updated accumulators
// from them (per PROTOCOL.md contract: WASM modules are restartable).

const OP_OBSERVE = 1, OP_SCORE = 2;

export class ReputationClient {
  exports;
  scratch = 0;
  peers = new Map(); // peerHex → {serve, miss, last}

  static async load(bytes) {
    const c = new ReputationClient();
    const mod = new WebAssembly.Module(bytes);
    const inst = new WebAssembly.Instance(mod, {
      env: {
        abort: (_m, _f, l, col) => { throw new Error(`reputation abort ${l}:${col}`); },
        seed: () => Date.now(),
        trace: () => {},
      },
    });
    c.exports = inst.exports;
    c.scratch = c.exports.scratch.value;
    return c;
  }

  write(b) {
    new Uint8Array(this.exports.memory.buffer, this.scratch, b.length).set(b);
    return b.length;
  }
  readF64(off = 0) {
    return new DataView(this.exports.memory.buffer, this.scratch + off, 8).getFloat64(0, true);
  }
  readU64BE(off) {
    const v = new DataView(this.exports.memory.buffer, this.scratch + off, 8);
    const hi = v.getUint32(0, false);
    const lo = v.getUint32(4, false);
    return hi * 0x100000000 + lo;
  }
  u64be(out, off, ms) {
    const hi = Math.floor(ms / 0x100000000);
    out[off] = (hi >>> 24) & 255; out[off + 1] = (hi >>> 16) & 255;
    out[off + 2] = (hi >>> 8) & 255; out[off + 3] = hi & 255;
    const lo = ms >>> 0;
    out[off + 4] = (lo >>> 24) & 255; out[off + 5] = (lo >>> 16) & 255;
    out[off + 6] = (lo >>> 8) & 255; out[off + 7] = lo & 255;
  }
  f64le(out, off, v) {
    const view = new DataView(out.buffer, out.byteOffset + off, 8);
    view.setFloat64(0, v, true);
  }
  peerHex(peerPk) {
    const chars = "0123456789abcdef";
    let hex = "";
    for (let i = 0; i < peerPk.length; i++) {
      const b = peerPk[i];
      hex += chars[(b >> 4) & 15] + chars[b & 15];
    }
    return hex;
  }

  pruneStale(now) {
    const HALF_LIFE_MS = 7 * 24 * 3600 * 1000;
    const LN2 = 0.6931471805599453;
    const THRESHOLD = 1 / 65536;
    for (const [key, rep] of this.peers) {
      const dt = now - rep.last;
      const factor = dt > 0 ? Math.exp(-LN2 * dt / HALF_LIFE_MS) : 1;
      if ((rep.serve + rep.miss) * factor <= THRESHOLD) this.peers.delete(key);
    }
  }

  /** Record a verification-fetch outcome for a peer (§8, §13). */
  observe(peerPk, nowMs, pass) {
    const hex = this.peerHex(peerPk);
    let rep = this.peers.get(hex);
    if (rep === undefined) {
      this.pruneStale(nowMs);
      rep = { serve: 0, miss: 0, last: 0 };
      this.peers.set(hex, rep);
    }

    // Build request: [op u8][serve f64 LE][miss f64 LE][last u64 BE][now u64 BE][result u8]
    const req = new Uint8Array(1 + 8 + 8 + 8 + 8 + 1);
    req[0] = OP_OBSERVE;
    this.f64le(req, 1, rep.serve);
    this.f64le(req, 9, rep.miss);
    this.u64be(req, 17, rep.last);
    this.u64be(req, 25, nowMs);
    req[33] = pass ? 1 : 0;

    this.exports.handle(this.write(req));

    // Parse response: [serve f64 LE][miss f64 LE][last u64 BE][score f64 LE]
    rep.serve = this.readF64(0);
    rep.miss = this.readF64(8);
    rep.last = this.readU64BE(16);
    const score = this.readF64(24);
    return score;
  }

  /** Decayed reciprocity score for a peer at `nowMs` (§13.1). Read-only: a never-observed
   *  peer scores off the zero accumulator without entering `peers` (Sybil-local, §13 —
   *  scoring a stranger must stay free of side effects). */
  score(peerPk, nowMs) {
    const hex = this.peerHex(peerPk);
    const rep = this.peers.get(hex) ?? { serve: 0, miss: 0, last: 0 };

    // Build request: [op u8][serve f64 LE][miss f64 LE][last u64 BE][now u64 BE]
    const req = new Uint8Array(1 + 8 + 8 + 8 + 8);
    req[0] = OP_SCORE;
    this.f64le(req, 1, rep.serve);
    this.f64le(req, 9, rep.miss);
    this.u64be(req, 17, rep.last);
    this.u64be(req, 25, nowMs);

    this.exports.handle(this.write(req));

    // Parse response: [score f64 LE]
    return this.readF64(0);
  }

  count() {
    return this.peers.size;
  }

  reset() {
    this.peers.clear();
  }
}

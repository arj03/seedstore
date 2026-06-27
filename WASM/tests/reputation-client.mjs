// Test-only host-owned instance of the reputation WASM (README §13, §17). Lets a
// test drive the decayed-reciprocity counters directly — it is pure (no host
// calls), so it instantiates with only the env imports. The runtime never uses
// this: a node reaches reputation as an installed kernel handler over MODULE_CALL
// (host/storage-node.ts score()), so this client lives with its test. The ABI
// (op-tag layout) is owned by assembly/reputation/index.ts.

const OP_OBSERVE = 1, OP_SCORE = 2, OP_COUNT = 3, OP_RESET = 4;

export class ReputationClient {
  exports;
  scratch = 0;

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
  readF64() {
    return new DataView(this.exports.memory.buffer, this.scratch, 8).getFloat64(0, true);
  }
  u64be(out, off, ms) {
    const hi = Math.floor(ms / 0x100000000);
    out[off] = (hi >>> 24) & 255; out[off + 1] = (hi >>> 16) & 255;
    out[off + 2] = (hi >>> 8) & 255; out[off + 3] = hi & 255;
    const lo = ms >>> 0;
    out[off + 4] = (lo >>> 24) & 255; out[off + 5] = (lo >>> 16) & 255;
    out[off + 6] = (lo >>> 8) & 255; out[off + 7] = lo & 255;
  }

  /** Record a verification-fetch outcome for a peer (§8, §13). */
  observe(peerPk, nowMs, pass) {
    const req = new Uint8Array(1 + 32 + 8 + 1);
    req[0] = OP_OBSERVE; req.set(peerPk, 1);
    this.u64be(req, 33, nowMs);
    req[41] = pass ? 1 : 0;
    this.exports.handle(this.write(req));
    return this.readF64();
  }

  /** Decayed reciprocity score for a peer at `nowMs` (§13.1). */
  score(peerPk, nowMs) {
    const req = new Uint8Array(1 + 32 + 8);
    req[0] = OP_SCORE; req.set(peerPk, 1);
    this.u64be(req, 33, nowMs);
    this.exports.handle(this.write(req));
    return this.readF64();
  }

  count() {
    this.write(new Uint8Array([OP_COUNT]));
    const len = this.exports.handle(1);
    if (len !== 4) return 0;
    const v = new DataView(this.exports.memory.buffer, this.scratch, 4);
    return v.getUint32(0, false);
  }

  reset() {
    this.write(new Uint8Array([OP_RESET]));
    this.exports.handle(1);
  }
}

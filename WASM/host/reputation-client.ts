// Host-owned instance of the reputation WASM (README §13, §17). The node's
// orchestration records witnessed verification-fetch outcomes here and queries
// scores to rank peers for placement (§6), admission (§14), and fetch order
// (§7). Pure — no host calls — so it instantiates with only the env imports.

const OP_OBSERVE = 1, OP_SCORE = 2, OP_COUNT = 3, OP_RESET = 4;

interface RepExports {
  memory: WebAssembly.Memory;
  scratch: WebAssembly.Global;
  handle(input_len: number): number;
}

export class ReputationClient {
  private exports!: RepExports;
  private scratch = 0;

  static async load(bytes: Uint8Array): Promise<ReputationClient> {
    const c = new ReputationClient();
    const mod = new WebAssembly.Module(bytes as BufferSource);
    const inst = new WebAssembly.Instance(mod, {
      env: {
        abort: (_m: number, _f: number, l: number, col: number) => { throw new Error(`reputation abort ${l}:${col}`); },
        seed: () => Date.now(),
        trace: () => {},
      },
    });
    c.exports = inst.exports as unknown as RepExports;
    c.scratch = c.exports.scratch.value as number;
    return c;
  }

  private write(b: Uint8Array): number {
    new Uint8Array(this.exports.memory.buffer, this.scratch, b.length).set(b);
    return b.length;
  }
  private readF64(): number {
    return new DataView(this.exports.memory.buffer, this.scratch, 8).getFloat64(0, true);
  }
  private u64be(out: Uint8Array, off: number, ms: number): void {
    const hi = Math.floor(ms / 0x100000000);
    out[off] = (hi >>> 24) & 255; out[off + 1] = (hi >>> 16) & 255;
    out[off + 2] = (hi >>> 8) & 255; out[off + 3] = hi & 255;
    const lo = ms >>> 0;
    out[off + 4] = (lo >>> 24) & 255; out[off + 5] = (lo >>> 16) & 255;
    out[off + 6] = (lo >>> 8) & 255; out[off + 7] = lo & 255;
  }

  /** Record a verification-fetch outcome for a peer (§8, §13). */
  observe(peerPk: Uint8Array, nowMs: number, pass: boolean): number {
    const req = new Uint8Array(1 + 32 + 8 + 1);
    req[0] = OP_OBSERVE; req.set(peerPk, 1);
    this.u64be(req, 33, nowMs);
    req[41] = pass ? 1 : 0;
    this.exports.handle(this.write(req));
    return this.readF64();
  }

  /** Decayed reciprocity score for a peer at `nowMs` (§13.1). */
  score(peerPk: Uint8Array, nowMs: number): number {
    const req = new Uint8Array(1 + 32 + 8);
    req[0] = OP_SCORE; req.set(peerPk, 1);
    this.u64be(req, 33, nowMs);
    this.exports.handle(this.write(req));
    return this.readF64();
  }

  count(): number {
    this.write(new Uint8Array([OP_COUNT]));
    const len = this.exports.handle(1);
    if (len !== 4) return 0;
    const v = new DataView(this.exports.memory.buffer, this.scratch, 4);
    return v.getUint32(0, false);
  }

  reset(): void {
    this.write(new Uint8Array([OP_RESET]));
    this.exports.handle(1);
  }
}

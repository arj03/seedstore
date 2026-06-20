// Host-owned instance of the codec WASM (README §17). The node's orchestration
// (coordinator/repair) is host-side and drives erasure coding synchronously, so
// it instantiates the same codec bytes directly and provides the one host call
// the codec makes — kernel.call("crypto.hash", …) for the block-id op — by
// routing it to the crypto service. The codec stays pure either way (§2): it
// computes RS over the bytes it is given and reaches nothing else.
//
// (The codec is *also* installed as a kernel handler on the node, so other WASM
// handlers could call it via kernel.call; that path is exercised by the
// bridges/storage tests. This client is the host-side fast path.)

import type { Crypto } from "./crypto.js";
import { writeU32BE } from "./util.js";

const OP_INFO = 0, OP_ENCODE = 1, OP_DECODE = 2, OP_BLOCKID = 3;

interface CodecExports {
  memory: WebAssembly.Memory;
  scratch: WebAssembly.Global;
  configure(input_len: number): void;
  handle(input_len: number): number;
}

export class CodecClient {
  private exports!: CodecExports;
  private scratch = 0;
  private constructor(private readonly crypto: Crypto) {}

  /** Instantiate the codec and plant the crypto.hash name it calls for ids. */
  static async load(codecBytes: Uint8Array, crypto: Crypto, cryptoHashName: Uint8Array): Promise<CodecClient> {
    const c = new CodecClient(crypto);
    const mod = new WebAssembly.Module(codecBytes as BufferSource);
    const imports: WebAssembly.Imports = {
      kernel: {
        // The codec's only host call: genesis hashing. Write the digest back to
        // the codec's scratch, mirroring how KernelHost delivers a kernel.call
        // response to the caller's scratch region.
        call: (_sPtr: number, _sLen: number, payloadPtr: number, payloadLen: number): number => {
          const data = new Uint8Array(c.exports.memory.buffer, payloadPtr, payloadLen).slice();
          const digest = crypto.hash(data);
          new Uint8Array(c.exports.memory.buffer, c.scratch, digest.length).set(digest);
          return digest.length;
        },
      },
      env: {
        abort: (_m: number, _f: number, l: number, col: number) => { throw new Error(`codec abort ${l}:${col}`); },
        seed: () => Date.now(),
        trace: () => {},
      },
    };
    const inst = new WebAssembly.Instance(mod, imports);
    c.exports = inst.exports as unknown as CodecExports;
    c.scratch = c.exports.scratch.value as number;
    // Plant the hash bridge name (the value is irrelevant to this host-owned
    // instance, but the codec guards on a non-empty name).
    const cfg = new Uint8Array(1 + cryptoHashName.length);
    cfg[0] = cryptoHashName.length; cfg.set(cryptoHashName, 1);
    c.write(cfg);
    c.exports.configure(cfg.length);
    return c;
  }

  private write(bytes: Uint8Array): number {
    new Uint8Array(this.exports.memory.buffer, this.scratch, bytes.length).set(bytes);
    return bytes.length;
  }
  private read(len: number): Uint8Array {
    return new Uint8Array(this.exports.memory.buffer, this.scratch, len).slice();
  }
  /** A writable view over the first `len` bytes of scratch — lets the RS paths
   *  stage their request in place instead of building a concatenated buffer and
   *  copying it in (the codec's scratch never moves: it is heap.alloc'd once at
   *  module init and the codec never grows memory). */
  private scratchView(len: number): Uint8Array {
    return new Uint8Array(this.exports.memory.buffer, this.scratch, len);
  }
  /** Slice `len` bytes of scratch into one owned block per blockSize. Each slice
   *  is a single copy straight out of wasm memory — no intermediate whole-buffer
   *  read() + re-slice (which copied the output twice). */
  private readBlocks(len: number, blockSize: number): Uint8Array[] {
    const src = this.scratchView(len);
    const out: Uint8Array[] = [];
    for (let o = 0; o < len; o += blockSize) out.push(src.slice(o, o + blockSize));
    return out;
  }

  info(): { version: number; polyLo: number; polyHi: number; maxK: number; maxM: number } {
    this.write(new Uint8Array([OP_INFO]));
    const r = this.read(this.exports.handle(1));
    return { version: r[0], polyLo: r[1], polyHi: r[2], maxK: r[3], maxM: r[4] };
  }

  /** block_id via the codec's host-crypto path (§4.2). Equivalent to
   *  crypto.blockId; used where the WASM path is what we want to exercise. */
  blockId(bytes: Uint8Array): Uint8Array {
    const req = new Uint8Array(1 + bytes.length);
    req[0] = OP_BLOCKID; req.set(bytes, 1);
    const len = this.exports.handle(this.write(req));
    if (len !== 32) throw new Error("codec block-id failed");
    return this.read(32);
  }

  /** Systematic RS encode: k data blocks → m parity blocks (§4.1). Stages the
   *  request directly in the codec's scratch — one copy of the k data blocks
   *  into wasm, versus the old concat-then-write which copied them twice. */
  rsEncode(k: number, m: number, blockSize: number, dataBlocks: Uint8Array[]): Uint8Array[] {
    if (dataBlocks.length !== k) throw new Error("rsEncode: need exactly k data blocks");
    const reqLen = 7 + k * blockSize;
    const buf = this.scratchView(reqLen);
    buf[0] = OP_ENCODE; buf[1] = k; buf[2] = m; writeU32BE(buf, 3, blockSize);
    let off = 7;
    for (const b of dataBlocks) { buf.set(b, off); off += b.length; }
    const len = this.exports.handle(reqLen);
    if (len !== m * blockSize) throw new Error(`rsEncode failed (got ${len})`);
    return this.readBlocks(len, blockSize);
  }

  /** RS decode: any k present blocks → the k data blocks (§4.1, §7). Each
   *  present entry carries its generator-row index (0..k data, k..n parity).
   *  Staged in place in scratch, same single-copy discipline as rsEncode. */
  rsDecode(k: number, m: number, blockSize: number, present: { index: number; bytes: Uint8Array }[]): Uint8Array[] {
    if (present.length < k) throw new Error("rsDecode: need at least k present blocks");
    const use = present.slice(0, k);
    const cnt = use.length;
    const reqLen = 8 + cnt + cnt * blockSize;
    const buf = this.scratchView(reqLen);
    buf[0] = OP_DECODE; buf[1] = k; buf[2] = m; writeU32BE(buf, 3, blockSize); buf[7] = cnt;
    for (let i = 0; i < cnt; i++) buf[8 + i] = use[i].index;
    let off = 8 + cnt;
    for (const p of use) { buf.set(p.bytes, off); off += p.bytes.length; }
    const len = this.exports.handle(reqLen);
    if (len !== k * blockSize) throw new Error(`rsDecode failed (got ${len})`);
    return this.readBlocks(len, blockSize);
  }
}

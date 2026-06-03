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
import { concatBytes, writeU32BE } from "./util.js";

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

  /** Systematic RS encode: k data blocks → m parity blocks (§4.1). */
  rsEncode(k: number, m: number, blockSize: number, dataBlocks: Uint8Array[]): Uint8Array[] {
    if (dataBlocks.length !== k) throw new Error("rsEncode: need exactly k data blocks");
    const header = new Uint8Array(7);
    header[0] = OP_ENCODE; header[1] = k; header[2] = m; writeU32BE(header, 3, blockSize);
    const req = concatBytes([header, ...dataBlocks]);
    const len = this.exports.handle(this.write(req));
    if (len !== m * blockSize) throw new Error(`rsEncode failed (got ${len})`);
    const parity = this.read(len);
    return splitBlocks(parity, blockSize);
  }

  /** RS decode: any k present blocks → the k data blocks (§4.1, §7). Each
   *  present entry carries its generator-row index (0..k data, k..n parity). */
  rsDecode(k: number, m: number, blockSize: number, present: { index: number; bytes: Uint8Array }[]): Uint8Array[] {
    if (present.length < k) throw new Error("rsDecode: need at least k present blocks");
    const use = present.slice(0, k);
    const header = new Uint8Array(8);
    header[0] = OP_DECODE; header[1] = k; header[2] = m; writeU32BE(header, 3, blockSize);
    header[7] = use.length;
    const idx = new Uint8Array(use.length);
    for (let i = 0; i < use.length; i++) idx[i] = use[i].index;
    const req = concatBytes([header, idx, ...use.map((p) => p.bytes)]);
    const len = this.exports.handle(this.write(req));
    if (len !== k * blockSize) throw new Error(`rsDecode failed (got ${len})`);
    return splitBlocks(this.read(len), blockSize);
  }
}

function splitBlocks(buf: Uint8Array, blockSize: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let o = 0; o < buf.length; o += blockSize) out.push(buf.slice(o, o + blockSize));
  return out;
}

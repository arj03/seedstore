// Test-only host-owned instance of the codec WASM (README §17). Lets a test drive
// the Reed–Solomon codec directly — instantiating the same codec.wasm and serving
// the one host call it makes (kernel.call("crypto.hash", …) for the block-id op) by
// routing it to the crypto service. The runtime never uses this: a node reaches the
// codec as an installed kernel handler over MODULE_CALL (host/storage-node.ts), so
// this client lives with the tests that exercise the wasm in isolation. The ABI
// (op-tag layout) is owned by assembly/codec/index.ts.

import { writeU32BE } from "../build/host/util.js";

const OP_INFO = 0, OP_ENCODE = 1, OP_DECODE = 2, OP_BLOCKID = 3;

export class CodecClient {
  #crypto;
  exports;
  scratch = 0;

  constructor(crypto) { this.#crypto = crypto; }

  /** Instantiate the codec and plant the crypto.hash name it calls for ids. */
  static async load(codecBytes, crypto, cryptoHashName) {
    const c = new CodecClient(crypto);
    const mod = new WebAssembly.Module(codecBytes);
    const imports = {
      kernel: {
        // The codec's only host call: genesis hashing. Write the digest back to
        // the codec's scratch, mirroring how KernelHost delivers a kernel.call
        // response to the caller's scratch region.
        call: (_sPtr, _sLen, payloadPtr, payloadLen) => {
          const data = new Uint8Array(c.exports.memory.buffer, payloadPtr, payloadLen).slice();
          const digest = crypto.hash(data);
          new Uint8Array(c.exports.memory.buffer, c.scratch, digest.length).set(digest);
          return digest.length;
        },
      },
      env: {
        abort: (_m, _f, l, col) => { throw new Error(`codec abort ${l}:${col}`); },
        seed: () => Date.now(),
        trace: () => {},
      },
    };
    const inst = new WebAssembly.Instance(mod, imports);
    c.exports = inst.exports;
    c.scratch = c.exports.scratch.value;
    // Plant the hash bridge name (the value is irrelevant to this host-owned
    // instance, but the codec guards on a non-empty name).
    const cfg = new Uint8Array(1 + cryptoHashName.length);
    cfg[0] = cryptoHashName.length; cfg.set(cryptoHashName, 1);
    c.write(cfg);
    c.exports.configure(cfg.length);
    return c;
  }

  write(bytes) {
    new Uint8Array(this.exports.memory.buffer, this.scratch, bytes.length).set(bytes);
    return bytes.length;
  }
  read(len) {
    return new Uint8Array(this.exports.memory.buffer, this.scratch, len).slice();
  }
  /** A writable view over the first `len` bytes of scratch — lets the RS paths
   *  stage their request in place instead of building a concatenated buffer and
   *  copying it in (the codec's scratch never moves: it is heap.alloc'd once at
   *  module init and the codec never grows memory). */
  scratchView(len) {
    return new Uint8Array(this.exports.memory.buffer, this.scratch, len);
  }
  /** Slice `len` bytes of scratch into one owned block per blockSize. Each slice
   *  is a single copy straight out of wasm memory — no intermediate whole-buffer
   *  read() + re-slice (which copied the output twice). */
  readBlocks(len, blockSize) {
    const src = this.scratchView(len);
    const out = [];
    for (let o = 0; o < len; o += blockSize) out.push(src.slice(o, o + blockSize));
    return out;
  }

  info() {
    this.write(new Uint8Array([OP_INFO]));
    const r = this.read(this.exports.handle(1));
    return { version: r[0], polyLo: r[1], polyHi: r[2], maxK: r[3], maxM: r[4] };
  }

  /** block_id via the codec's host-crypto path (§4.2). Equivalent to
   *  crypto.hash; used where the WASM path is what we want to exercise. */
  blockId(bytes) {
    const req = new Uint8Array(1 + bytes.length);
    req[0] = OP_BLOCKID; req.set(bytes, 1);
    const len = this.exports.handle(this.write(req));
    if (len !== 32) throw new Error("codec block-id failed");
    return this.read(32);
  }

  /** Systematic RS encode: k data blocks → m parity blocks (§4.1). Stages the
   *  request directly in the codec's scratch — one copy of the k data blocks
   *  into wasm, versus the old concat-then-write which copied them twice. */
  rsEncode(k, m, blockSize, dataBlocks) {
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
  rsDecode(k, m, blockSize, present) {
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

// Focused correctness tests for the codec WASM module (Reed–Solomon over
// GF(2^8), README §4.1). Loads build/codec.wasm directly with a minimal
// kernel.call import that routes the block-id op to libsodium BLAKE2b-256 —
// the storage content hash (§4.2). Exhaustive over loss patterns for small
// codes, randomized for the defaults.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadSodium } from "seedkernel-wasm";

const sodium = await loadSodium();

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");

const OP_INFO = 0, OP_ENCODE = 1, OP_DECODE = 2, OP_BLOCKID = 3;

export async function loadCodec() {
  await sodium.ready;
  const bytes = readFileSync(join(root, "build/codec.wasm"));
  let inst;
  const imports = {
    kernel: {
      // The only host call codec makes: crypto.hash (BLAKE2b-256). The
      // request bytes are at payloadPtr; write the 32-byte digest to scratch.
      call: (_schemaPtr, _schemaLen, payloadPtr, payloadLen) => {
        const mem = new Uint8Array(inst.exports.memory.buffer);
        const data = mem.slice(payloadPtr, payloadPtr + payloadLen);
        const digest = sodium.crypto_generichash(32, data); // BLAKE2b-256 (the storage content hash)
        new Uint8Array(inst.exports.memory.buffer, scratch, digest.length).set(digest);
        return digest.length;
      },
    },
    env: {
      abort: (_m, _f, l, c) => { throw new Error(`codec abort ${l}:${c}`); },
      seed: () => Date.now(),
      trace: () => {},
    },
  };
  const mod = new WebAssembly.Module(bytes);
  inst = new WebAssembly.Instance(mod, imports);
  const scratch = inst.exports.scratch.value;

  const writeReq = (bytes) => {
    new Uint8Array(inst.exports.memory.buffer, scratch, bytes.length).set(bytes);
    return bytes.length;
  };
  const readResp = (len) =>
    new Uint8Array(inst.exports.memory.buffer, scratch, len).slice();

  // Plant a (dummy here) crypto.hash name via configure.
  const name = sodium.crypto_hash_sha3256(new TextEncoder().encode("crypto.hash"));
  const cfg = new Uint8Array(1 + name.length);
  cfg[0] = name.length; cfg.set(name, 1);
  writeReq(cfg);
  inst.exports.configure(cfg.length);

  const u32be = (v) => [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];

  return {
    info() {
      writeReq(new Uint8Array([OP_INFO]));
      return readResp(inst.exports.handle(1));
    },
    encode(k, m, bs, data /* k*bs */) {
      const req = new Uint8Array(7 + data.length);
      req[0] = OP_ENCODE; req[1] = k; req[2] = m; req.set(u32be(bs), 3);
      req.set(data, 7);
      const got = writeReq(req);
      const len = inst.exports.handle(got);
      return len > 0 ? readResp(len) : null;
    },
    decode(k, m, bs, present /* [{index, bytes}] */) {
      const cnt = present.length;
      const req = new Uint8Array(8 + cnt + cnt * bs);
      req[0] = OP_DECODE; req[1] = k; req[2] = m; req.set(u32be(bs), 3);
      req[7] = cnt;
      for (let r = 0; r < cnt; r++) req[8 + r] = present[r].index;
      for (let r = 0; r < cnt; r++) req.set(present[r].bytes, 8 + cnt + r * bs);
      const got = writeReq(req);
      const len = inst.exports.handle(got);
      return len > 0 ? readResp(len) : null;
    },
    blockId(data) {
      const req = new Uint8Array(1 + data.length);
      req[0] = OP_BLOCKID; req.set(data, 1);
      const got = writeReq(req);
      const len = inst.exports.handle(got);
      return len > 0 ? readResp(len) : null;
    },
  };
}

// Split a flat buffer into n blocks of bs bytes.
function blocks(buf, bs) {
  const out = [];
  for (let i = 0; i < buf.length; i += bs) out.push(buf.slice(i, i + bs));
  return out;
}
function concat(arr) {
  const total = arr.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arr) { out.set(a, o); o += a.length; }
  return out;
}
function eq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
// Iterate over every size-`pick` subset of [0,n).
function* combinations(n, pick) {
  const idx = Array.from({ length: pick }, (_, i) => i);
  while (true) {
    yield idx.slice();
    let i = pick - 1;
    while (i >= 0 && idx[i] === n - pick + i) i--;
    if (i < 0) return;
    idx[i]++;
    for (let j = i + 1; j < pick; j++) idx[j] = idx[j - 1] + 1;
  }
}

export async function run(t) {
  const codec = await loadCodec();

  t.group("codec: module info");
  {
    const info = codec.info();
    t.eq(info[0], 1, "version 1");
    t.eq(info[1], 0x1d, "poly low byte 0x1d");
    t.eq(info[2], 0x01, "poly high byte 0x01 (0x11D)");
  }

  t.group("codec: block-id equals the host content hash (BLAKE2b-256, §4.2)");
  {
    const data = new TextEncoder().encode("the quick brown fox");
    const id = codec.blockId(data);
    const expect = sodium.crypto_generichash(32, data);
    t.ok(id && eq(id, expect), "OP_BLOCKID routes through the crypto.hash bridge");
  }

  t.group("codec: encode is deterministic (keyless repair, §9)");
  {
    const k = 10, m = 6, bs = 64;
    const data = new Uint8Array(k * bs).map((_, i) => (i * 7 + 3) & 255);
    const p1 = codec.encode(k, m, bs, data);
    const p2 = codec.encode(k, m, bs, data);
    t.ok(p1 && p2 && eq(p1, p2), "same input → byte-identical parity");
    t.eq(p1.length, m * bs, "parity is m*bs bytes");
  }

  // Exhaustive any-k-of-n recovery for small codes across ALL loss patterns.
  for (const [k, m] of [[2, 2], [3, 2], [4, 3], [5, 3]]) {
    const n = k + m, bs = 32;
    t.group(`codec: RS(${k},${m}) recovers from every k-of-${n} subset`);
    const data = new Uint8Array(k * bs).map((_, i) => (i * 31 + 17) & 255);
    const parity = codec.encode(k, m, bs, data);
    const all = [...blocks(data, bs), ...blocks(parity, bs)]; // n blocks
    let subsets = 0, ok = 0;
    for (const subset of combinations(n, k)) {
      subsets++;
      const present = subset.map((index) => ({ index, bytes: all[index] }));
      const recovered = codec.decode(k, m, bs, present);
      if (recovered && eq(recovered, data)) ok++;
    }
    t.eq(ok, subsets, `all ${subsets} subsets reconstruct the original data`);
  }

  t.group("codec: block sizes not a multiple of 16 exercise the SIMD tail");
  {
    // bs % 16 != 0 forces the scalar remainder path after the v128 body.
    for (const bs of [17, 20, 31, 100, 255]) {
      const k = 4, m = 3, n = k + m;
      const data = new Uint8Array(k * bs).map((_, i) => (i * 37 + bs) & 255);
      const parity = codec.encode(k, m, bs, data);
      const all = [...blocks(data, bs), ...blocks(parity, bs)];
      // Drop the first two blocks; reconstruct from k others.
      const present = [...Array(n).keys()].slice(2, 2 + k).map((index) => ({ index, bytes: all[index] }));
      const recovered = codec.decode(k, m, bs, present);
      t.ok(recovered && eq(recovered, data), `bs=${bs}: encode+decode round trip (tail = ${bs % 16} bytes)`);
    }
  }

  t.group("codec: large blocks cross the register-blocked body + both tails");
  {
    // bs > 128 with awkward remainders exercises the 128-byte STRIDE body, then
    // the 16-byte SIMD remainder, then the scalar tail — all in one block — and
    // proves the stitched paths agree (the optimized multiply-accumulate).
    for (const bs of [128, 145, 159, 200, 257, 1024 + 53]) {
      const k = 6, m = 4, n = k + m;
      const data = new Uint8Array(k * bs).map((_, i) => (i * 2654435761) & 255);
      const parity = codec.encode(k, m, bs, data);
      const all = [...blocks(data, bs), ...blocks(parity, bs)];
      // Drop two data blocks → real matrix inversion with many nonzero coeffs.
      const present = [...Array(n).keys()].slice(2, 2 + k).map((index) => ({ index, bytes: all[index] }));
      const recovered = codec.decode(k, m, bs, present);
      t.ok(recovered && eq(recovered, data), `bs=${bs}: STRIDE+remainder+tail round trip`);
    }
  }

  t.group("codec: systematic — the k data blocks pass through verbatim");
  {
    const k = 6, m = 4, bs = 48;
    const data = new Uint8Array(k * bs).map((_, i) => (i * 13 + 5) & 255);
    const parity = codec.encode(k, m, bs, data);
    const all = [...blocks(data, bs), ...blocks(parity, bs)];
    // Decode using exactly the k data rows → must equal data with no GF work.
    const present = [0, 1, 2, 3, 4, 5].map((index) => ({ index, bytes: all[index] }));
    const recovered = codec.decode(k, m, bs, present);
    t.ok(recovered && eq(recovered, data), "data-only decode == data");
  }

  t.group("codec: defaults RS(10,6) randomized loss up to m=6");
  {
    const k = 10, m = 6, n = 16, bs = 256;
    let trials = 0, ok = 0;
    for (let trial = 0; trial < 40; trial++) {
      const data = new Uint8Array(k * bs);
      for (let i = 0; i < data.length; i++) data[i] = (Math.random() * 256) | 0;
      const parity = codec.encode(k, m, bs, data);
      const all = [...blocks(data, bs), ...blocks(parity, bs)];
      // Drop a random subset of up to m blocks.
      const drop = (Math.random() * (m + 1)) | 0;
      const order = [...Array(n).keys()].sort(() => Math.random() - 0.5);
      const lost = new Set(order.slice(0, drop));
      const present = [...Array(n).keys()]
        .filter((i) => !lost.has(i)).slice(0, k)
        .map((index) => ({ index, bytes: all[index] }));
      const recovered = codec.decode(k, m, bs, present);
      trials++;
      if (recovered && eq(recovered, data)) ok++;
    }
    t.eq(ok, trials, `all ${trials} randomized trials reconstruct`);
  }

  t.group("codec: re-encode after decode regenerates identical blocks (§9)");
  {
    const k = 10, m = 6, bs = 128;
    const data = new Uint8Array(k * bs).map((_, i) => (i * 101 + 7) & 255);
    const parity = codec.encode(k, m, bs, data);
    const all = [...blocks(data, bs), ...blocks(parity, bs)];
    // Lose data block 2 and parity block 1 (index k+1). Recover from k others.
    const lost = new Set([2, k + 1]);
    const present = [...Array(k + m).keys()]
      .filter((i) => !lost.has(i)).slice(0, k)
      .map((index) => ({ index, bytes: all[index] }));
    const recoveredData = codec.decode(k, m, bs, present);
    t.ok(recoveredData && eq(recoveredData, data), "data recovered");
    // Re-encode and confirm the regenerated parity block 1 is byte-identical.
    const reparity = codec.encode(k, m, bs, recoveredData);
    t.ok(eq(reparity, parity), "regenerated parity == original (hashes to same block_id)");
  }
}

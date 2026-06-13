// Throughput benchmark for the Reed–Solomon codec on a 100 MB file.
// Not part of the test suite. Run: node tests/bench.mjs
//
// Measures pure RS work (the WASM codec + the JS<->WASM boundary copies), and
// for context the full PUT-style pipeline cost of also hashing (block_id) and
// stream-encrypting every block.

import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { Crypto, DOMAIN_BODY } from "../build/host/crypto.js";
import { CodecClient } from "../build/host/codec-client.js";
import { storageNames } from "../build/host/names.js";
import { loadHost } from "./helpers.mjs";
import { loadSodium } from "seedkernel-wasm";

const sodium = await loadSodium();
const crypto = new Crypto(sodium);
const { host } = await loadHost();
const names = storageNames(host);
const codec = await CodecClient.load(new Uint8Array(readFileSync("build/codec.wasm")), crypto, names.cryptoHash);

const MB = 1024 * 1024;
const K = 10, M = 6, B = 64 * 1024;       // defaults RS(10,6), 64 KB blocks
const FILE = 100 * MB;
const chunkData = K * B;                   // 640 KB of data per chunk
const numChunks = Math.ceil(FILE / chunkData);

// One reusable 100 MB buffer (content is irrelevant to RS timing — a cheap
// deterministic fill avoids a slow byte-by-byte random gen).
const data = new Uint8Array(FILE);
for (let i = 0; i < FILE; i++) data[i] = (i * 1103515245 + 12345) & 255;

function split(buf, off, n, bs) {
  const out = [];
  for (let i = 0; i < n; i++) out.push(buf.subarray(off + i * bs, off + (i + 1) * bs));
  return out;
}

// Warm up.
{ const blocks = split(data, 0, K, B); for (let i = 0; i < 5; i++) codec.rsEncode(K, M, B, blocks); }

// ── encode 100 MB ──────────────────────────────────────────────────────────
let t0 = performance.now();
for (let c = 0; c < numChunks; c++) {
  codec.rsEncode(K, M, B, split(data, c * chunkData, K, B));
}
let enc = performance.now() - t0;

// ── read, all k data present: systematic — just concatenate, no GF (§4.1, §7) ──
// This is the common read path: when every data block is retrievable the codec
// is never invoked.
t0 = performance.now();
let acc = 0;
for (let c = 0; c < numChunks; c++) {
  const blocks = split(data, c * chunkData, K, B);
  const out = new Uint8Array(chunkData);
  let o = 0;
  for (const b of blocks) { out.set(b, o); o += b.length; }
  acc += out[0];
}
let sysRead = performance.now() - t0;

// ── read, ONE block missing: the common failure is exactly one lost block per
// chunk (§6 puts one block per peer, §21). Decode from the k-1 surviving data
// blocks + one parity block. ──
const blocks0 = split(data, 0, K, B).map((b) => b.slice());
const parity0 = codec.rsEncode(K, M, B, blocks0);
const all0 = [...blocks0, ...parity0];
const present = [];
for (let i = 1; i < K; i++) present.push({ index: i, bytes: all0[i] }); // data rows 1..k-1 (block 0 lost)
present.push({ index: K, bytes: all0[K] });                             // one parity block fills in
t0 = performance.now();
for (let c = 0; c < numChunks; c++) codec.rsDecode(K, M, B, present);
let dec = performance.now() - t0;

// ── component breakdown (encrypt-only, hash-only) ──────────────────────────
const key = crypto.randomKey();
t0 = performance.now();
for (let c = 0; c < numChunks; c++) crypto.encrypt(key, DOMAIN_BODY, c, data.subarray(c * chunkData, (c + 1) * chunkData));
let encr = performance.now() - t0;

// Hash the n blocks of every chunk (data + parity = 1.6× the file).
let hsum = 0;
t0 = performance.now();
for (let c = 0; c < numChunks; c++) {
  for (let bl = 0; bl < K + M; bl++) {
    const off = c * chunkData + (bl % K) * B;
    hsum ^= crypto.hash(data.subarray(off, off + B))[0];
  }
}
let hsh = performance.now() - t0;

// ── full PUT-style pipeline: encrypt + hash every block + encode ───────────
t0 = performance.now();
for (let c = 0; c < numChunks; c++) {
  const ct = crypto.encrypt(key, DOMAIN_BODY, c, data.subarray(c * chunkData, (c + 1) * chunkData));
  const dataBlocks = split(ct, 0, K, B);
  const parity = codec.rsEncode(K, M, B, dataBlocks);
  for (const b of dataBlocks) crypto.hash(b);
  for (const b of parity) crypto.hash(b);
}
let full = performance.now() - t0;

const rate = (ms) => (FILE / MB / (ms / 1000)).toFixed(0);
console.log(`\nRS(${K},${M}), B=${B / 1024} KB, ${FILE / MB} MB → ${numChunks} chunks, ${1.6}x stored\n`);
console.log(`  WRITE`);
console.log(`    RS encode                    ${enc.toFixed(0).padStart(6)} ms   ${rate(enc).padStart(5)} MB/s`);
console.log(`    encrypt (xchacha20)          ${encr.toFixed(0).padStart(6)} ms   ${rate(encr).padStart(5)} MB/s`);
console.log(`    hash block-ids (BLAKE2b)  ${hsh.toFixed(0).padStart(6)} ms   ${(FILE * 1.6 / MB / (hsh / 1000)).toFixed(0).padStart(5)} MB/s   (hashes n blocks = 1.6×)  [acc ${hsum & 255}]`);
console.log(`    encrypt+hash+encode (full)   ${full.toFixed(0).padStart(6)} ms   ${rate(full).padStart(5)} MB/s`);
console.log(`  READ`);
console.log(`    all data present (concat)    ${sysRead.toFixed(0).padStart(6)} ms   ${rate(sysRead).padStart(5)} MB/s   ← common path, no GF`);
console.log(`    one block missing (decode)   ${dec.toFixed(0).padStart(6)} ms   ${rate(dec).padStart(5)} MB/s   ← common failure (§21)`);
console.log(`\nnode ${process.version}, single-threaded   (acc=${acc & 0xff})`);

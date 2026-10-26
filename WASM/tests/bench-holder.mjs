// HOLDER-SIDE STORE-processing throughput. bench.mjs measures the initiator's
// compute and bench-net.mjs measures round-trip economy; neither isolates what
// the RECEIVING side costs per block — the open question behind a live PUT
// that fills socket buffers (receiver-limited vs. path-limited). It measures holder
// STORE processing, on real disk when `disk` is passed. The verdict reports both conservative
// payload/wall throughput and the sum of the holders' independently measured
// active-window rates.
//
// Each holder runs in a process of its own (this script with `--holder`), reached over
// loopback TCP through the real transport, as a deployed holder is: a holder that blocks
// its loop on its own disk write stalls only itself, not the initiator or another holder.
// Each times every inbound request inside the guest's own `handle` (the `recv` half of
// Op.STATS): admit -> hash -> verify -> fs write -> reply, no initiator work.
//
// Per STORE'd block: BLAKE2b, one Ed25519 verify, the §6 sibling check against
// the holder-owned index, then one framed-record fsPut. Geometry defaults to the
// live deployment's (RS(1,1), 256 KiB blocks) for comparability with p2p-cli runs.
//
// NOT priced: a real network's latency and bandwidth, disk persistence unless `disk` is
// passed for a NodeFs temp dir, or a weaker deployment CPU. Read the result as an upper
// bound on holder ingest.
//
// Run:  node tests/bench-holder.mjs [fileMB] [blockKiB] [k] [m] [disk]
//   e.g. node tests/bench-holder.mjs 16            (the live geometry, in-RAM fs)
//        node tests/bench-holder.mjs 16 256 1 1 disk  (same, holders on real disk)
//        node tests/bench-holder.mjs 16 256 2 2    (RS(2,2) — 4 holders)

import { fork } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import {
  loadWasmBytes, loadSodium, PRODUCTION_BLOCK_SIZE, bootStorageNode, inProcessStandUp, inProcessHost,
  generateKeyPair, netAddr, netReady,
} from "../build/host/node.js";
import { bytesEqual } from "../build/host/util.js";
import { blockHashInput } from "../build/host/descriptor-core.js";
import { nodeRawFiles } from "seedkernel-wasm/fs-node";
import { nodeChannels } from "seedkernel-wasm/shell-node";

const FILE_MB = Number(process.argv[2] ?? 16);
const BLOCK_KIB = Number(process.argv[3] ?? PRODUCTION_BLOCK_SIZE / 1024);
const K = Number(process.argv[4] ?? 1);
const M = Number(process.argv[5] ?? 1);
const ON_DISK = process.argv.includes("disk");

const MB = 1024 * 1024;
const blockSize = BLOCK_KIB * 1024;
const fileBytes = Math.round(FILE_MB * MB);
const config = { k: K, m: M, blockSize, maxMessageBytes: 1 << 20 };

// MsgType (host/protocol.ts) — index the per-type timers.
const HAVE = 1, OFFER = 2, FETCH = 3, STORE = 4;
const TYPE_NAME = { [HAVE]: "HAVE", [OFFER]: "OFFER", [FETCH]: "FETCH", [STORE]: "STORE" };

const fmt = (n, d = 1) => n.toFixed(d);
const rate = (bytes, ms) => (ms <= 0 ? Infinity : bytes / MB / (ms / 1000));

const sodium = await loadSodium();
const wasm = await loadWasmBytes();

/** One node on real loopback TCP, on disk when `dir` is set. */
const bootNode = (dir) => bootStorageNode(dir ? (cfg) => inProcessHost(nodeRawFiles).standUp(cfg) : inProcessStandUp, {
  sodium,
  bundleBlob: wasm.bundleBlob,
  identity: generateKeyPair(sodium), dir,
  suppressLinkLog: true, channels: nodeChannels(),
  listen: [{ label: "tcp", host: "127.0.0.1", port: 0 }],
  config,
  // Generous: each holder takes ~fileBytes plus descriptors and record framing; a §14-full
  // holder would silently decline instead of measuring anything.
  quota: Math.max(64 * MB, fileBytes * 4),
  timeoutMs: 20000,
});

// A holder process: say where it listens, then answer each `stats` with Op.STATS. Its
// group is itself and the initiator whose key it was handed.
const holderArg = process.argv.indexOf("--holder");
if (holderArg >= 0) {
  const node = await bootNode(process.argv[holderArg + 1] || undefined);
  await node.setGroups({ bench: [process.argv[holderArg + 2], node.peerId] });
  process.on("message", async () => { process.send([...await node.stats()]); });
  process.send({ peerId: node.peerId, port: node.net.portOf("tcp") });
  await new Promise(() => {}); // until the bench kills it
}

// One initiator + exactly k+m holders, so every chunk's blocks fill the cohort and each
// holder takes one block per chunk (the §6 sibling rule) — the live shape. Only the
// holders need a real backend — the initiator stores nothing (durability is the
// cohort's), so putting it on disk would measure nothing and cost a temp dir.
const holders = K + M;
const tmpDirs = [];
const children = [];
const initiator = await bootNode();
for (let i = 0; i < holders; i++) {
  const dir = ON_DISK ? mkdtempSync(join(tmpdir(), "seedstore-bench-holder-")) : "";
  if (dir) tmpDirs.push(dir);
  const child = fork(fileURLToPath(import.meta.url), [...process.argv.slice(2), "--holder", dir, initiator.peerId]);
  const [{ peerId, port }] = await once(child, "message");
  children.push({ child, peerId });
  await netAddr(initiator.shell, peerId, `tcp://127.0.0.1:${port}`);
}
await netReady(initiator.shell);
const holderIds = children.map((c) => c.peerId);
await initiator.setGroups({ bench: [initiator.peerId, ...holderIds] });

/** One holder's received-request stats (the guest's read-and-clear Op.STATS), shaped
 *  as `{ [MsgType]: { n, ms, payloadBytes } }` for the per-type reporting below. */
async function holderStats(id) {
  const { child } = children.find((c) => c.peerId === id);
  child.send("stats");
  const [map] = await once(child, "message");
  const out = {};
  for (const [type, rs] of map) out[type] = { n: rs.recv, ms: rs.recvMs, payloadBytes: rs.recvBytes };
  return out;
}

const data = new Uint8Array(fileBytes);
for (let i = 0; i < fileBytes; i++) data[i] = (i * 1103515245 + 12345) & 255;

const numChunks = Math.ceil(Math.ceil(fileBytes / blockSize) / K);

console.log(`holder STORE-processing bench — RS(${K},${M}), ${BLOCK_KIB} KiB blocks, ${fmt(FILE_MB)} MB file`);
console.log(`  ${numChunks} chunks over ${holders} holder(s), ~1 MiB batches, one process per holder over loopback TCP`);
console.log(`  holder fs: ${ON_DISK ? "NodeFs (real disk, temp dir)" : "MemoryFs (in-RAM — pass `disk` for the honest write cost)"}\n`);

// Warm the initiator's codec/crypto so its cold-JIT tax doesn't land inside the measured
// window as backpressure. Holders warm themselves on their first few requests; the run is
// long enough that this is noise.
await initiator.warm();

const t0 = performance.now();
const put = await initiator.put(data);
const putMs = performance.now() - t0;

// ── holder ingest ──────────────────────────────────────────────────────────
// Each holder's guest timed every request it answered (the recv half of Op.STATS,
// read-and-cleared). The stats read here covers exactly the PUT above.
let storeMs = 0, storeBytes = 0, storeReqs = 0, offerMs = 0, offerReqs = 0, holderRateSum = 0;
console.log("per-holder request handling (time spent inside the confined guest's `handle`):");
for (const id of holderIds) {
  const s = await holderStats(id);
  const st = s[STORE] ?? { n: 0, ms: 0, payloadBytes: 0 };
  const of = s[OFFER] ?? { n: 0, ms: 0, payloadBytes: 0 };
  storeMs += st.ms; storeBytes += st.payloadBytes; storeReqs += st.n;
  holderRateSum += rate(st.payloadBytes, st.ms);
  offerMs += of.ms; offerReqs += of.n;
  const parts = [STORE, OFFER, HAVE].filter((ty) => s[ty]?.n).map((ty) => {
    const b = s[ty];
    return `${TYPE_NAME[ty]} ${b.n}× ${fmt(b.ms)}ms`;
  });
  console.log(`  ${id.slice(0, 8)}…  ${parts.join("  ")}`);
}

// Blocks, not messages: a ~1 MiB batch carries several 256 KiB blocks, and per-block cost
// is what scales with the file.
const totalBlocks = numChunks * holders;
// Bytes and elapsed handler time are both summed, so this is the weighted mean of the
// holders, each in its own process — not a serialized box rate.
const ingestMBs = rate(storeBytes, storeMs);
console.log(`\nSTORE (the ingest path — hash + descriptor verify + indexed sibling check + 1 fs write per block):`);
console.log(`  ${storeReqs} batched requests carrying ${totalBlocks} blocks (${fmt(storeBytes / MB)} MB of payload)`);
console.log(`  holder time total   ${fmt(storeMs)} ms  →  ${fmt(storeMs / Math.max(1, totalBlocks), 2)} ms per block`);
console.log(`  MEAN HOLDER RATE    ${fmt(ingestMBs, 1)} MB/s (weighted across the holders)`);
if (offerReqs) {
  console.log(`\nOFFER (admission only — same verify + sibling check, NO block hash, NO fs write):`);
  console.log(`  ${offerReqs} requests, ${fmt(offerMs)} ms total → ${fmt(offerMs / Math.max(1, totalBlocks), 2)} ms per offered block`);
  console.log(`  so hash + fs write ≈ ${fmt((storeMs - offerMs) / Math.max(1, totalBlocks), 2)} ms per block, verify + sibling ≈ ${fmt(offerMs / Math.max(1, totalBlocks), 2)} ms`);
}

// ── the crypto floor ───────────────────────────────────────────────────────
// What the two mandatory crypto ops alone cost, host-side, for the same block count —
// the floor the confined holder cannot go below. The gap between this and the measured
// per-block time is bridge crossings + QuickJS + fs, i.e. the part that is ours to fix.
{
  const block = data.subarray(0, blockSize);
  const msg = new Uint8Array(64);
  const kp = sodium.crypto_sign_keypair();
  const sig = sodium.crypto_sign_detached(msg, kp.privateKey);
  const reps = Math.min(totalBlocks, 400);
  // The holder names a block by hashing domain ‖ authorPk ‖ bytes (§4.2), not the
  // bytes alone — price both, so the binding's share of the floor is visible.
  let h0 = performance.now();
  for (let i = 0; i < reps; i++) sodium.crypto_generichash(32, block);
  const bareHashMs = (performance.now() - h0) / reps;
  h0 = performance.now();
  for (let i = 0; i < reps; i++) sodium.crypto_generichash(32, blockHashInput(kp.publicKey, block));
  const hashMs = (performance.now() - h0) / reps;
  h0 = performance.now();
  for (let i = 0; i < reps; i++) sodium.crypto_sign_verify_detached(sig, msg, kp.publicKey);
  const verifyMs = (performance.now() - h0) / reps;
  const floorMs = hashMs + verifyMs;
  console.log(`\ncrypto floor (host-side libsodium, same block size):`);
  console.log(`  block-id/block ${fmt(hashMs, 3)} ms + Ed25519 verify ${fmt(verifyMs, 3)} ms = ${fmt(floorMs, 3)} ms → ${fmt(rate(blockSize, floorMs), 0)} MB/s`);
  console.log(`  (the id's author binding is ${fmt(hashMs - bareHashMs, 3)} ms of that — a bare content hash would be ${fmt(bareHashMs, 3)} ms,`);
  console.log(`   i.e. ${fmt((hashMs - bareHashMs) / (storeMs / Math.max(1, totalBlocks)) * 100, 1)}% of what the holder actually spends per block)`);
  console.log(`  the holder COSTS ${fmt((storeMs / Math.max(1, totalBlocks)) / floorMs, 1)}× that floor — the excess is fs + seam crossings + QuickJS,`);
  console.log(`  i.e. the part that is ours to fix if holder ingest ever becomes the limit.`);
}

// ── GET side, for context ──────────────────────────────────────────────────
const g0 = performance.now();
const got = await initiator.get(put.root, put.key);
const getMs = performance.now() - g0;
let fetchMs = 0, fetchReqs = 0;
for (const id of holderIds) {
  const b = (await holderStats(id))[FETCH];
  if (b) { fetchMs += b.ms; fetchReqs += b.n; }
}
console.log(`\nFETCH (serve path, for contrast — a store read + a copy, no verify, no write):`);
console.log(`  ${fetchReqs} requests, ${fmt(fetchMs)} ms total → ${fmt(fetchMs / Math.max(1, totalBlocks), 2)} ms per block served`);

console.log(`\nwall-clock (the initiator here, each holder in its own process, over loopback TCP):`);
console.log(`  PUT ${fmt(putMs)} ms (${fmt(rate(fileBytes, putMs), 1)} MB/s)   GET ${fmt(getMs)} ms (${fmt(rate(fileBytes, getMs), 1)} MB/s)`);
console.log(`  holder share of PUT: ${fmt((storeMs + offerMs) / putMs * 100)}%`);
console.log(`  bytes verified: ${bytesEqual(got, data) ? "round-trip OK" : "MISMATCH"}`);

// Compare against a reference live run: the sum of the holders' observed rates for the
// active holder-window estimate, and total holder payload / whole PUT wall time as the
// deliberately conservative comparison.
const LIVE_WIRE_MBS = 7.2;   // 50 MB file, 100.2 MB on the wire in 13.87 s (p2p-cli, 2026-07-21)
const holderWindowMBs = holderRateSum;
const processMBs = rate(storeBytes, putMs);
const margin = processMBs / LIVE_WIRE_MBS;
console.log(`\nverdict vs a reference live run (${LIVE_WIRE_MBS} MB/s of wire into ONE box running the cohort):`);
console.log(`  whole-PUT floor     ${fmt(processMBs, 1)} MB/s (${fmt(margin, 1)}× demand): holder payload ÷ full PUT wall time`);
console.log(`  holder-window rate  ${fmt(holderWindowMBs, 1)} MB/s (${fmt(holderWindowMBs / LIVE_WIRE_MBS, 1)}× demand): sum of ${holders} holders' measured rates`);
console.log(margin > 3
  ? `  even the conservative comparison is ${fmt(margin, 1)}× live demand on THIS machine. For holder ingest to have been the limit,\n` +
    `  the holder box would have to be ~${fmt(margin, 0)}× slower at hash+verify+write than this one — and the\n` +
    `  ${ON_DISK ? "disk cost is already priced in" : "MemoryFs caveat still applies; re-run with `disk`"}. The untimed WS receive path is the remaining unknown.\n` +
    `  To close it properly, run this same bench ON the holder box and compare.`
  : `  the conservative comparison is only ${fmt(margin, 1)}× live demand — holder processing is a plausible limiter.`);

for (const { child } of children) {
  child.kill();
  await once(child, "exit");
}
for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
process.exit(0);

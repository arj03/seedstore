// HOLDER-SIDE STORE-processing throughput — the benchmark the repo was missing.
//
// bench.mjs measures the INITIATOR's compute (RS codec + hash + encrypt) and
// bench-net.mjs measures round-trip economy over a latency-bearing link. Neither
// isolates what the RECEIVING side costs per block, which is the open question left
// by the live PUT numbers: a 50 MB PUT to two WS holders sustains ~7.2 MB/s wire and
// fills our socket buffers (peak buffered 67.5 MB), which is equally consistent with
//   (1) receiver-limited — the holder ingests slowly and TCP backpressure fills us, or
//   (2) path-limited — the link carries ~62 Mbit for this traffic and full buffers are
//       just the consequence.
// Removing the sender-side window barrier changed neither the time nor the answer (see
// the note over put() in host/storage-node.ts), so the way to separate them is to price
// the holder with the network taken out of the picture. If holder ingest here lands far
// above the ~3.6 MB/s per holder the live run sustained, hypothesis (1) is dead.
//
// HOW IT ISOLATES THE HOLDER. Nodes run over a zero-latency in-process loopback, so the
// only cost left in a request is the work itself. Transport.dispatchRequest calls the
// holder's handler and, because the confined holder answers synchronously (callSync
// returns bytes, never a Promise), takes no await before sending the response — the
// whole admit → hash → verify → fs write → reply runs INSIDE the receiver's sink call.
// So timing that one call, per inbound request type, is the holder's processing time,
// with no initiator work and no wire in it.
//
// WHAT THE HOLDER DOES PER STORE'd BLOCK (acceptStore, tier2-guest.orchestration.js):
// BLAKE2b over the block; verifyDescriptor → one Ed25519 verify; the §6 sibling check
// (a storeHas fs stat per sibling id); then storeWrite = 2 fsSize + 2 fsPut. Every fs op
// is a cap-bridge crossing. NB the Ed25519 verify is NOT redundant work a cache could
// remove: the sibling rule means a holder takes at most one block per chunk, so the
// blocks in one STORE batch carry DISTINCT descriptors.
//
// Geometry defaults to the live deployment's (RS(1,1), 256 KiB blocks, ~1 MiB batches)
// so the numbers are comparable to a p2p-cli run rather than to test-scale config.
//
// WHAT THIS DOES *NOT* PRICE, so the verdict is not over-read:
//   - the transport's own receive cost on the holder box (WS unmasking, frame
//     reassembly, TCP) — loopback hands over a Uint8Array;
//   - by default, real disk: StorageNode's fs defaults to an in-RAM MemoryFs, so
//     storeWrite's two fsPut calls are memcpys. Pass `disk` to run the holders on a
//     NodeFs in a temp dir and get the honest write cost;
//   - a weaker deployment CPU (this runs on a dev machine; a deployed holder is typically
//     a VPS, and co-resident holders share one).
// So read the result as an upper bound on holder ingest, and judge the margin.
//
// Run:  node tests/bench-holder.mjs [fileMB] [blockKiB] [k] [m] [disk]
//   e.g. node tests/bench-holder.mjs 16            (the live geometry, in-RAM fs)
//        node tests/bench-holder.mjs 16 256 1 1 disk  (same, holders on real disk)
//        node tests/bench-holder.mjs 16 256 2 2    (RS(2,2) — 4 holders)

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { StorageNode, loadWasmBytes, loadSodium, PRODUCTION_BLOCK_SIZE } from "../build/host/node.js";
import { bytesEqual } from "../build/host/util.js";
import { NodeFs } from "seedkernel-wasm/fs-node";

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
const KIND_REQ = 0;

// A zero-latency loopback that times how long each node spends INSIDE its own request
// handler. Delivery is deferred (queueMicrotask) so the sender never re-enters itself,
// exactly as the plain LoopbackNetwork does; the timing wraps only the receiver's sink,
// which is where the holder's synchronous work happens.
class HolderTimingNetwork {
  constructor() { this.sinks = new Map(); this.offline = new Set(); this.stats = new Map(); }
  statsFor(peer) {
    let s = this.stats.get(peer);
    if (!s) this.stats.set(peer, (s = {}));
    return s;
  }
  bucket(peer, type) {
    const s = this.statsFor(peer);
    return s[type] ?? (s[type] = { n: 0, ms: 0, payloadBytes: 0 });
  }
  endpoint(id) {
    return {
      send: (to, frame) => this.deliver(id, to, frame),
      onFrame: (sink) => { this.sinks.set(id, sink); },
      close: () => { this.sinks.delete(id); },
    };
  }
  setOnline(peerId, online) { if (online) this.offline.delete(peerId); else this.offline.add(peerId); }
  isOnline(peerId) { return this.sinks.has(peerId) && !this.offline.has(peerId); }
  deliver(from, to, frame) {
    if (this.offline.has(from) || this.offline.has(to)) return;
    if (!this.sinks.has(to)) return;
    const copy = frame.slice();
    queueMicrotask(() => {
      const sink = this.sinks.get(to);
      if (!sink) return;
      if (copy[0] !== KIND_REQ) { sink(from, copy); return; }
      // req = [kind u8][corr u32][type u8][payload…] — the response is sent before this
      // returns, so the delta is the receiver's whole handling of this request.
      const b = this.bucket(to, copy[5]);
      b.n++; b.payloadBytes += copy.length - 6;
      const t0 = performance.now();
      sink(from, copy);
      b.ms += performance.now() - t0;
    });
  }
}

const fmt = (n, d = 1) => n.toFixed(d);
const rate = (bytes, ms) => (ms <= 0 ? Infinity : bytes / MB / (ms / 1000));

const sodium = await loadSodium();
const wasm = await loadWasmBytes();
const net = new HolderTimingNetwork();

// One initiator + exactly k+m holders, so every chunk's blocks fill the cohort and each
// holder takes one block per chunk (the §6 sibling rule) — the live shape. Built node by
// node rather than via createConnectedCohort so each holder can be given its own fs
// backend (the `disk` mode); the wiring is what that helper does.
const holders = K + M;
const tmpDirs = [];
const nodes = [];
for (let i = 0; i < 1 + holders; i++) {
  // Only the holders need a real backend — the initiator stores nothing (durability is
  // the cohort's), so putting it on disk would measure nothing and cost a temp dir.
  let fs;
  if (ON_DISK && i > 0) {
    const dir = mkdtempSync(join(tmpdir(), "seedstore-bench-holder-"));
    tmpDirs.push(dir);
    fs = new NodeFs(dir);
  }
  nodes.push(await StorageNode.create({
    network: net, sodium,
    bundleBlob: wasm.bundleBlob,
    config, fs,
    // Generous: each holder takes ~fileBytes of blocks plus .dsc sidecars, and a §14-full
    // holder would silently decline instead of measuring anything.
    quota: Math.max(64 * MB, fileBytes * 4),
    timeoutMs: 20000,
  }));
}
for (let i = 0; i < nodes.length; i++) {
  for (let j = i + 1; j < nodes.length; j++) StorageNode.connect(nodes[i], nodes[j]);
}
const initiator = nodes[0];
const holderIds = nodes.slice(1).map((n) => n.peerId);

const data = new Uint8Array(fileBytes);
for (let i = 0; i < fileBytes; i++) data[i] = (i * 1103515245 + 12345) & 255;

const numChunks = Math.ceil(Math.ceil(fileBytes / blockSize) / K);

console.log(`holder STORE-processing bench — RS(${K},${M}), ${BLOCK_KIB} KiB blocks, ${fmt(FILE_MB)} MB file`);
console.log(`  ${numChunks} chunks over ${holders} holder(s), ~1 MiB batches, zero-latency loopback`);
console.log(`  holder fs: ${ON_DISK ? "NodeFs (real disk, temp dir)" : "MemoryFs (in-RAM — pass `disk` for the honest write cost)"}\n`);

// Warm the initiator's codec/crypto so its cold-JIT tax doesn't land inside the measured
// window as backpressure. Holders warm themselves on their first few requests; the run is
// long enough that this is noise.
await initiator.warm();

const t0 = performance.now();
const put = await initiator.put(data);
const putMs = performance.now() - t0;

// ── holder ingest ──────────────────────────────────────────────────────────
let storeMs = 0, storeBytes = 0, storeReqs = 0, offerMs = 0, offerReqs = 0;
console.log("per-holder request handling (time spent inside the confined guest's `handle`):");
for (const id of holderIds) {
  const s = net.statsFor(id);
  const st = s[STORE] ?? { n: 0, ms: 0, payloadBytes: 0 };
  const of = s[OFFER] ?? { n: 0, ms: 0, payloadBytes: 0 };
  storeMs += st.ms; storeBytes += st.payloadBytes; storeReqs += st.n;
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
// Bytes and time are both summed over the holders, so the ratio is one holder's ingest
// rate against its OWN cpu time — which is the per-holder figure, since in a deployment
// the holders run on separate machines and their work does not queue behind each other.
const ingestMBs = rate(storeBytes, storeMs);
console.log(`\nSTORE (the ingest path — hash + descriptor verify + sibling check + 2 fs writes per block):`);
console.log(`  ${storeReqs} batched requests carrying ${totalBlocks} blocks (${fmt(storeBytes / MB)} MB of payload)`);
console.log(`  holder time total   ${fmt(storeMs)} ms  →  ${fmt(storeMs / Math.max(1, totalBlocks), 2)} ms per block`);
console.log(`  INGEST THROUGHPUT   ${fmt(ingestMBs, 1)} MB/s per holder (bytes ÷ that holder's own cpu time)`);
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
  let h0 = performance.now();
  for (let i = 0; i < reps; i++) sodium.crypto_generichash(32, block);
  const hashMs = (performance.now() - h0) / reps;
  h0 = performance.now();
  for (let i = 0; i < reps; i++) sodium.crypto_sign_verify_detached(sig, msg, kp.publicKey);
  const verifyMs = (performance.now() - h0) / reps;
  const floorMs = hashMs + verifyMs;
  console.log(`\ncrypto floor (host-side libsodium, same block size):`);
  console.log(`  BLAKE2b/block ${fmt(hashMs, 3)} ms + Ed25519 verify ${fmt(verifyMs, 3)} ms = ${fmt(floorMs, 3)} ms → ${fmt(rate(blockSize, floorMs), 0)} MB/s`);
  console.log(`  the holder COSTS ${fmt((storeMs / Math.max(1, totalBlocks)) / floorMs, 1)}× that floor — the excess is fs + cap-bridge crossings + QuickJS,`);
  console.log(`  i.e. the part that is ours to fix if holder ingest ever becomes the limit.`);
}

// ── GET side, for context ──────────────────────────────────────────────────
net.stats.clear();
const g0 = performance.now();
const got = await initiator.get(put.manifestId, put.key);
const getMs = performance.now() - g0;
let fetchMs = 0, fetchReqs = 0;
for (const id of holderIds) {
  const b = net.statsFor(id)[FETCH];
  if (b) { fetchMs += b.ms; fetchReqs += b.n; }
}
console.log(`\nFETCH (serve path, for contrast — a store read + a copy, no verify, no write):`);
console.log(`  ${fetchReqs} requests, ${fmt(fetchMs)} ms total → ${fmt(fetchMs / Math.max(1, totalBlocks), 2)} ms per block served`);

console.log(`\nwall-clock (in-process, so this is initiator + holder on one CPU, not a wire rate):`);
console.log(`  PUT ${fmt(putMs)} ms (${fmt(rate(fileBytes, putMs), 1)} MB/s)   GET ${fmt(getMs)} ms (${fmt(rate(fileBytes, getMs), 1)} MB/s)`);
console.log(`  holder share of PUT: ${fmt((storeMs + offerMs) / putMs * 100)}%`);
console.log(`  bytes verified: ${bytesEqual(got, data) ? "round-trip OK" : "MISMATCH"}`);

// Compare against a reference live run. The comparison that matters is per BOX, not per
// holder: a small cohort usually runs its holders on ONE machine, so their ingest work
// shares a CPU and the thing to beat is the PUT's whole wire rate, not one holder's share.
const LIVE_WIRE_MBS = 7.2;   // 50 MB file, 100.2 MB on the wire in 13.87 s (p2p-cli, 2026-07-21)
const boxMBs = ingestMBs / holders;  // worst case: every holder co-resident on one cpu
const margin = boxMBs / LIVE_WIRE_MBS;
console.log(`\nverdict vs a reference live run (${LIVE_WIRE_MBS} MB/s of wire into ONE box running the cohort):`);
console.log(`  per-holder ingest ${fmt(ingestMBs, 0)} MB/s → ${fmt(boxMBs, 0)} MB/s for ${holders} co-resident holders on one cpu`);
console.log(margin > 3
  ? `  that is ${fmt(margin, 0)}× the live demand, on THIS machine. For holder ingest to have been the limit,\n` +
    `  the holder box would have to be ~${fmt(margin, 0)}× slower at hash+verify+write than this one — and the\n` +
    `  ${ON_DISK ? "disk cost is already priced in" : "MemoryFs caveat still applies; re-run with `disk`"}. The untimed WS receive path is the remaining unknown.\n` +
    `  To close it properly, run this same bench ON the holder box and compare.`
  : `  that is only ${fmt(margin, 1)}× the live demand — holder processing is a plausible limiter.`);

for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
// Exit without disposing the guest realms. StorageNode.close() defers realm disposal onto
// the node's in-flight chain, and doing that at the end of a standalone script aborts in
// QuickJS with `Assertion failed: list_empty(&rt->gc_obj_list)` — a PRE-EXISTING teardown
// bug on this path, reproducible on the untouched tests/bench-net.mjs, not something this
// bench introduces (the test suite closes hundreds of nodes without it). The process is
// ending anyway, so there is nothing to tear down orderly; exiting here keeps the bench's
// exit code meaningful instead of always failing on a crash after the results are printed.
process.exit(0);

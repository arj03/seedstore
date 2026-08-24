// End-to-end PUT/GET wall-clock over a *latency-bearing* cohort. bench.mjs
// measures pure compute in-process, and the integration tests run on the
// zero-latency LoopbackNetwork, so neither sees the cost that dominates a real
// cross-machine cohort: wall-clock ~ (serial round-trip count) x RTT. This
// drives real latency through the link and sweeps the guest's fanoutWindow to
// find where widening it stops helping, for both directions.
//
// The window binds hardest when the transport cap forces ~one block per
// STORE/FETCH message (the WebRTC case), so the cap defaults to blockKiB + 16.
// Pass a big cap (e.g. 1024) to model a WS/TCP frame instead, where the window
// is a near no-op.
//
// Run:  node tests/bench-net.mjs [rttMs] [fileMB] [blockKiB] [capKiB] [wireChunkKiB] [windows]
//   e.g. node tests/bench-net.mjs 10 2 32       (10 ms RTT, 2 MB file, 32 KiB blocks, WebRTC cap)
//        node tests/bench-net.mjs 10 2 32 1024  (same, but a 1 MiB WS frame cap)

import { performance } from "node:perf_hooks";
import { loadWasmBytes, loadSodium, createConnectedCohort } from "../build/host/node.js";
import { bytesEqual } from "../build/host/util.js";
import { MsgType } from "../build/host/protocol.js";
import { LatencyNetwork } from "./latency-net.mjs";

const OFFER = MsgType.OFFER, FETCH = MsgType.FETCH, STORE = MsgType.STORE;

const RTT_MS = Number(process.argv[2] ?? 10);     // round-trip latency to model
const FILE_MB = Number(process.argv[3] ?? 2);
const BLOCK_KIB = Number(process.argv[4] ?? 32);
const CAP_KIB = Number(process.argv[5] ?? BLOCK_KIB + 16); // one block + headers per STORE → WebRTC
const WIRE_CHUNK_KIB = Number(process.argv[6] ?? 0);       // 0 = platform messages; e.g. 48 = length-framed WebRTC chunks
const WINDOWS = (process.argv[7] ?? "1,2,4,8,16,32").split(",").map(Number);

const MB = 1024 * 1024;
const blockSize = BLOCK_KIB * 1024;
const fileBytes = Math.round(FILE_MB * MB);
const delay = RTT_MS / 2;                          // one request = two sends
const maxMessageBytes = CAP_KIB * 1024;
const config = { k: 2, m: 2, blockSize, maxMessageBytes };
const numChunks = Math.ceil(Math.ceil(fileBytes / blockSize) / config.k);

const sodium = await loadSodium();
const wasm = await loadWasmBytes();

// A pseudo-random file (content is irrelevant to the round-trip count; a cheap
// deterministic fill avoids a slow byte-by-byte RNG).
const data = new Uint8Array(fileBytes);
for (let i = 0; i < fileBytes; i++) data[i] = (i * 2654435761) & 255;

// timeoutMs must comfortably exceed one RTT or healthy requests would "time out".
const timeoutMs = Math.max(2000, RTT_MS * 20);

async function measure(W) {
  const net = new LatencyNetwork(delay, WIRE_CHUNK_KIB * 1024);
  // n = k + m = 4 distinct holders per chunk; give the cohort a little headroom.
  const nodes = await createConnectedCohort({
    count: 6, network: net, sodium, wasm,
    config: { ...config, fanoutWindow: W }, timeoutMs,
  });
  const owner = nodes[0];

  // The latency link lives at the WIRE (latency-net.mjs — every message delayed);
  // the request counts and in-flight peaks come from the guest's Op.STATS counter
  // (read-and-cleared), since the kernel's shell has no host-side inbound seam.
  await owner.stats(); // clear whatever the cohort wiring accumulated
  let t0 = performance.now();
  const put = await owner.put(data);
  const putMs = performance.now() - t0;
  let s = await owner.stats();
  const putPeak = Math.max(s.get(OFFER)?.sentPeak ?? 0, s.get(STORE)?.sentPeak ?? 0); // the "work" types (HAVE excluded)
  const putReqs = (s.get(OFFER)?.sent ?? 0) + (s.get(STORE)?.sent ?? 0);

  await owner.stats(); // clear — the GET below is the only thing counted
  t0 = performance.now();
  const got = await owner.get(put.root, put.key);
  const getMs = performance.now() - t0;
  s = await owner.stats();
  const getPeak = s.get(FETCH)?.sentPeak ?? 0;
  const getReqs = s.get(FETCH)?.sent ?? 0;

  const ok = bytesEqual(got, data);
  // Nodes are left open between measures and torn down only by the final
  // process.exit(0) below: closing realms right after heavy in-process traffic
  // trips a pre-existing quickjs-ng teardown assertion in seedkernel's safe-js
  // (list_empty(&rt->gc_obj_list) at JS_FreeRuntime) — documented in
  // bench-holder.mjs. The process is ending anyway.
  return { W, putMs, getMs, putPeak, getPeak, putReqs, getReqs, ok };
}

const tput = (ms) => (FILE_MB / (ms / 1000)).toFixed(1);

const blocksPerMsg = Math.max(1, Math.floor(maxMessageBytes / blockSize));
console.log(`\nPUT/GET over a ${RTT_MS} ms-RTT cohort — RS(${config.k},${config.m}), ${BLOCK_KIB} KiB blocks, ${CAP_KIB} KiB cap (~${blocksPerMsg} block/msg), ${FILE_MB} MB → ${numChunks} chunks${WIRE_CHUNK_KIB > 0 ? `, ${WIRE_CHUNK_KIB} KiB physical chunks` : ""}`);
console.log(`(a serial PUT issues ~${numChunks * (config.k + config.m) * 2} request/response round trips; the window overlaps them — W is fanoutWindow)\n`);
console.log(`   W   PUT (ms)   MB/s   peak     GET (ms)   MB/s   peak    bytes`);
console.log(`  ──  ────────  ─────  ────    ────────  ─────  ────    ─────`);

let baseline = null;
for (const W of WINDOWS) {
  const r = await measure(W);
  if (W === 1) baseline = r;
  const putX = baseline ? `${(baseline.putMs / r.putMs).toFixed(1)}×` : "";
  const getX = baseline ? `${(baseline.getMs / r.getMs).toFixed(1)}×` : "";
  console.log(
    `  ${String(W).padStart(2)}  ${r.putMs.toFixed(0).padStart(8)}  ${tput(r.putMs).padStart(5)}  ${String(r.putPeak).padStart(3)} ${putX.padStart(5)}` +
    `  ${r.getMs.toFixed(0).padStart(8)}  ${tput(r.getMs).padStart(5)}  ${String(r.getPeak).padStart(3)} ${getX.padStart(5)}    ${r.ok ? "ok" : "MISMATCH"}`,
  );
  if (!r.ok) { console.error("byte mismatch — aborting"); process.exit(1); }
}

console.log(`\nSpeedup tracks W until W ≈ chunks (${numChunks}); past that the file has no more`);
console.log(`independent chunks to overlap, so the curve flattens — the point to stop raising W.`);
process.exit(0);

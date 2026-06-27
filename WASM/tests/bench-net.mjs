// End-to-end PUT/GET wall-clock over a *latency-bearing* cohort — the benchmark
// the repo was missing. bench.mjs and bench-wasm.mjs both measure pure compute
// (RS codec + crypto) in-process, and the integration tests run on the
// zero-latency LoopbackNetwork, so none of them can see the cost that dominates a
// real cross-machine cohort: wall-clock ≈ (serial round-trip count) × RTT. This
// drives a real round-trip latency through the link and sweeps the coordinator's
// chunk window (putConcurrency on PUT, getConcurrency on GET) so the serial-vs-
// windowed gap — and the point past which widening the window stops helping — is
// visible for BOTH directions. (Within a chunk the n blocks already place in
// parallel, so the "peak" column reflects window × n in flight.)
//
// The window binds hardest when the transport cap forces ~one block per STORE/FETCH
// message — exactly the WebRTC case (a ~64 KB data channel, 32 KiB blocks). So the
// cap defaults to blockKiB + 16, modelling that link: at W = 1 a 10 MB file pays one
// serial round trip per block in each direction; widening W pipelines them. Pass a
// big cap (e.g. 1024) to model a WS/TCP frame, where a holder's blocks ride a few
// large batches and the window is a near no-op.
//
// Run:  node tests/bench-net.mjs [rttMs] [fileMB] [blockKiB] [capKiB]
//   e.g. node tests/bench-net.mjs 10 2 32       (10 ms RTT, 2 MB file, 32 KiB blocks, WebRTC cap)
//        node tests/bench-net.mjs 10 2 32 1024  (same, but a 1 MiB WS frame cap)

import { performance } from "node:perf_hooks";
import { loadWasmBytes, loadSodium, createConnectedCohort, Tier2Coordinator } from "../build/host/node.js";
import { bytesEqual } from "../build/host/util.js";
import { LatencyNetwork } from "./latency-net.mjs";

const RTT_MS = Number(process.argv[2] ?? 10);     // round-trip latency to model
const FILE_MB = Number(process.argv[3] ?? 2);
const BLOCK_KIB = Number(process.argv[4] ?? 32);
const CAP_KIB = Number(process.argv[5] ?? BLOCK_KIB + 16); // one block + headers per STORE → WebRTC

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
  const net = new LatencyNetwork(delay);
  // n = k + m = 4 distinct holders per chunk; give the cohort a little headroom.
  const nodes = await createConnectedCohort({
    count: 6, network: net, sodium, wasm,
    config: { ...config, putConcurrency: W, getConcurrency: W }, timeoutMs,
  });
  const owner = nodes[0];

  net.reset();
  let t0 = performance.now();
  const put = await owner.put(data);
  const putMs = performance.now() - t0;
  const putPeak = net.maxInflightWork;
  const putReqs = net.requests;

  net.reset();
  t0 = performance.now();
  const got = await owner.get(put.manifestId, put.key);
  const getMs = performance.now() - t0;
  const getPeak = net.maxInflightWork;
  const getReqs = net.requests;

  const ok = bytesEqual(got, data);
  nodes.forEach((n) => n.close());
  return { W, putMs, getMs, putPeak, getPeak, putReqs, getReqs, ok };
}

// The confined guest (Tier2Coordinator) drives the SAME cohort over the per-peer
// fan-out cap (CAP_NET_SEND_MANY). It honours the SAME putConcurrency/getConcurrency
// windows as the host (read from its injected APP config — here the default 16),
// packing up to W per-peer requests into each batched fan-out, so its row should now
// land near the host's W=16 peak rather than peer-count. One row, lined up against
// the host W-sweep above for a like-for-like wall-clock comparison.
async function measureGuest() {
  const net = new LatencyNetwork(delay);
  const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs });
  const owner = nodes[0];
  const t2 = new Tier2Coordinator(owner);

  net.reset();
  let t0 = performance.now();
  const put = await t2.put(data);
  const putMs = performance.now() - t0;
  const putPeak = net.maxInflightWork;

  net.reset();
  t0 = performance.now();
  const got = await t2.get(put.manifestId, put.key);
  const getMs = performance.now() - t0;
  const getPeak = net.maxInflightWork;

  const ok = bytesEqual(got, data);
  t2.dispose();
  nodes.forEach((n) => n.close());
  return { putMs, getMs, putPeak, getPeak, ok };
}

const tput = (ms) => (FILE_MB / (ms / 1000)).toFixed(1);

const blocksPerMsg = Math.max(1, Math.floor(maxMessageBytes / blockSize));
console.log(`\nPUT/GET over a ${RTT_MS} ms-RTT cohort — RS(${config.k},${config.m}), ${BLOCK_KIB} KiB blocks, ${CAP_KIB} KiB cap (~${blocksPerMsg} block/msg), ${FILE_MB} MB → ${numChunks} chunks`);
console.log(`(a serial PUT issues ~${numChunks * (config.k + config.m) * 2} request/response round trips; the window overlaps them — W is putConcurrency on PUT, getConcurrency on GET)\n`);
console.log(`   W   PUT (ms)   MB/s   peak     GET (ms)   MB/s   peak    bytes`);
console.log(`  ──  ────────  ─────  ────    ────────  ─────  ────    ─────`);

let baseline = null;
for (const W of [1, 2, 4, 8, 16, 32]) {
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

// The confined guest, same cohort, over the fan-out cap — one row, no W knob.
const g = await measureGuest();
const gPutX = baseline ? `${(baseline.putMs / g.putMs).toFixed(1)}×` : "";
const gGetX = baseline ? `${(baseline.getMs / g.getMs).toFixed(1)}×` : "";
console.log(`  ──  ────────  ─────  ────    ────────  ─────  ────    ─────`);
console.log(
  `  gu  ${g.putMs.toFixed(0).padStart(8)}  ${tput(g.putMs).padStart(5)}  ${String(g.putPeak).padStart(3)} ${gPutX.padStart(5)}` +
  `  ${g.getMs.toFixed(0).padStart(8)}  ${tput(g.getMs).padStart(5)}  ${String(g.getPeak).padStart(3)} ${gGetX.padStart(5)}    ${g.ok ? "ok" : "MISMATCH"}`,
);
console.log(`  (gu = the confined guest over CAP_NET_SEND_MANY; compare its peak/wall-clock to the host W rows)`);

console.log(`\nSpeedup tracks W until W ≈ chunks (${numChunks}); past that the file has no more`);
console.log(`independent chunks to overlap, so the curve flattens — the point to stop raising W.`);

// PUT/GET concurrency over a *latency-bearing* link.
//
// The rest of the suite runs on the zero-latency LoopbackNetwork, where a serial
// round-trip loop and a windowed one finish in the same ~0 ms — so neither the
// regression (wall-clock scaling with the serial round-trip count) nor its fix
// (the chunk window + within-chunk parallel placement) is observable. This group
// gives the link a real RTT and asserts what only then becomes visible:
//   - correctness is identical to the serial path (bytes round-trip; the windowed
//     GET assembles chunks into the right offsets regardless of completion order),
//   - the windows are actually bounded (within-chunk fan-out = n, chunk window = W),
//   - and the windowed path is dramatically faster than the serial one — the
//     property the old benchmarks could not have caught.

import { loadWasmBytes, loadSodium, createConnectedCohort } from "../build/host/node.js";
import { bytesEqual } from "../build/host/util.js";
import { LatencyNetwork } from "./latency-net.mjs";

const DELAY = 2;        // ms per send → ~4 ms per request/response round trip
const TIMEOUT = 2000;   // generous: requests succeed, so this never fires
const W = 6;            // window width under test (chunks N > W so the cap binds)

function file(n, seed = 1) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + seed * 7) & 255;
  return out;
}

export async function run(t) {
  const sodium = await loadSodium();
  const wasm = await loadWasmBytes();
  // RS(2,2): every chunk places n = k + m = 4 distinct blocks; a 6-node cohort
  // leaves 5 holders, enough for placement. N (> W) chunks → a one-chunk-at-a-time
  // PUT pays N× the round trips a window of W overlaps.
  const config = { k: 2, m: 2, blockSize: 64 };
  const N = 12;
  const n = config.k + config.m; // blocks placed per chunk, fanned out in parallel
  const data = file(N * config.k * config.blockSize, 7); // exactly N RS chunks (N > W)

  // Stand up a fresh cohort, run `body(owner)`, and return its wall-clock plus
  // the link's peak request concurrency for that run.
  async function onCohort(cfg, body) {
    const net = new LatencyNetwork(DELAY);
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    net.reset();
    const t0 = performance.now();
    const result = await body(nodes[0]);
    const ms = performance.now() - t0;
    nodes.forEach((n) => n.close());
    return { result, ms, maxInflightWork: net.maxInflightWork };
  }

  t.group("PUT places n blocks per chunk in parallel, chunks through a window");
  {
    const serial = await onCohort(
      { ...config, putConcurrency: 1 },
      (owner) => owner.put(data),
    );
    const windowed = await onCohort(
      { ...config, putConcurrency: W },
      (owner) => owner.put(data),
    );

    // One chunk at a time still fans its n blocks out concurrently (Phase 2), so
    // even the chunk-window-of-1 run peaks at n in flight, not 1.
    t.eq(serial.maxInflightWork, n, `putConcurrency=1 still places a chunk's n=${n} blocks in parallel (peak ${serial.maxInflightWork})`);
    // The chunk window stacks on top: W chunks × n blocks in flight at the peak.
    t.eq(windowed.maxInflightWork, W * n, `putConcurrency=${W} drives ${W}×${n} placements in flight (peak ${windowed.maxInflightWork}, N=${N} > W)`);
    t.eq(windowed.result.blockIds.length, serial.result.blockIds.length, "both paths place the same number of blocks");
    t.ok(windowed.ms < serial.ms * 0.6,
      `windowing chunks is far faster than one-at-a-time (${windowed.ms.toFixed(0)} ms vs ${serial.ms.toFixed(0)} ms) — the regression a real RTT exposes`);
  }

  t.group("GET fans out discovery once, then fetches chunks through a window");
  {
    // One PUT, then read it back at W=1 and W=W on fresh links so we compare the
    // *same* placement. The windowed GET must assemble byte-identically.
    const net = new LatencyNetwork(DELAY);
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config: { ...config, putConcurrency: W, getConcurrency: W }, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const put = await owner.put(data);

    net.reset();
    owner.config.getConcurrency = 1;
    let t0 = performance.now();
    const serialBytes = await owner.get(put.manifestId, put.key);
    const serialMs = performance.now() - t0;
    const serialWork = net.maxInflightWork;

    net.reset();
    owner.config.getConcurrency = W;
    t0 = performance.now();
    const windowedBytes = await owner.get(put.manifestId, put.key);
    const windowedMs = performance.now() - t0;
    const windowedWork = net.maxInflightWork;

    t.ok(bytesEqual(serialBytes, data), "serial GET reconstructs the file");
    t.ok(bytesEqual(windowedBytes, data), "windowed GET reconstructs the file byte-identically");
    t.eq(serialWork, 1, "getConcurrency=1 fetches one block at a time (serial)");
    t.eq(windowedWork, W, `getConcurrency=${W} drives the fetch window to its bound (peak ${windowedWork})`);
    t.ok(windowedMs < serialMs * 0.6,
      `windowed GET is far faster than serial (${windowedMs.toFixed(0)} ms vs ${serialMs.toFixed(0)} ms)`);
    nodes.forEach((n) => n.close());
  }

  t.group("the window preserves every existing invariant under latency");
  {
    // A full round trip on the latency link, just like the loopback groups, to
    // confirm the concurrent path is correct end-to-end and tolerates loss.
    const net = new LatencyNetwork(DELAY);
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const put = await owner.put(data);
    t.ok(bytesEqual(await owner.get(put.manifestId, put.key), data), "PUT → GET round-trips on a latency-bearing link");
    // Drop two holders (≤ m of any chunk): any k of n still reads.
    net.setOnline(nodes[1].peerId, false);
    net.setOnline(nodes[2].peerId, false);
    t.ok(bytesEqual(await owner.get(put.manifestId, put.key), data), "windowed GET still reads with two holders offline");
    nodes.forEach((n) => n.close());
  }
}

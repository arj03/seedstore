// PUT/GET round-trip economy over a *latency-bearing* link.
//
// The rest of the suite runs on the zero-latency LoopbackNetwork, where per-block
// and batched round trips finish in the same ~0 ms — so the cost that batching
// attacks (wall-clock ≈ round-trip count × RTT) is invisible. This group gives the
// link a real RTT and asserts what only then matters: that OFFER, STORE, and FETCH
// are batched *per holder* instead of issued *per block*. The win shows up as
// request counts (LatencyNetwork.byType), not just wall-clock:
//   - PUT negotiates with ONE OFFER per holder (accept-mask) and pushes the
//     accepted blocks in ONE streamed STORE per holder — no per-block handshake.
//   - GET pulls every block a holder serves in ONE FETCH per holder.
//   - correctness is unchanged: bytes round-trip, assembly lands at the right
//     offsets regardless of completion order, and any k of n still reads.

import { loadWasmBytes, loadSodium, createConnectedCohort } from "../build/host/node.js";
import { bytesEqual } from "../build/host/util.js";
import { LatencyNetwork } from "./latency-net.mjs";

const DELAY = 2;        // ms per send → ~4 ms per request/response round trip
const TIMEOUT = 2000;   // generous: requests succeed, so this never fires
const W = 6;            // window width under test (chunks N > W so the cap binds)

// MsgType (host/protocol.ts) — index the per-type request counter.
const OFFER = 2, FETCH = 3, STORE = 4;

function file(n, seed = 1) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + seed * 7) & 255;
  return out;
}

export async function run(t) {
  const sodium = await loadSodium();
  const wasm = await loadWasmBytes();
  // RS(2,2): every chunk places n = k + m = 4 distinct blocks; a 6-node cohort
  // leaves 5 holders, enough for placement. N (> W) chunks → a per-block PUT would
  // pay N×n OFFER round trips; batching folds them to ≈ one OFFER per holder.
  const config = { k: 2, m: 2, blockSize: 64 };
  const N = 12;
  const n = config.k + config.m;        // blocks per chunk
  const replicas = config.m + 1;        // manifest copies (defaultConfig: m+1)
  const data = file(N * config.k * config.blockSize, 7); // exactly N RS chunks (N > W)

  // Stand up a fresh cohort, run `body(owner)`, and return its wall-clock plus the
  // link's request counters (reset just before the body runs).
  async function onCohort(cfg, body) {
    const net = new LatencyNetwork(DELAY);
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    net.reset();
    const t0 = performance.now();
    const result = await body(nodes[0]);
    const ms = performance.now() - t0;
    const byType = net.byType, peakWork = net.maxInflightWork, peakByType = net.maxInflightByType;
    nodes.forEach((nn) => nn.close());
    return { result, ms, byType, peakWork, peakByType };
  }

  t.group("PUT batches OFFER and STORE per holder, not per block");
  {
    const put = await onCohort(config, (o) => o.put(data));
    const offers = put.byType[OFFER] ?? 0;
    const stores = put.byType[STORE] ?? 0;

    // A per-block PUT issues N×n OFFERs AND N×n STOREs (+ the manifest's replicas).
    // Batching folds EACH to ≈ one message per holder offered to (≤ n) + the
    // manifest's per-replica messages — the OFFER handshake and the bulk STORE both
    // collapse from per-block to per-holder.
    t.ok(offers <= n + replicas, `OFFER batched: ${offers} for ${N * n} chunk blocks (≤ one per holder + ${replicas} manifest)`);
    t.ok(stores <= n + replicas, `STORE batched: ${stores} for ${N * n} chunk blocks (≤ one per holder + ${replicas} manifest)`);
    t.ok(offers + stores < N * n, `control round trips collapsed from per-block ${2 * (N * n)} to ${offers + stores}`);
    t.eq(put.result.blockIds.length, N * n + 1, "every chunk block + the manifest was placed");
  }

  t.group("PUT windows the per-holder STOREs so they pipeline (putConcurrency), not one serial round trip per block");
  {
    // The WebRTC case: a small frame cap forces ~one block per STORE message (two
    // won't fit), so a big file becomes many single-block STOREs. OFFER descriptors
    // are tiny, so the OFFER still collapses to one batched message per holder
    // (point 1 — discovery helped even on WebRTC); the STORE bytes must cross one
    // block per message (point 2 — transport physics); the only lever left is
    // pipelining those per-holder STOREs (point 3 — this fix). On the zero-latency
    // loopback the gap is invisible; under an RTT it is the dominant cost.
    const bs = 4096;                                 // block big enough to dominate a STORE message
    const Nw = 16;                                   // chunks ≫ holders, so a per-holder window can bind
    const cap = bs + 2000;                           // one 4 KiB block + headers fits a STORE; two don't.
    const webrtcData = file(Nw * config.k * bs, 9);  // exactly Nw RS chunks
    const cfg = { ...config, blockSize: bs, maxMessageBytes: cap };
    const replicas = config.m + 1;                   // manifest copies (defaultConfig: m+1)

    // Same file, same cohort shape, same cap — only the window differs. putConcurrency
    // = 1 reproduces the OLD serial-per-holder STORE loop (mapPool width 1 is strictly
    // serial); putConcurrency = 64 is the fix.
    const serial = await onCohort({ ...cfg, putConcurrency: 1 }, (o) => o.put(webrtcData));
    const windowed = await onCohort({ ...cfg, putConcurrency: 64 }, (o) => o.put(webrtcData));

    const storeSerial = serial.peakByType[STORE] ?? 0;
    const storeWindowed = windowed.peakByType[STORE] ?? 0;
    const offersW = windowed.byType[OFFER] ?? 0;

    // The cap really did force one block per STORE: the STORE *count* is per-block
    // (Nw·n chunk blocks + the manifest's replicas), the case batching can't shrink.
    t.eq(windowed.byType[STORE], Nw * n + replicas, `the cap forces one block per STORE: ${Nw * n} chunk blocks + ${replicas} manifest`);
    // Point 1 still holds under the tight cap: OFFER collapses to ≈ one batched
    // message per holder (≤ n + the manifest replicas), not one per block.
    t.ok(offersW <= n + replicas, `OFFER stays batched per holder under the WebRTC cap: ${offersW} for ${Nw * n} blocks`);

    // BEFORE — serial per holder: at most one STORE in flight per holder, so the peak
    // is just the holder count (≤ n), the round-trip-bound case the window must hide.
    t.ok(storeSerial <= n, `serial STORE peaks at the holder count: ${storeSerial} in flight (≤ ${n})`);
    // AFTER — the window pipelines each holder's STOREs, so many ride in flight at
    // once: a single holder alone overlaps its Nw blocks, far past the serial peak.
    t.ok(storeWindowed >= Nw, `windowed STORE pipelines past serial: ${storeWindowed} in flight (≥ ${Nw}, vs ${storeSerial} serial)`);
    t.ok(storeWindowed > storeSerial * 2, `the window multiplies in-flight STOREs (${storeWindowed} vs ${storeSerial})`);
    // …but stays bounded by putConcurrency × holders — flow-control, not a flood.
    t.ok(storeWindowed <= 64 * n, `windowed STORE stays bounded by putConcurrency × holders: ${storeWindowed} ≤ ${64 * n}`);

    // Correctness is unchanged: the windowed PUT still places every block + manifest.
    t.eq(windowed.result.blockIds.length, Nw * n + 1, "windowed PUT placed every chunk block + the manifest");
  }

  t.group("GET pulls every block a holder serves in one FETCH, not one per block");
  {
    // One PUT, then read it back. A per-block GET would issue N×k fetches + the
    // manifest; the batched GET issues ≈ one FETCH per distinct holder + the
    // manifest, and assembles byte-identically.
    const net = new LatencyNetwork(DELAY);
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config: { ...config, putConcurrency: W, getConcurrency: W }, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const put = await owner.put(data);

    net.reset();
    const bytes = await owner.get(put.manifestId, put.key);
    const fetches = net.byType[FETCH] ?? 0;

    t.ok(bytesEqual(bytes, data), "batched GET reconstructs the file byte-identically");
    // ≤ one FETCH per cohort holder (each serves a batch of the blocks it holds) +
    // one for the manifest — far below the N×k a per-block GET would issue.
    t.ok(fetches <= nodes.length,
      `batched FETCH: ${fetches} FETCHes to recover ${N} chunks (≤ one per holder + manifest, vs ${N * config.k} per-block)`);
    t.ok(fetches * 3 < N * config.k, `FETCH round trips are a fraction of the per-block count (${fetches} vs ${N * config.k})`);
    nodes.forEach((nn) => nn.close());
  }

  t.group("the batched paths preserve every invariant under latency");
  {
    // A full round trip on the latency link, just like the loopback groups, to
    // confirm the batched path is correct end-to-end and tolerates loss.
    const net = new LatencyNetwork(DELAY);
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const put = await owner.put(data);
    t.ok(bytesEqual(await owner.get(put.manifestId, put.key), data), "PUT → GET round-trips on a latency-bearing link");
    // Drop two holders (≤ m of any chunk): any k of n still reads.
    net.setOnline(nodes[1].peerId, false);
    net.setOnline(nodes[2].peerId, false);
    t.ok(bytesEqual(await owner.get(put.manifestId, put.key), data), "batched GET still reads with two holders offline");
    nodes.forEach((nn) => nn.close());
  }
}

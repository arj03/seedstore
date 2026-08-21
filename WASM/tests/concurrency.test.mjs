// PUT/GET round-trip economy over a *latency-bearing* link.
//
// The rest of the suite runs on the zero-latency LoopbackNetwork, where the
// cost batching attacks (wall-clock ~ round-trip count x RTT) is invisible.
// This group gives the link a real RTT (latency-net.mjs) and asserts that
// OFFER, STORE, and FETCH are batched *per holder*, not issued *per block*:
//   - PUT negotiates ONE OFFER per holder and pushes accepted blocks in ONE
//     streamed STORE per holder.
//   - GET pulls every block a holder serves in ONE FETCH per holder.
//   - correctness is unchanged regardless of completion order.
// The win shows up in request counters the guest keeps (StorageNode.stats),
// since the batching lives in the guest.

import { loadWasmBytes, loadSodium, createConnectedCohort } from "../build/host/node.js";
import { bytesEqual, toHex } from "../build/host/util.js";
import { MsgType } from "../build/host/protocol.js";
import { LatencyNetwork } from "./latency-net.mjs";

const DELAY = 2;        // ms per send → ~4 ms per request/response round trip
const TIMEOUT = 2000;   // generous: requests succeed, so this never fires
const W = 6;            // window width under test (chunks N > W so the cap binds)
// Wall-clock comparisons use a larger delay than DELAY so the round trip dwarfs
// per-message realm/JS processing, whose cost varies with machine load (a 4 ms
// RTT flipped under load). See `pipelinedSavesWallClock`.
const WC_DELAY = 25;    // ms per send on the wall-clock wire → RTT = 2×WC_DELAY

// MsgType (host/protocol.ts) — index the per-type request counter.
const OFFER = MsgType.OFFER, FETCH = MsgType.FETCH, STORE = MsgType.STORE;

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
  const config = { k: 2, m: 2, blockSize: 4096 };
  const N = 12;
  const n = config.k + config.m;        // blocks per chunk
  const replicas = config.m + 1;        // manifest copies (defaultConfig: m+1)
  const data = file(N * config.k * config.blockSize, 7); // exactly N RS chunks (N > W)

  // Stand up a fresh cohort, run `body(owner, net)`, and return its wall-clock
  // plus the owner's request counters (guest-kept, read-and-cleared via
  // Op.STATS) — cleared by an initial read so wiring traffic isn't counted.
  async function onCohort(cfg, body, delayMs = DELAY) {
    const net = new LatencyNetwork(delayMs);
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    await owner.stats(); // clear whatever the cohort wiring accumulated
    const t0 = performance.now();
    const result = await body(owner, net);
    const ms = performance.now() - t0;
    const stats = await owner.stats(); // read-and-clear
    nodes.forEach((nn) => nn.close());
    net.close();
    return { result, ms, stats };
  }

  /** The wall-clock floor for a pipelined-vs-serial comparison. The pipelined
   *  run pays ONE round trip where serial pays `depth`, so savings ~= (depth-1)
   *  x RTT regardless of machine speed (per-message processing cost cancels
   *  out of the difference). Floor is HALF that (jitter tolerance). */
  function pipelinedSavesWallClock(serialMs, windowedMs, depth, wireDelayMs) {
    const saved = serialMs - windowedMs;
    const floor = (depth - 1) * wireDelayMs; // ½ × (depth−1) × 2×wireDelayMs
    return { saved, floor };
  }

  t.group("PUT batches OFFER and STORE per holder, not per block");
  {
    const put = await onCohort(config, (o) => o.put(data));
    const offers = put.stats.get(OFFER)?.sent ?? 0;
    const stores = put.stats.get(STORE)?.sent ?? 0;

    // A per-block PUT issues N×n OFFERs AND N×n STOREs (+ the manifest's replicas).
    // Batching folds EACH to ≈ one message per holder offered to (≤ n) + the
    // manifest's per-replica messages — the OFFER handshake and the bulk STORE both
    // collapse from per-block to per-holder.
    t.ok(offers <= n + replicas, `OFFER batched: ${offers} for ${N * n} chunk blocks (≤ one per holder + ${replicas} manifest)`);
    t.ok(stores <= n + replicas, `STORE batched: ${stores} for ${N * n} chunk blocks (≤ one per holder + ${replicas} manifest)`);
    t.ok(offers + stores < N * n, `control round trips collapsed from per-block ${2 * (N * n)} to ${offers + stores}`);
    t.eq(put.result.blockIds.length, N * n + 1, "every chunk block + the manifest was placed");
  }

  t.group("PUT windows the per-holder STOREs so they pipeline (fanoutWindow), not one serial round trip per block");
  {
    // The WebRTC case: a small frame cap forces ~one block per STORE message, so
    // a big file becomes many single-block STOREs. OFFER still batches (tiny
    // descriptors); the only lever left is pipelining those per-holder STOREs.
    const bs = 4096;                                 // block big enough to dominate a STORE message
    const Nw = 16;                                   // chunks ≫ holders, so a per-holder window can bind
    const cap = bs + 2000;                           // one 4 KiB block + headers fits a STORE; two don't.
    const webrtcData = file(Nw * config.k * bs, 9);  // exactly Nw RS chunks
    const cfg = { ...config, blockSize: bs, maxMessageBytes: cap };
    const replicas = config.m + 1;                   // manifest copies (defaultConfig: m+1)

    // Same file/cohort/cap — only the window differs. fanoutWindow=1 is strictly
    // serial (the old behavior); 64 is the fix. Measured as time SAVED, not a
    // ratio of noisy totals (see `pipelinedSavesWallClock`).
    const serial = await onCohort({ ...cfg, fanoutWindow: 1 }, (o) => o.put(webrtcData), WC_DELAY);
    const windowed = await onCohort({ ...cfg, fanoutWindow: 64 }, (o) => o.put(webrtcData), WC_DELAY);

    const storeSerial = serial.stats.get(STORE)?.sentPeak ?? 0;
    const storeWindowed = windowed.stats.get(STORE)?.sentPeak ?? 0;
    const offersW = windowed.stats.get(OFFER)?.sent ?? 0;

    // The cap really did force one block per STORE: the STORE *count* is per-block
    // (Nw·n chunk blocks + the manifest's replicas), the case batching can't shrink.
    t.eq(windowed.stats.get(STORE)?.sent ?? 0, Nw * n + replicas, `the cap forces one block per STORE: ${Nw * n} chunk blocks + ${replicas} manifest`);
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
    // …but stays bounded by fanoutWindow × holders — flow-control, not a flood.
    t.ok(storeWindowed <= 64 * n, `windowed STORE stays bounded by fanoutWindow × holders: ${storeWindowed} ≤ ${64 * n}`);
    // Savings asserted absolutely (RTTs removed), not as a ratio of two totals,
    // so per-message processing noise cancels out and the floor holds under load.
    const { saved, floor } = pipelinedSavesWallClock(serial.ms, windowed.ms, Nw, WC_DELAY);
    t.ok(saved >= floor,
      `windowed PUT saved the pipelined round trips: ${saved.toFixed(0)} ms (≥ ${floor} = half of ${Nw - 1} × RTT on the latency wire)`);

    // Correctness is unchanged: the windowed PUT still places every block + manifest.
    t.eq(windowed.result.blockIds.length, Nw * n + 1, "windowed PUT placed every chunk block + the manifest");
  }

  t.group("GET pulls every block a holder serves in one FETCH, not one per block");
  {
    // One PUT, then read it back. A per-block GET would issue N×k fetches + the
    // manifest; the batched GET issues ≈ one FETCH per distinct holder + the
    // manifest, and assembles byte-identically.
    const net = new LatencyNetwork(DELAY);
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config: { ...config, fanoutWindow: W }, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const put = await owner.put(data);

    await owner.stats(); // clear — only the GET below is counted
    const bytes = await owner.get(put.root, put.key);
    const fetches = (await owner.stats()).get(FETCH)?.sent ?? 0;

    t.ok(bytesEqual(bytes, data), "batched GET reconstructs the file byte-identically");
    // ≤ one FETCH per cohort holder (each serves a batch of the blocks it holds) +
    // one for the manifest — far below the N×k a per-block GET would issue.
    t.ok(fetches <= nodes.length,
      `batched FETCH: ${fetches} FETCHes to recover ${N} chunks (≤ one per holder + manifest, vs ${N * config.k} per-block)`);
    t.ok(fetches * 3 < N * config.k, `FETCH round trips are a fraction of the per-block count (${fetches} vs ${N * config.k})`);
    nodes.forEach((nn) => nn.close());
    net.close();
  }

  t.group("the batched paths preserve every invariant under latency");
  {
    // A full round trip on the latency link, just like the loopback groups, to
    // confirm the batched path is correct end-to-end and tolerates loss.
    const net = new LatencyNetwork(DELAY);
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const put = await owner.put(data);
    t.ok(bytesEqual(await owner.get(put.root, put.key), data), "PUT → GET round-trips on a latency-bearing link");
    // Drop two holders (≤ m of any chunk): any k of n still reads.
    net.setOnline(nodes[1].peerId, false);
    net.setOnline(nodes[2].peerId, false);
    t.ok(bytesEqual(await owner.get(put.root, put.key), data), "batched GET still reads with two holders offline");
    nodes.forEach((nn) => nn.close());
    net.close();
  }

  t.group("placement + gather fan out across holders (Promise.all over NET_SEND), not one round trip at a time");
  {
    // The orchestration runs INSIDE the QuickJS realm and reaches net only through
    // host.call, yet placement/gather must still overlap holders. The guest's own
    // in-flight peak (how many requests of a type it has outstanding at once) IS the
    // fan-out: a serial awaited round trip would peak at 1, the Promise.all fan-out
    // peaks at the holder count.
    const net = new LatencyNetwork(DELAY);
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];

    await owner.stats(); // clear
    const put = await owner.put(data);
    let s = await owner.stats();
    const offerPeak = s.get(OFFER)?.sentPeak ?? 0;
    const storePeak = s.get(STORE)?.sentPeak ?? 0;
    t.ok(offerPeak > 1, `OFFER fan-out overlaps holders: peak ${offerPeak} in flight (a serial path would be 1)`);
    t.ok(storePeak > 1, `STORE fan-out overlaps holders: peak ${storePeak} in flight (a serial path would be 1)`);
    t.eq(put.chunkCount, N, "placed every RS chunk");

    await owner.stats(); // clear
    const bytes = await owner.get(put.root, put.key);
    const fetchPeak = (await owner.stats()).get(FETCH)?.sentPeak ?? 0;
    t.ok(bytesEqual(bytes, data), "GET reconstructs the file byte-identically under latency");
    t.ok(fetchPeak > 1, `FETCH fan-out overlaps holders: peak ${fetchPeak} in flight (a serial path would be 1)`);

    nodes.forEach((nn) => nn.close());
    net.close();
  }

  t.group("GET windows the per-holder FETCHes so they pipeline (fanoutWindow), not one serial round trip per block");
  {
    // The WebRTC tight-cap twin of the STORE-window group above: ~one block per
    // FETCH message, windowed into one Promise.all fan-out per fanoutWindow
    // instead of one round trip apiece. PUT then GET on ONE cohort; the setup
    // PUT is excluded from the peak by clearing stats just before the GET.
    const bs = 4096;                                   // a block dominates a FETCH message
    const Nw = 16;                                     // chunks ≫ holders, so a window can bind
    const cap = bs + 2000;                             // one 4 KiB block + headers fits; two don't
    const webrtcData = file(Nw * config.k * bs, 9);    // exactly Nw RS chunks
    const cfg = { ...config, blockSize: bs, maxMessageBytes: cap };

    async function getPeak(fanoutWindow, delayMs = DELAY) {
      const r = await onCohort({ ...cfg, fanoutWindow }, (owner) => owner.put(webrtcData).then((put) => owner.get(put.root, put.key)), delayMs);
      return { bytes: r.result, fetchPeak: r.stats.get(FETCH)?.sentPeak ?? 0, ms: r.ms };
    }
    const serial = await getPeak(1, WC_DELAY);
    const windowed = await getPeak(64, WC_DELAY);

    t.ok(bytesEqual(serial.bytes, webrtcData), "the serial GET reconstructs the tight-cap file byte-identically");
    t.ok(bytesEqual(windowed.bytes, webrtcData), "the windowed GET reconstructs the tight-cap file byte-identically");
    t.ok(serial.fetchPeak <= 1, `serial GET fetches one block at a time: peak ${serial.fetchPeak} in flight (≤ 1)`);
    t.ok(windowed.fetchPeak >= Nw, `windowed GET pipelines past serial: ${windowed.fetchPeak} in flight (≥ ${Nw}, vs ${serial.fetchPeak} serial)`);
    // Both phases (PUT and GET) pipeline, so this is two phases' worth of
    // savings, asserted absolutely (see `pipelinedSavesWallClock`).
    const { saved, floor } = pipelinedSavesWallClock(serial.ms, windowed.ms, Nw, 2 * WC_DELAY);
    t.ok(saved >= floor,
      `windowed PUT+GET saved the pipelined round trips: ${saved.toFixed(0)} ms (≥ ${floor} = half of ${Nw - 1} × RTT per phase, two phases)`);
  }

  t.group("overlapping PUT/GET operations on one node don't clobber the guest's stream state");
  {
    // The guest keeps a streamed PUT's state in realm state, so exactly one
    // stream may be open per role at a time; runExclusive chains whole
    // OPERATIONS (not individual window calls) to keep that safe. Force the
    // worst case — one chunk per window, so each PUT is a dozen separate realm
    // calls — and fire three PUTs, then three GETs, concurrently.
    const cfg = { ...config, windowTargetBytes: config.k * config.blockSize }; // one chunk per window
    const files = [21, 22, 23].map((seed) => file(N * config.k * config.blockSize, seed));
    const r = await onCohort(cfg, (owner) => {
      return Promise.all(files.map((f) => owner.put(f))).then((puts) =>
        Promise.all(puts.map((p) => owner.get(p.root, p.key))).then((got) => ({ puts, got })));
    });
    t.ok(r.result.got.every((got, i) => bytesEqual(got, files[i])), "three concurrent multi-window PUT/GETs each round-trip their own bytes");
    t.ok(r.result.puts.every((p) => p.chunkCount === N), `each PUT sealed a manifest over its own ${N} chunks — no window folded into another's stream`);
    t.eq(new Set(r.result.puts.map((p) => toHex(p.root))).size, 3, "the three files got three distinct manifests");
  }
}

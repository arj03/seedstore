// End-to-end multi-node tests over the loopback network: a storage node booted
// on the real seedkernel, then PUT → place → GET → repair across simulated
// peers (README Part I). These are the integration tests that exercise the
// whole onion together.

import {
  LoopbackNetwork, loadWasmBytes, loadSodium, createConnectedCohort, StorageNode,
} from "../build/host/node.js";
import { encodeFetchBatchReq, decodeFetchBatchRes, FETCH_UNANSWERED } from "../build/host/protocol.js";
import { parseSignedDescriptor } from "../build/host/manifest.js";
import { toHex, fromHex, bytesEqual } from "../build/host/util.js";
import { liveBlockCount } from "./helpers.mjs";

const TIMEOUT = 40; // ms — keep offline-peer timeouts snappy in tests

function file(n, seed = 1) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + seed * 7) & 255;
  return out;
}

// Collect each distinct chunk's block-ids by scanning holders' stores (every
// holder carries the chunk's signed descriptor, §4.3).
function chunkBlockIds(nodes) {
  const seen = new Map();
  for (const node of nodes) {
    for (const id of node.store.list()) {
      const sb = node.store.get(id);
      if (!sb || !sb.descriptor) continue;
      const sd = parseSignedDescriptor(sb.descriptor);
      const key = toHex(node.crypto.hash(sb.descriptor));
      if (!seen.has(key)) seen.set(key, sd.descriptor.blockIds);
    }
  }
  return [...seen.values()];
}

export async function run(t) {
  const sodium = await loadSodium();
  const wasm = await loadWasmBytes();
  const config = { k: 2, m: 2, blockSize: 64 };

  t.group("node boots on seedkernel: pure codec + reputation handlers installed (§19)");
  {
    const net = new LoopbackNetwork();
    const [node] = await createConnectedCohort({ count: 1, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    t.ok(node.handlersInstalled(), "codec + reputation installed as kernel handlers");
    node.close();
  }

  t.group("PUT → GET round trip across a cohort (RS path, §6, §7)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const data = file(200); // 4 blocks → 2 RS chunks
    const put = await owner.put(data);
    t.ok(!put.replicated, "a multi-block file takes the RS path");
    t.eq(put.chunkCount, 2, "200 bytes / (k=2 × 64) → 2 chunks");
    const got = await owner.get(put.manifestId, put.key);
    t.ok(bytesEqual(got, data), "GET reconstructs the original file");
    // Blocks really live on distinct peers, not the owner.
    const holders = nodes.filter((n) => n !== owner && n.store.list().length > 0);
    t.ok(holders.length >= 4, "blocks placed across several distinct peers");
    t.eq(owner.store.list().length, 0, "owner holds no blocks — durability leans on the cohort");
    nodes.forEach((n) => n.close());
  }

  t.group("large blocks (> the 128 KB default handler scratch) round-trip (§4.1)");
  {
    // The p2p demo runs 256 KiB blocks so a WS cohort pays few round trips. A
    // codec encode/decode request is then k·blockSize bytes — far past the kernel's
    // 128 KB default handler scratch — so the codec must declare its larger scratch
    // (exported `scratchSize`) and the host must honor it. Before that wiring the
    // codec call silently returned no parity and PUT died with "blockIds.length must
    // equal k+m". Use RS(2,2) at 96 KiB so both the encode request (2·96 KiB) and its
    // parity response (2·96 KiB) exceed the default, over genuine (k>1) parity.
    const net = new LoopbackNetwork();
    const bigCfg = { k: 2, m: 2, blockSize: 96 * 1024 };
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config: bigCfg, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const data = file(bigCfg.k * bigCfg.blockSize * 3 - 5000, 9); // ~3 chunks, last chunk short
    const put = await owner.put(data);
    t.ok(!put.replicated, "a many-block file takes the RS path");
    t.eq(put.chunkCount, 3, "spans 3 RS chunks");
    const got = await owner.get(put.manifestId, put.key);
    t.ok(bytesEqual(got, data), "GET reconstructs a file coded in > 128 KB blocks");
    nodes.forEach((n) => n.close());
  }

  t.group("small file replication path (§4.1)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const data = file(40, 9); // < 1 block → replicated, not coded
    const put = await owner.put(data);
    t.ok(put.replicated, "a sub-chunk file is replicated, not RS-coded");
    const got = await owner.get(put.manifestId, put.key);
    t.ok(bytesEqual(got, data), "replicated small file reads back");
    nodes.forEach((n) => n.close());
  }

  t.group("offline tolerance: any k of n still reads (§7, §8)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const data = file(200, 3);
    const put = await owner.put(data);
    // Take two peers offline (≤ m of any chunk, since blocks are on distinct
    // peers). Manifest is replicated on r=3 peers, so it stays reachable too.
    net.setOnline(nodes[1].peerId, false);
    net.setOnline(nodes[2].peerId, false);
    const got = await owner.get(put.manifestId, put.key);
    t.ok(bytesEqual(got, data), "read succeeds with two holders offline");
    nodes.forEach((n) => n.close());
  }

  t.group("self-healing: repair restores redundancy after loss (§9)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 8, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const data = file(128, 5); // 2 blocks → 1 RS chunk (n=4)
    const put = await owner.put(data);
    const chunks = chunkBlockIds(nodes.filter((n) => n !== owner));
    t.ok(chunks.length >= 1, "found the chunk descriptor among holders");
    const ids = chunks[0];

    const before = liveBlockCount(nodes, net, ids);
    t.eq(before, 4, "all n=4 blocks live after PUT");

    // Find two online peers holding a block of this chunk and take them offline
    // (Lost, §8).
    const holders = nodes.filter((n) => n !== owner && ids.some((id) => n.store.has(id)));
    net.setOnline(holders[0].peerId, false);
    net.setOnline(holders[1].peerId, false);
    const degraded = liveBlockCount(nodes, net, ids);
    t.ok(degraded <= 2, `redundancy dropped after losing two holders (live=${degraded})`);

    // Any online block-holder runs the repair loop; it reconstructs the missing
    // blocks and places them on fresh peers (idempotent, §9).
    const online = nodes.filter((n) => n !== owner && net.isOnline(n.peerId));
    for (const n of online) await n.runRepair();

    const healed = liveBlockCount(nodes, net, ids);
    t.ok(healed >= config.k + Math.ceil(config.m / 2), `repair lifted redundancy back above low-water (live=${healed})`);
    const got = await owner.get(put.manifestId, put.key);
    t.ok(bytesEqual(got, data), "file still reads after loss + repair");
    nodes.forEach((n) => n.close());
  }

  // Fewest distinct online holders across a set of block-ids — the redundancy that
  // matters for a k=1 (RS(1,1)) chunk: one id per chunk, replicated onto r peers, so
  // the count of distinct *ids* maxes out at 1 and hides the loss of a copy.
  const minHolders = (nodes, net, ids) =>
    Math.min(...ids.map((id) => nodes.filter((n) => net.isOnline(n.peerId) && n.store.has(id)).length));

  t.group("self-healing re-replicates a k=1 (RS(1,1)) file — chunks + manifest (§9)");
  {
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 1, blockSize: 64 };            // the p2p.html demo config
    const nodes = await createConnectedCohort({ count: 5, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    // Nothing about durability is a config field any more: r = m+1 and the low-water
    // mark come off each chunk's signed descriptor, so overriding k/m cannot leave a
    // stale knob behind (an unreachable low-water would make repair never settle). The
    // "2 holders" + idempotence checks below exercise both end-to-end.
    const data = file(256, 11);                            // 4 blocks → 4 RS(1,1) chunks
    const put = await owner.put(data);
    t.ok(!put.replicated, "a multi-block k=1 file windows (not the whole-file small path); each chunk is replicated (healReplicated)");
    // put.blockIds = each chunk's single (replicated) block id + the manifest.
    t.eq(minHolders(nodes, net, put.blockIds), 2, "every block — chunks and manifest — is on 2 holders after PUT");

    const holder = nodes.find((n) => n !== owner && n.store.list().length > 0);
    net.setOnline(holder.peerId, false);                  // a holder leaves (tab closes)
    t.eq(minHolders(nodes, net, put.blockIds), 1, "redundancy drops to 1 copy for the blocks it held");

    const online = nodes.filter((n) => n !== owner && net.isOnline(n.peerId));
    let replaced = 0;
    for (const n of online) replaced += await n.runRepair();
    t.ok(replaced >= 1, `repair re-replicated the lost copies (placed=${replaced})`);
    t.ok(minHolders(nodes, net, put.blockIds) >= 2, "every block — incl. the manifest — is back on >= 2 holders");
    t.ok(bytesEqual(await owner.get(put.manifestId, put.key), data), "file still reads after loss + repair");

    // Idempotent: a second pass over now-healthy chunks re-places nothing (§9).
    let again = 0;
    for (const n of online) again += await n.runRepair();
    t.eq(again, 0, "repair is idempotent once redundancy is restored");
    nodes.forEach((n) => n.close());
  }

  t.group("repair settles on a high-redundancy k=1 config (RS(1,4)) (§9)");
  {
    // RS(1,4) is replication r = m+1 = 5: each chunk's lone id lives on 5 distinct
    // holders, giving a loss margin of 4 against a low-water margin of ceil(m/2) = 2.
    // Repair must read the *full* live-holder set, never a capped sample: a sample of,
    // say, 2 reads a margin of 1 < 2 and would re-place on every pass, never settling.
    // A freshly-PUT, fully-healthy file must therefore be a strict no-op for repair.
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 4, blockSize: 64 };
    const nodes = await createConnectedCohort({ count: 7, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT }); // owner + 6 holders >= r=5
    const owner = nodes[0];
    const data = file(256, 41);                            // 4 blocks → windowed (per-chunk replication)
    const put = await owner.put(data);
    t.ok(!put.replicated, "multi-block k=1 file windows; each chunk is replicated r=5 ways");

    let replaced = 0;
    for (const n of nodes.filter((x) => x !== owner)) replaced += await n.runRepair();
    t.eq(replaced, 0, "repair places nothing on an already-healthy file (reads the full holder set, §9)");
    t.ok(bytesEqual(await owner.get(put.manifestId, put.key), data), "file still reads after the repair pass");
    nodes.forEach((n) => n.close());
  }

  t.group("mixed geometry: a replicated chunk is repaired to ITS OWN r, not the repairer's config (§4.1, §9)");
  {
    // §4.1 permits a cohort to run mixed geometry, because every chunk descriptor is
    // self-describing. That promise only holds if the *replica target* is descriptor-math
    // too: here the owner writes at RS(1,4) — r = m+1 = 5 copies, low-water margin
    // ceil(4/2) = 2 — while every holder is configured RS(1,1), which for its own writes
    // would be r = 2. A repairer reading r (and the low-water mark) off its own config
    // sees 2 live copies of a 5-copy chunk, calls it healthy, and repairs nothing.
    const net = new LoopbackNetwork();
    const wasmOpts = { network: net, sodium, bundleBlob: wasm.bundleBlob, timeoutMs: TIMEOUT };
    const owner = await StorageNode.create({ ...wasmOpts, config: { k: 1, m: 4, blockSize: 64 } });
    const holders = [];
    for (let i = 0; i < 7; i++) {
      holders.push(await StorageNode.create({ ...wasmOpts, config: { k: 1, m: 1, blockSize: 64 } }));
    }
    const all = [owner, ...holders];
    for (let i = 0; i < all.length; i++) for (let j = i + 1; j < all.length; j++) StorageNode.connect(all[i], all[j]);

    const data = file(64, 47);                             // 1 block → the small replicated path
    const put = await owner.put(data);
    t.ok(put.replicated, "the owner wrote one replicated chunk at its own RS(1,4)");
    t.eq(minHolders(all, net, put.blockIds), 5, "r = m+1 = 5 copies of every block, per the WRITER's geometry");

    // Lose three copies of the chunk's block: margin 5−1 = 4 drops to 1, under the
    // descriptor's low-water margin of 2.
    const chunkId = put.blockIds[0];
    const held = holders.filter((n) => n.store.has(chunkId));
    for (const n of held.slice(0, 3)) net.setOnline(n.peerId, false);
    t.eq(minHolders(all, net, [chunkId]), 2, "two copies live — healthy under the repairer's own RS(1,1), not under the chunk's");

    let replaced = 0;
    for (const n of holders) if (net.isOnline(n.peerId)) replaced += await n.runRepair();
    t.ok(replaced > 0, `a differently-configured holder still healed the chunk (placed=${replaced})`);
    t.ok(minHolders(all, net, [chunkId]) > 2, `copies restored toward the descriptor's r=5 (now ${minHolders(all, net, [chunkId])})`);
    t.ok(bytesEqual(await owner.get(put.manifestId, put.key), data), "the file still reads after the mixed-geometry repair");
    all.forEach((n) => n.close());
  }

  t.group("startRepairLoop runs repair on a jittered interval, then settles (§9)");
  {
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 1, blockSize: 64 };
    const nodes = await createConnectedCohort({ count: 5, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const put = await owner.put(file(256, 13));            // multi-block → windowed replication

    const holder = nodes.find((n) => n !== owner && n.store.list().length > 0);
    net.setOnline(holder.peerId, false);

    let passes = 0;
    const online = nodes.filter((n) => n !== owner && net.isOnline(n.peerId));
    for (const n of online) n.startRepairLoop({ intervalMs: 25, jitter: 0.3, onPass: () => { passes++; } });
    await new Promise((r) => setTimeout(r, 800));
    for (const n of online) n.stopRepairLoop();

    t.ok(passes > 0, `the loop fired at least one pass on its own (passes=${passes})`);
    t.ok(minHolders(nodes, net, put.blockIds) >= 2, "the loop restored redundancy with no manual call");
    // stopRepairLoop() must actually stop it — no further passes after a settle.
    const at = passes;
    await new Promise((r) => setTimeout(r, 150));
    t.eq(passes, at, "stopRepairLoop() halts the loop (no passes after stop)");
    nodes.forEach((n) => n.close());
  }

  t.group("sharing is sharing the key, not the bytes (§4.4)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0], recipient = nodes[1];
    const data = file(200, 11);
    const put = await owner.put(data);
    // Owner seals K to the recipient's kernel key; recipient opens and reads.
    const sealed = owner.shareKey(put.key, recipient.identity.publicKey);
    const K = recipient.openKey(sealed);
    t.ok(K && bytesEqual(K, put.key), "recipient recovers K from the seal");
    const got = await recipient.get(put.manifestId, K);
    t.ok(bytesEqual(got, data), "recipient reads the shared file");
    // A stranger in the cohort cannot open the seal.
    t.ok(nodes[2].openKey(sealed) === null, "a non-recipient cannot open the seal");
    nodes.forEach((n) => n.close());
  }

  t.group("crypto-shredding: without K the bytes are noise (§11)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const data = file(200, 13);
    const put = await owner.put(data);
    // Crypto-shred = discard K. A reader with the wrong key recovers nothing.
    const wrongK = owner.crypto.randomKey();
    let leaked = false;
    try { leaked = bytesEqual(await owner.get(put.manifestId, wrongK), data); }
    catch { leaked = false; } // manifest fails to parse under the wrong key
    t.ok(!leaked, "ciphertext on holders is permanent noise once K is gone");
    nodes.forEach((n) => n.close());
  }

  t.group("reciprocity: serving raises a holder's local standing (§13)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const put = await owner.put(file(200, 17));
    await owner.get(put.manifestId, put.key); // verification-fetches feed scoring
    let anyPositive = false;
    for (const n of nodes) {
      if (n === owner) continue;
      // Reputation now lives in the installed reputation handler the guest scores
      // through; the owner reads a holder's standing the same way (§13).
      if (owner.score(n.identity.publicKey) > 0) anyPositive = true;
    }
    t.ok(anyPositive, "holders that served the owner gained positive standing");
    nodes.forEach((n) => n.close());
  }

  // The browser demos run k=1 (RS(1,·)) on two or three holders — a shape the groups
  // above never used (they are all RS(2,2) on a full cohort). That blind spot is
  // why two real bugs shipped: the old degenerate coded k=1 repeated one id across its
  // slots, so it leaked into the returned set (the "13/13" holder probe); and a cohort
  // smaller than n=k+m used to fail the whole PUT. k=1 is now replication (one id per
  // chunk, m=0 descriptor), so the dup-id leak is structurally impossible — cover both.
  t.group("k=1 replication on a 2-holder cohort (RS(1,9) on an undersized cohort)");
  {
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 9, blockSize: 64 };
    const nodes = await createConnectedCohort({ count: 3, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT }); // owner + 2 holders
    const owner = nodes[0];
    const data = file(400, 23); // > 1 block → windowed, several chunks

    const put = await owner.put(data);
    t.ok(!put.replicated, "k=1 multi-block file windows into per-chunk replication");

    // The returned set must name each placed id once: the 13/13 probe was a
    // duplicate id leaking into blockIds (the old degenerate coded k=1), not the store lying.
    const hexes = put.blockIds.map(toHex);
    t.eq(new Set(hexes).size, hexes.length, "PUT reports each placed block id once (no dup-id leak)");

    // has() must agree with list() on every holder — has reporting an id the
    // holder does not actually store would be the bug we shipped.
    let consistent = true;
    for (const n of nodes.filter((x) => x !== owner)) {
      const held = new Set(n.store.list().map(toHex));
      for (const h of hexes) if (n.store.has(fromHex(h)) !== held.has(h)) consistent = false;
    }
    t.ok(consistent, "every holder's has(id) matches its store.list()");

    t.ok(bytesEqual(await owner.get(put.manifestId, put.key), data), "GET round-trips on a 2-holder cohort");

    // What the demo user actually did: kill a holder, then read. k=1 means any one
    // surviving copy reconstructs the file.
    net.setOnline(nodes[1].peerId, false);
    t.ok(bytesEqual(await owner.get(put.manifestId, put.key), data), "GET still reads after a holder is killed");
    nodes.forEach((n) => n.close());
  }

  t.group("PUT on a cohort smaller than n = k+m succeeds best-effort (§6, §9)");
  {
    // RS(2,2) wants n=4 distinct holders; with only 3 the reference places what it
    // can (≥ k distinct blocks) and leans on repair, rather than failing the PUT.
    const net = new LoopbackNetwork();
    const cfg = { k: 2, m: 2, blockSize: 64 };
    const nodes = await createConnectedCohort({ count: 4, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT }); // owner + 3 holders < n=4
    const owner = nodes[0];
    const data = file(300, 29);
    const put = await owner.put(data); // threw before best-effort placement
    t.ok(put.blockIds.length > 0, "PUT places across the 3 available holders instead of failing");
    t.ok(bytesEqual(await owner.get(put.manifestId, put.key), data), "GET reconstructs from a sub-n placement");
    nodes.forEach((n) => n.close());
  }

  t.group("maxMessageBytes mismatch: a holder's smaller FETCH cap degrades, never fails (§18)");
  {
    // maxMessageBytes is per-node operator policy, so a cohort can diverge: this owner
    // sizes FETCH sub-batches for 4 blocks per response (cap 280 = 4·(64+5) + header),
    // while its holders serve at most ~1 block per response (cap 100). A block past a
    // holder's cap comes back tagged FETCH_UNANSWERED — held, but no room this response —
    // distinct from a genuine miss. serveFetch must always serve the first present block,
    // and the reader must re-request exactly the unanswered blocks (runFetchTasks), so the
    // mismatch costs round trips, not data.
    const net = new LoopbackNetwork();
    const ownerCfg = { k: 2, m: 2, blockSize: 64, maxMessageBytes: 280 };
    const holderCfg = { ...ownerCfg, maxMessageBytes: 100 };
    const mk = (cfg) => StorageNode.create({ network: net, sodium, ...wasm, config: cfg, timeoutMs: TIMEOUT });
    const owner = await mk(ownerCfg);
    const holders = [await mk(holderCfg), await mk(holderCfg), await mk(holderCfg), await mk(holderCfg)];
    const nodes = [owner, ...holders];
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) StorageNode.connect(nodes[i], nodes[j]);
    }

    const data = file(256, 41); // 4 blocks → 2 RS(2,2) chunks, block i of each on holder i
    const put = await owner.put(data);
    t.ok(!put.replicated, "the file takes the RS path");

    // Pin the scenario at the wire: a raw 2-id FETCH to a holder that stores both
    // must come back with the first block served (the progress guarantee) and the second
    // marked UNANSWERED (over the holder's 100-byte cap, but held). If this ever stops
    // hitting the cap, the GET below no longer exercises the mismatch.
    const holder = holders.find((h) => h.store.list().length >= 2);
    t.ok(!!holder, "a holder carries at least two blocks");
    const [idA, idB] = holder.store.list();
    const raw = await owner.transport.request(holder.peerId, 3 /* MSG_FETCH */, encodeFetchBatchReq([idA, idB]));
    const served = decodeFetchBatchRes(raw);
    t.ok(served[0] !== null && bytesEqual(served[0], holder.store.get(idA).bytes), "the first present block is always served, even near the cap");
    t.eq(served[1], FETCH_UNANSWERED, "the second block is marked UNANSWERED by the holder's smaller cap");

    t.ok(bytesEqual(await owner.get(put.manifestId, put.key), data), "GET completes across the cap mismatch (unanswered block re-requested, not marked tried)");
    nodes.forEach((n) => n.close());
  }
}

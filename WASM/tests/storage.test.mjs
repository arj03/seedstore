// End-to-end multi-node tests over the loopback network: a storage node booted
// on the real seedkernel, then PUT → place → GET → repair across simulated
// peers (README Part I). These are the integration tests that exercise the
// whole onion together.
//
// The "loopback network" is the new in-process fabric (host/loopback.ts): the
// real transport bundle runs between the nodes — AKE, record layer, routing —
// over microtask-delivered channel pairs, and `setOnline`/`isOnline` mirror the
// old LoopbackNetwork's offline control by killing a peer's links.

import {
  LoopbackNetwork, loadWasmBytes, loadSodium, createConnectedCohort, StorageNode,
} from "../build/host/node.js";
import { encodeFetchBatchReq, decodeFetchBatchRes, encodeStoreBatch, decodeMask, FETCH_UNANSWERED, VERDICT_ACCEPTED, VERDICT_DECLINED, VERDICT_QUOTA, VERDICT_SIBLING, VERDICT_DESCRIPTOR, MsgType } from "../build/host/protocol.js";
import { parseSignedDescriptor, signDescriptor, encodeDescriptorList } from "../build/host/manifest.js";
import { MemoryFs } from "seedkernel-wasm/fs-memory";
import { toHex, fromHex, bytesEqual } from "../build/host/util.js";
import { liveBlockCount, newKey, plantBlock } from "./helpers.mjs";

const TIMEOUT = 40; // ms — keep offline-peer timeouts snappy in tests
const enc = new TextEncoder();
const SEEDSTORE_PROTO = enc.encode("seedstore");

function typed(type, data) {
  const out = new Uint8Array(1 + data.length);
  out[0] = type; out.set(data, 1);
  return out;
}

function file(n, seed = 1) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + seed * 7) & 255;
  return out;
}

// Collect each distinct chunk's block-ids by scanning holders' stores (every
// holder carries the chunk's signed descriptor, §4.3).
async function chunkBlockIds(nodes) {
  const seen = new Map();
  for (const node of nodes) {
    for (const id of await node.store.list()) {
      const sb = await node.store.get(id);
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
  const config = { k: 2, m: 2, blockSize: 1024 };

  t.group("node boots on seedkernel: pure codec + reputation handlers installed (§19)");
  {
    const net = new LoopbackNetwork();
    const [node] = await createConnectedCohort({ count: 1, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    t.ok(node.handlersInstalled(), "codec + reputation installed as kernel handlers");
    node.close();
    net.close();
  }

  t.group("PUT → GET round trip across a cohort (RS path, §6, §7)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const data = file(3200); // 4 blocks → 2 RS chunks
    const put = await owner.put(data);
    t.eq(put.chunkCount, 2, "3200 bytes / (k=2 × 1024) → 2 chunks");
    const got = await owner.get(put.root, put.key);
    t.ok(bytesEqual(got, data), "GET reconstructs the original file");
    // Blocks really live on distinct peers, not the owner.
    const holders = [];
    for (const n of nodes) { if (n !== owner && (await n.store.list()).length > 0) holders.push(n); }
    t.ok(holders.length >= 4, "blocks placed across several distinct peers");
    t.eq((await owner.store.list()).length, 0, "owner holds no blocks — durability leans on the cohort");
    nodes.forEach((n) => n.close());
    net.close();
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
    t.eq(put.chunkCount, 3, "spans 3 RS chunks");
    const got = await owner.get(put.root, put.key);
    t.ok(bytesEqual(got, data), "GET reconstructs a file coded in > 128 KB blocks");
    nodes.forEach((n) => n.close());
    net.close();
  }

  t.group("small file — sub-chunk plaintext → k=1 replicated chunk (§4.1)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const data = file(640, 9); // < 1 block → k=1 chunk, its id listed m+1 times
    const put = await owner.put(data);
    const got = await owner.get(put.root, put.key);
    t.ok(bytesEqual(got, data), "sub-chunk file round-trips via per-chunk k");
    nodes.forEach((n) => n.close());
    net.close();
  }

  t.group("offline tolerance: any k of n still reads (§7, §8)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const data = file(3200, 3);
    const put = await owner.put(data);
    // Take two peers offline (≤ m of any chunk, since blocks are on distinct
    // peers). Manifest is replicated on r=3 peers, so it stays reachable too.
    net.setOnline(nodes[1].peerId, false);
    net.setOnline(nodes[2].peerId, false);
    const got = await owner.get(put.root, put.key);
    t.ok(bytesEqual(got, data), "read succeeds with two holders offline");
    nodes.forEach((n) => n.close());
    net.close();
  }

  t.group("self-healing: repair restores redundancy after loss (§9)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 8, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const data = file(2048, 5); // 2 blocks → 1 RS chunk (n=4)
    const put = await owner.put(data);
    const chunks = await chunkBlockIds(nodes.filter((n) => n !== owner));
    t.ok(chunks.length >= 1, "found the chunk descriptor among holders");
    const ids = chunks[0];

    const before = await liveBlockCount(nodes, net, ids);
    t.eq(before, 4, "all n=4 blocks live after PUT");

    // Find two online peers holding a block of this chunk and take them offline
    // (Lost, §8).
    const holders = [];
    for (const n of nodes) { if (n !== owner && (await storeHoldsAny(n, ids))) holders.push(n); }
    net.setOnline(holders[0].peerId, false);
    net.setOnline(holders[1].peerId, false);
    const degraded = await liveBlockCount(nodes, net, ids);
    t.ok(degraded <= 2, `redundancy dropped after losing two holders (live=${degraded})`);

    // Any online block-holder runs the repair loop; it reconstructs the missing
    // blocks and places them on fresh peers (idempotent, §9).
    const online = nodes.filter((n) => n !== owner && net.isOnline(n.peerId));
    for (const n of online) await n.runRepair();

    const healed = await liveBlockCount(nodes, net, ids);
    t.ok(healed >= config.k + Math.ceil(config.m / 2), `repair lifted redundancy back above low-water (live=${healed})`);
    const got = await owner.get(put.root, put.key);
    t.ok(bytesEqual(got, data), "file still reads after loss + repair");
    nodes.forEach((n) => n.close());
    net.close();
  }

  // Fewest distinct online holders across a set of block-ids — the redundancy that
  // matters for a k=1 (RS(1,1)) chunk: one id per chunk, replicated onto r peers, so
  // the count of distinct *ids* maxes out at 1 and hides the loss of a copy.
  const minHolders = async (nodes, net, ids) => {
    const perId = [];
    for (const id of ids) {
      let n = 0;
      for (const node of nodes) if (net.isOnline(node.peerId) && (await node.store.has(id))) n++;
      perId.push(n);
    }
    return Math.min(...perId);
  };

  t.group("self-healing re-replicates a k=1 (RS(1,1)) file — chunks + manifest (§9)");
  {
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 1, blockSize: 1024 };            // the p2p.html demo config
    const nodes = await createConnectedCohort({ count: 5, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    // Nothing about durability is a config field any more: r = m+1 and the low-water
    // mark come off each chunk's signed descriptor, so overriding k/m cannot leave a
    // stale knob behind (an unreachable low-water would make repair never settle). The
    // "2 holders" + idempotence checks below exercise both end-to-end.
    const data = file(4096, 11);                           // 4 blocks → 4 RS(1,1) chunks
    const put = await owner.put(data);
    // put.blockIds = each chunk's single (replicated) block id + the manifest.
    t.eq(await minHolders(nodes, net, put.blockIds), 2, "every block — chunks and manifest — is on 2 holders after PUT");

    let holder = null;
    for (const n of nodes) { if (n !== owner && (await n.store.list()).length > 0) { holder = n; break; } }
    net.setOnline(holder.peerId, false);                  // a holder leaves (tab closes)
    t.eq(await minHolders(nodes, net, put.blockIds), 1, "redundancy drops to 1 copy for the blocks it held");

    const online = nodes.filter((n) => n !== owner && net.isOnline(n.peerId));
    let replaced = 0;
    for (const n of online) replaced += await n.runRepair();
    t.ok(replaced >= 1, `repair re-replicated the lost copies (placed=${replaced})`);
    t.ok((await minHolders(nodes, net, put.blockIds)) >= 2, "every block — incl. the index — is back on >= 2 holders");
    t.ok(bytesEqual(await owner.get(put.root, put.key), data), "file still reads after loss + repair");

    // Idempotent: a second pass over now-healthy chunks re-places nothing (§9).
    let again = 0;
    for (const n of online) again += await n.runRepair();
    t.eq(again, 0, "repair is idempotent once redundancy is restored");
    nodes.forEach((n) => n.close());
    net.close();
  }

  t.group("repair settles on a high-redundancy k=1 config (RS(1,4)) (§9)");
  {
    // RS(1,4) is replication r = m+1 = 5: each chunk's lone id lives on 5 distinct
    // holders, giving a loss margin of 4 against a low-water margin of ceil(m/2) = 2.
    // Repair must read the *full* live-holder set, never a capped sample: a sample of,
    // say, 2 reads a margin of 1 < 2 and would re-place on every pass, never settling.
    // A freshly-PUT, fully-healthy file must therefore be a strict no-op for repair.
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 4, blockSize: 1024 };
    const nodes = await createConnectedCohort({ count: 7, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT }); // owner + 6 holders >= r=5
    const owner = nodes[0];
    const data = file(4096, 41);                           // 4 blocks → windowed (per-chunk replication)
    const put = await owner.put(data);

    let replaced = 0;
    for (const n of nodes.filter((x) => x !== owner)) replaced += await n.runRepair();
    t.eq(replaced, 0, "repair places nothing on an already-healthy file (reads the full holder set, §9)");
    t.ok(bytesEqual(await owner.get(put.root, put.key), data), "file still reads after the repair pass");
    nodes.forEach((n) => n.close());
    net.close();
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
    const ownerId = sodium.crypto_sign_keypair();
    const owner = await StorageNode.create({
      sodium, bundleBlob: wasm.bundleBlob, identity: ownerId,
      channels: net.view(toHex(ownerId.publicKey)), listen: { host: "127.0.0.1", port: 0 },
      config: { k: 1, m: 4, blockSize: 1024 }, timeoutMs: TIMEOUT,
    });
    const holders = [];
    for (let i = 0; i < 7; i++) {
      const id = sodium.crypto_sign_keypair();
      holders.push(await StorageNode.create({
        sodium, bundleBlob: wasm.bundleBlob, identity: id,
        channels: net.view(toHex(id.publicKey)), listen: { host: "127.0.0.1", port: 0 },
        config: { k: 1, m: 1, blockSize: 1024 }, timeoutMs: TIMEOUT,
      }));
    }
    const all = [owner, ...holders];
    for (let i = 0; i < all.length; i++) for (let j = i + 1; j < all.length; j++) await StorageNode.connect(all[i], all[j]);

    const data = file(1024, 47);                           // 1 block → k=1 chunk
    const put = await owner.put(data);
    t.eq(await minHolders(all, net, put.blockIds), 5, "r = m+1 = 5 copies of every block, per the WRITER's geometry");

    // Lose three copies of the chunk's block: margin 5−1 = 4 drops to 1, under the
    // descriptor's low-water margin of 2.
    const chunkId = put.blockIds[0];
    const held = [];
    for (const n of holders) if (await n.store.has(chunkId)) held.push(n);
    for (const n of held.slice(0, 3)) net.setOnline(n.peerId, false);
    t.eq(await minHolders(all, net, [chunkId]), 2, "two copies live — healthy under the repairer's own RS(1,1), not under the chunk's");

    let replaced = 0;
    for (const n of holders) if (net.isOnline(n.peerId)) replaced += await n.runRepair();
    t.ok(replaced > 0, `a differently-configured holder still healed the chunk (placed=${replaced})`);
    t.ok((await minHolders(all, net, [chunkId])) > 2, `copies restored toward the descriptor's r=5 (now ${await minHolders(all, net, [chunkId])})`);
    t.ok(bytesEqual(await owner.get(put.root, put.key), data), "the file still reads after the mixed-geometry repair");
    all.forEach((n) => n.close());
    net.close();
  }

  t.group("startRepairLoop runs repair on a jittered interval, then settles (§9)");
  {
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 1, blockSize: 1024 };
    const nodes = await createConnectedCohort({ count: 5, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const put = await owner.put(file(4096, 13));           // multi-block → windowed replication

    let holder = null;
    for (const n of nodes) { if (n !== owner && (await n.store.list()).length > 0) { holder = n; break; } }
    net.setOnline(holder.peerId, false);

    let passes = 0;
    const online = nodes.filter((n) => n !== owner && net.isOnline(n.peerId));
    for (const n of online) n.startRepairLoop({ intervalMs: 25, jitter: 0.3, onPass: () => { passes++; } });
    await new Promise((r) => setTimeout(r, 800));
    for (const n of online) n.stopRepairLoop();

    t.ok(passes > 0, `the loop fired at least one pass on its own (passes=${passes})`);
    t.ok((await minHolders(nodes, net, put.blockIds)) >= 2, "the loop restored redundancy with no manual call");
    // stopRepairLoop() must actually stop it — no further passes after a settle.
    const at = passes;
    await new Promise((r) => setTimeout(r, 150));
    t.eq(passes, at, "stopRepairLoop() halts the loop (no passes after stop)");
    nodes.forEach((n) => n.close());
    net.close();
  }

  t.group("sharing is sharing the key, not the bytes (§4.4)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0], recipient = nodes[1];
    const data = file(3200, 11);
    const put = await owner.put(data);
    // Owner seals K to the recipient's kernel key; recipient opens and reads.
    const sealed = owner.shareKey(put.key, recipient.identity.publicKey);
    const K = recipient.openKey(sealed);
    t.ok(K && bytesEqual(K, put.key), "recipient recovers K from the seal");
    const got = await recipient.get(put.root, K);
    t.ok(bytesEqual(got, data), "recipient reads the shared file");
    // A stranger in the cohort cannot open the seal.
    t.ok(nodes[2].openKey(sealed) === null, "a non-recipient cannot open the seal");
    nodes.forEach((n) => n.close());
    net.close();
  }

  t.group("crypto-shredding: without K the bytes are noise (§11)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const data = file(3200, 13);
    const put = await owner.put(data);
    // Crypto-shred = discard K. A reader with the wrong key recovers nothing.
    const wrongK = owner.crypto.randomKey();
    let leaked = false;
    try { leaked = bytesEqual(await owner.get(put.root, wrongK), data); }
    catch { leaked = false; } // manifest fails to parse under the wrong key
    t.ok(!leaked, "ciphertext on holders is permanent noise once K is gone");
    nodes.forEach((n) => n.close());
    net.close();
  }

  t.group("reciprocity: serving raises a holder's local standing (§13)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const put = await owner.put(file(3200, 17));
    await owner.get(put.root, put.key); // verification-fetches feed scoring
    let anyPositive = false;
    for (const n of nodes) {
      if (n === owner) continue;
      // Reputation now lives in the installed reputation handler the guest scores
      // through; the owner reads a holder's standing the same way (§13).
      if (owner.score(n.identity.publicKey) > 0) anyPositive = true;
    }
    t.ok(anyPositive, "holders that served the owner gained positive standing");
    nodes.forEach((n) => n.close());
    net.close();
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
    const cfg = { k: 1, m: 9, blockSize: 1024 };
    const nodes = await createConnectedCohort({ count: 3, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT }); // owner + 2 holders
    const owner = nodes[0];
    const data = file(6400, 23); // > 1 block → windowed, several chunks

    const put = await owner.put(data);

    // The returned set must name each placed id once: the 13/13 probe was a
    // duplicate id leaking into blockIds (the old degenerate coded k=1), not the store lying.
    const hexes = put.blockIds.map(toHex);
    t.eq(new Set(hexes).size, hexes.length, "PUT reports each placed block id once (no dup-id leak)");

    // has() must agree with list() on every holder — has reporting an id the
    // holder does not actually store would be the bug we shipped.
    let consistent = true;
    for (const n of nodes.filter((x) => x !== owner)) {
      const held = new Set((await n.store.list()).map(toHex));
      for (const h of hexes) if ((await n.store.has(fromHex(h))) !== held.has(h)) consistent = false;
    }
    t.ok(consistent, "every holder's has(id) matches its store.list()");

    t.ok(bytesEqual(await owner.get(put.root, put.key), data), "GET round-trips on a 2-holder cohort");

    // What the demo user actually did: kill a holder, then read. k=1 means any one
    // surviving copy reconstructs the file.
    net.setOnline(nodes[1].peerId, false);
    t.ok(bytesEqual(await owner.get(put.root, put.key), data), "GET still reads after a holder is killed");
    nodes.forEach((n) => n.close());
    net.close();
  }

  t.group("PUT on a cohort smaller than n = k+m succeeds best-effort (§6, §9)");
  {
    // RS(2,2) wants n=4 distinct holders; with only 3 the reference places what it
    // can (≥ k distinct blocks) and leans on repair, rather than failing the PUT.
    const net = new LoopbackNetwork();
    const cfg = { k: 2, m: 2, blockSize: 1024 };
    const nodes = await createConnectedCohort({ count: 4, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT }); // owner + 3 holders < n=4
    const owner = nodes[0];
    const data = file(4800, 29);
    const put = await owner.put(data); // threw before best-effort placement
    t.ok(put.blockIds.length > 0, "PUT places across the 3 available holders instead of failing");
    t.ok(bytesEqual(await owner.get(put.root, put.key), data), "GET reconstructs from a sub-n placement");
    nodes.forEach((n) => n.close());
    net.close();
  }

  t.group("maxMessageBytes mismatch: a holder's smaller FETCH cap degrades, never fails (§18)");
  {
    // maxMessageBytes is per-node operator policy, so a cohort can diverge: this owner
    // sizes FETCH sub-batches for 4 blocks per response (cap 4480 > 4·(1024+5) + header),
    // while its holders serve at most ~1 block per response (cap 1600). A block past a
    // holder's cap comes back tagged FETCH_UNANSWERED — held, but no room this response —
    // distinct from a genuine miss. serveFetch must always serve the first present block,
    // and the reader must re-request exactly the unanswered blocks (runFetchTasks), so the
    // mismatch costs round trips, not data.
    const net = new LoopbackNetwork();
    const ownerCfg = { k: 2, m: 2, blockSize: 1024, maxMessageBytes: 4480 };
    const holderCfg = { ...ownerCfg, maxMessageBytes: 1600 };
    const mk = (cfg, tag) => StorageNode.create({
      sodium, bundleBlob: wasm.bundleBlob, identity: tag,
      channels: net.view(toHex(tag.publicKey)), listen: { host: "127.0.0.1", port: 0 },
      config: cfg, timeoutMs: TIMEOUT,
    });
    const owner = await mk(ownerCfg, sodium.crypto_sign_keypair());
    const holders = [];
    for (let i = 0; i < 4; i++) holders.push(await mk(holderCfg, sodium.crypto_sign_keypair()));
    const nodes = [owner, ...holders];
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) await StorageNode.connect(nodes[i], nodes[j]);
    }

    const data = file(4096, 41); // 4 blocks → 2 RS(2,2) chunks, block i of each on holder i
    const put = await owner.put(data);

    // Pin the scenario at the wire: a raw 2-id FETCH to a holder that stores both
    // must come back with the first block served (the progress guarantee) and the second
    // marked UNANSWERED (over the holder's 1600-byte cap, but held). If this ever stops
    // hitting the cap, the GET below no longer exercises the mismatch.
    let holder = null;
    for (const h of holders) { if ((await h.store.list()).length >= 2) { holder = h; break; } }
    t.ok(!!holder, "a holder carries at least two blocks");
    const [idA, idB] = await holder.store.list();
    const raw = await owner.transport.request(holder.peerId, SEEDSTORE_PROTO, typed(MsgType.FETCH, encodeFetchBatchReq([idA, idB])));
    const served = decodeFetchBatchRes(raw);
    t.ok(served[0] !== null && bytesEqual(served[0], (await holder.store.get(idA)).bytes), "the first present block is always served, even near the cap");
    t.eq(served[1], FETCH_UNANSWERED, "the second block is marked UNANSWERED by the holder's smaller cap");

    t.ok(bytesEqual(await owner.get(put.root, put.key), data), "GET completes across the cap mismatch (unanswered block re-requested, not marked tried)");
    nodes.forEach((n) => n.close());
    net.close();
  }

  // ── Verdict diagnostics ────────────────────────────────────────────────────
  t.group("a zero-quota holder declines every OFFER/STORE as VERDICT_QUOTA, and the error names the reason");
  {
    const net = new LoopbackNetwork();
    const cfg = { ...config, k: 1, m: 0 };               // one block per chunk, no parity
    const nodes = await createConnectedCohort({ count: 2, network: net, sodium, wasm, config: cfg, quota: 0, timeoutMs: TIMEOUT });
    const data = file(2048, 7);                           // 2 blocks → windowed path, 2 chunks
    let err = null;
    try {
      await nodes[0].put(data);
    } catch (e) { err = e; }
    t.ok(err !== null, "PUT fails when every holder declines");
    t.ok(err && /quota/.test(err.message), "the error names 'quota' in the declined-reason summary");
    nodes.forEach((n) => n.close());
    net.close();
  }

  // ── §14 a holder that FAILS is not a holder that is FULL ───────────────────
  t.group("a holder whose backend write fails answers VERDICT_ERROR, not VERDICT_QUOTA (§14)");
  {
    // These were one verdict once, and the conflation is expensive in the field: a
    // holder has no console, so the verdict byte is its only voice, and reporting a
    // broken backend as "quota" sends an operator to raise a budget that was never the
    // constraint. Here the budget is enormous and the write still fails.
    const net = new LoopbackNetwork();
    const writerId = sodium.crypto_sign_keypair();
    const holderId = sodium.crypto_sign_keypair();
    const mk = (id, extra) => StorageNode.create({
      sodium, bundleBlob: wasm.bundleBlob, identity: id,
      channels: net.view(toHex(id.publicKey)), listen: { host: "127.0.0.1", port: 0 },
      config: { ...config, k: 1, m: 0 }, quota: 1 << 30, timeoutMs: TIMEOUT, ...extra,
    });
    // A backend that accepts reads and refuses the block write — a full disk, near
    // enough. The .dsc sidecar is left writable so the failure is the commit itself.
    const failing = new MemoryFs();
    const put0 = failing.put.bind(failing);
    failing.put = async (key, bytes) => {
      if (key.endsWith(".blk")) throw new Error("ENOSPC: no space left on device");
      return put0(key, bytes);
    };
    const writer = await mk(writerId);
    const holder = await mk(holderId, { fs: failing });
    try {
      await StorageNode.connect(writer, holder);
      let err = null;
      try { await writer.put(file(config.blockSize, 63)); } catch (e) { err = e; }
      t.ok(err !== null, "PUT fails when the only holder cannot commit");
      t.ok(err && /holder-error/.test(err.message), "the error names 'holder-error', not 'quota'");
      t.ok(err && !/holders: quota/.test(err.message), "a broken backend is never reported as an exhausted budget");
    } finally { [writer, holder].forEach((n) => n.close()); net.close(); }
  }

  // ── §4.3 the descriptor signature is ANCHORED, not merely valid ────────────
  t.group("a holder declines a validly-signed descriptor from an author its cohort does not know (§4.3)");
  {
    // The envelope carries its own author pubkey, so a signature checked against it alone
    // proves nothing about WHO signed: any cohort peer can mint a fresh keypair and
    // self-sign a descriptor with a truncated sibling list, defeating both the §4.3
    // "cannot substitute its own key" claim and the §6/§10 sibling rule. Anchoring the
    // author to a peer the holder knows is what makes a forgery attributable (§13).
    const net = new LoopbackNetwork();
    const [a, b] = await createConnectedCohort({ count: 2, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    try {
      const bytes = file(config.blockSize, 77);
      const bid = a.crypto.hash(bytes);
      const desc = (id, sk) => signDescriptor(
        sodium, { level: 0, k: 1, m: 0, blockSize: config.blockSize, tailBytes: config.blockSize, blockIds: [bid] },
        id.publicKey, id.privateKey, a.signAuthor,
      );

      // Signed by a real cohort peer (a, which b knows): admitted.
      const known = decodeMask(await a.transport.request(b.peerId, SEEDSTORE_PROTO,
        typed(MsgType.STORE, encodeStoreBatch([{ blockId: bid, descriptor: desc(a.identity), bytes }]))));
      t.eq(known[0], VERDICT_ACCEPTED, "a descriptor signed by a peer the holder knows is admitted");

      // Byte-for-byte the same descriptor, signed under a FRESH keypair in the same
      // scope. The signature verifies perfectly; the author is a stranger.
      const stranger = newKey();
      const bytes2 = file(config.blockSize, 78);
      const bid2 = a.crypto.hash(bytes2);
      const forged = signDescriptor(
        sodium, { level: 0, k: 1, m: 0, blockSize: config.blockSize, tailBytes: config.blockSize, blockIds: [bid2] },
        stranger.publicKey, stranger.privateKey, a.signAuthor,
      );
      const unknown = decodeMask(await a.transport.request(b.peerId, SEEDSTORE_PROTO,
        typed(MsgType.STORE, encodeStoreBatch([{ blockId: bid2, descriptor: forged, bytes: bytes2 }]))));
      t.eq(unknown[0], VERDICT_DESCRIPTOR, "a self-signed descriptor from a fresh keypair is declined — the signature is not anchored");
      t.ok(!(await b.store.has(bid2)), "nothing committed for the unanchored descriptor");
    } finally { [a, b].forEach((n) => n.close()); }
  }

  // ── §6/§10 a repeated id is a sibling of itself ────────────────────────────
  t.group("a holder declines a block it already holds, so a replica slot is not burned (§6)");
  {
    // With replication expressed as MULTIPLICITY, a k=1 chunk's m+1 listings are m+1
    // distinct peers. Silently overwriting an existing copy would fill a slot without
    // adding a holder — the chunk would look placed and be short a replica.
    const net = new LoopbackNetwork();
    const [a, b] = await createConnectedCohort({ count: 2, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    try {
      const bytes = file(config.blockSize, 91);
      const bid = a.crypto.hash(bytes);
      const env = signDescriptor(
        sodium, { level: 0, k: 1, m: 2, blockSize: config.blockSize, tailBytes: config.blockSize, blockIds: [bid, bid, bid] },
        a.identity.publicKey, a.identity.privateKey, a.signAuthor,
      );
      const first = decodeMask(await a.transport.request(b.peerId, SEEDSTORE_PROTO,
        typed(MsgType.STORE, encodeStoreBatch([{ blockId: bid, descriptor: env, bytes }]))));
      t.eq(first[0], VERDICT_ACCEPTED, "the first copy is admitted");
      const second = decodeMask(await a.transport.request(b.peerId, SEEDSTORE_PROTO,
        typed(MsgType.STORE, encodeStoreBatch([{ blockId: bid, descriptor: env, bytes }]))));
      t.eq(second[0], VERDICT_SIBLING, "a second copy of the SAME id on the same holder is declined");
    } finally { [a, b].forEach((n) => n.close()); }
  }

  // ── §4.3 the index descent is checked, not assumed ────────────────────────
  t.group("GET rejects an index level that does not descend (§4.3, §7)");
  {
    // A reader is HANDED (root, K) by whoever shared the file, and §4.4's cipher carries
    // no tag — so that sharer chose the plaintext at every level. Nothing else stops a
    // root at level ℓ from naming a list that is ALSO at level ℓ: content-addressing does
    // not catch it (the bytes genuinely hash to their ids), and the descriptors are
    // validly signed by a known author. Only the strict descent does. Note the danger is
    // a non-descending CHAIN, built bottom-up at no cost — a self-referential cycle would
    // need a hash preimage and is not constructible.
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 1, blockSize: 512 };
    const nodes = await createConnectedCohort({ count: 4, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    const [owner] = nodes;
    try {
      const K = owner.crypto.randomKey();
      const sign = (d) => signDescriptor(sodium, d, owner.identity.publicKey, owner.identity.privateKey, owner.signAuthor);
      const at = (level, ct, tailBytes) => {
        const id = owner.crypto.hash(ct);
        return { id, env: sign({ level, k: 1, m: 1, blockSize: cfg.blockSize, tailBytes, blockIds: [id, id] }) };
      };
      // Inner: a level-1 chunk. Outer: ANOTHER level-1 chunk whose plaintext is a list
      // naming the inner one. The walk therefore goes 1 → 1 and never descends. tailBytes
      // is set honestly to the list length — zero padding would be caught earlier, by
      // decodeDescriptorList refusing a zero-length entry.
      const inner = at(1, owner.crypto.encrypt(K, 1, 0, new Uint8Array(cfg.blockSize)), cfg.blockSize);
      const list = encodeDescriptorList([inner.env]);
      const outerPlain = new Uint8Array(cfg.blockSize);
      outerPlain.set(list);
      const outerCt = owner.crypto.encrypt(K, 1, 0, outerPlain);
      const outer = at(1, outerCt, list.length);
      await plantBlock(nodes[1].fs, toHex(outer.id), outerCt, outer.env);

      let err = null;
      try { await owner.get(outer.env, K); } catch (e) { err = e; }
      t.ok(err !== null, "a non-descending index is rejected rather than walked further");
      t.ok(err && /descend/.test(err.message), "the error names the failed descent");
    } finally { nodes.forEach((n) => n.close()); }
  }

  // ── §4.3 the index is a file, so it has no size ceiling ────────────────────
  t.group("a file whose index needs several levels still round-trips (§4.3)");
  {
    // The old manifest was one block, so it crossed maxMessageBytes at a bounded file
    // size and degraded rather than failing. The index is chunked like any file, so the
    // only thing a bigger file changes is how many levels the roll-up takes. Squeeze the
    // geometry (small blocks, many chunks) so this test file needs a genuinely multi-level
    // index — the case a single root descriptor could never cover.
    const net = new LoopbackNetwork();
    const cfg = { k: 2, m: 2, blockSize: 256 };            // one index chunk holds just 2 descriptors
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    try {
      const data = file(cfg.k * cfg.blockSize * 9 - 77, 55); // 9 chunks → 9 → 5 → 3 → 2 → 1: four index levels
      const put = await nodes[0].put(data);
      t.eq(put.chunkCount, 9, "nine leaf chunks");
      t.ok(put.root.length === 32 + 64 + 13 + 4 * 32, "the root is a signed descriptor envelope, not a 32-byte id");
      t.ok(parseSignedDescriptor(put.root).descriptor.level >= 2, "the roll-up needed more than one index level");
      t.ok(bytesEqual(await nodes[0].get(put.root, put.key), data), "a multi-level index round-trips");
      // Every block placed is exactly blockSize — the old manifest block was the whole
      // manifest, which is what put a ceiling on file size in the first place.
      let oversize = 0;
      for (const n of nodes) {
        for (const id of await n.store.list()) {
          if ((await n.store.get(id)).bytes.length !== cfg.blockSize) oversize++;
        }
      }
      t.eq(oversize, 0, "no block on the wire exceeds blockSize — the index has no size ceiling");
    } finally { nodes.forEach((n) => n.close()); }
  }
}

// Does `node` hold any of `ids`?
async function storeHoldsAny(node, ids) {
  for (const id of ids) if (await node.store.has(id)) return true;
  return false;
}

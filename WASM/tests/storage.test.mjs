// End-to-end multi-node tests over the loopback network: a storage node booted
// on the real seedkernel, then PUT → place → GET → repair across simulated
// peers (SPEC Part I). These are the integration tests that exercise the
// whole onion together.
//
// The "loopback network" is the in-process fabric (host/loopback.ts): the real
// transport bundle runs between the nodes — AKE, record layer, routing — over
// microtask-delivered channel pairs, and `setOffline` takes a peer offline by
// killing its links.

import {
  LoopbackNetwork, loadWasmBytes, loadSodium, createConnectedCohort, StorageNode,
  bootStorageNode, inProcessStandUp, inProcessHost,
} from "../build/host/node.js";
import { encodeFetchBatchReq, decodeFetchBatchRes, encodeStoreBatch, encodeHaveReq, decodeMask, FETCH_UNANSWERED, VERDICT_ACCEPTED, VERDICT_DECLINED, VERDICT_QUOTA, VERDICT_SIBLING, VERDICT_DESCRIPTOR, VERDICT_GROUP, MsgType } from "../build/host/protocol.js";
import { parseSignedDescriptor, signDescriptor, encodeDescriptorList } from "../build/host/descriptor.js";
import { memoryRawFiles } from "seedkernel-wasm/fs-memory";
import { toHex, fromHex, bytesEqual } from "../build/host/util.js";
import { eventually, joinGroup, liveBlockCount, newKey, plantBlock } from "./helpers.mjs";
import { TIER_CACHE, TIER_COMMITTED } from "../build/host/store-record.js";

const TIMEOUT = 40; // ms — keep offline-peer timeouts snappy in tests

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
function chunkBlockIds(nodes) {
  const seen = new Map();
  for (const node of nodes) {
    for (const id of node.store.list()) {
      const sb = node.store.get(id);
      if (!sb) continue;
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

  t.group("node boots on seedkernel: pure codec + reputation modules installed (§19)");
  {
    const net = new LoopbackNetwork();
    const [node] = await createConnectedCohort({ suppressLinkLog: true, count: 1, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    t.ok(node.handlersInstalled(), "codec + reputation installed as bundle modules");
    node.close();
    net.close();
  }

  t.group("PUT → GET round trip across a cohort (RS path, §6, §7)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const data = file(3200); // 4 blocks → 2 RS chunks
    const put = await owner.put(data);
    t.eq(put.chunkCount, 2, "3200 bytes / (k=2 × 1024) → 2 chunks");
    const got = await owner.get(put.root, put.key);
    t.ok(bytesEqual(got, data), "GET reconstructs the original file");
    // Blocks really live on distinct peers, not the owner.
    const holders = [];
    for (const n of nodes) { if (n !== owner && n.store.list().length > 0) holders.push(n); }
    t.ok(holders.length >= 4, "blocks placed across several distinct peers");
    t.eq(owner.store.list().length, 0, "owner holds no blocks — durability leans on the cohort");
    nodes.forEach((n) => n.close());
    net.close();
  }

  t.group("large blocks (> the 128 KB default module scratch) round-trip (§4.1)");
  {
    // A codec request of k·blockSize bytes can exceed the host's 128 KB
    // default module scratch, so the codec must declare its larger scratch
    // (exported `scratchSize`). RS(2,2) at 96 KiB puts both the encode request
    // and parity response past the default, over genuine (k>1) parity.
    const net = new LoopbackNetwork();
    const bigCfg = { k: 2, m: 2, blockSize: 96 * 1024 };
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 6, network: net, sodium, wasm, config: bigCfg, timeoutMs: TIMEOUT });
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
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
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
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const data = file(3200, 3);
    const put = await owner.put(data);
    // Take two peers offline (≤ m of any chunk, since blocks are on distinct
    // peers). The index is one block replicated on m+1 = 3 peers, so it stays reachable too.
    net.setOffline(nodes[1].peerId);
    net.setOffline(nodes[2].peerId);
    const got = await owner.get(put.root, put.key);
    t.ok(bytesEqual(got, data), "read succeeds with two holders offline");
    nodes.forEach((n) => n.close());
    net.close();
  }

  t.group("self-healing: repair restores redundancy after loss (§9)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 8, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const data = file(2048, 5); // 2 blocks → 1 RS chunk (n=4)
    const put = await owner.put(data);
    const chunks = chunkBlockIds(nodes.filter((n) => n !== owner));
    t.ok(chunks.length >= 1, "found the chunk descriptor among holders");
    const ids = chunks[0];

    const before = liveBlockCount(nodes, net, ids);
    t.eq(before, 4, "all n=4 blocks live after PUT");

    // Find two online peers holding a block of this chunk and take them offline
    // (Lost, §8).
    const holders = [];
    for (const n of nodes) { if (n !== owner && storeHoldsAny(n, ids)) holders.push(n); }
    net.setOffline(holders[0].peerId);
    net.setOffline(holders[1].peerId);
    const degraded = liveBlockCount(nodes, net, ids);
    t.ok(degraded <= 2, `redundancy dropped after losing two holders (live=${degraded})`);

    // Any online block-holder runs the repair loop; it reconstructs the missing
    // blocks and places them on fresh peers (idempotent, §9).
    const online = nodes.filter((n) => n !== owner && net.isOnline(n.peerId));
    for (const n of online) await n.runRepair();

    await eventually(() => liveBlockCount(nodes, net, ids) >= config.k + Math.ceil(config.m / 2));
    const healed = liveBlockCount(nodes, net, ids);
    t.ok(healed >= config.k + Math.ceil(config.m / 2), `repair lifted redundancy back above low-water (live=${healed})`);
    // Each holder audited the chunk, but the repairer's fetches told the others it was being
    // repaired, so no lost block was rebuilt on two members.
    const copies = ids.map((id) => nodes.filter((n) => net.isOnline(n.peerId) && n.store.has(id)).length);
    t.ok(copies.every((c) => c <= 1), `no block was rebuilt twice (copies per block: ${copies.join(", ")})`);
    const got = await owner.get(put.root, put.key);
    t.ok(bytesEqual(got, data), "file still reads after loss + repair");
    nodes.forEach((n) => n.close());
    net.close();
  }

  // Fewest distinct online holders across a set of block-ids — the redundancy that
  // matters for a k=1 (RS(1,1)) chunk: one id per chunk, replicated onto r peers, so
  // the count of distinct *ids* maxes out at 1 and hides the loss of a copy.
  const minHolders = (nodes, net, ids) => {
    const perId = [];
    for (const id of ids) {
      let n = 0;
      for (const node of nodes) if (net.isOnline(node.peerId) && node.store.has(id)) n++;
      perId.push(n);
    }
    return Math.min(...perId);
  };

  t.group("self-healing re-replicates a k=1 (RS(1,1)) file — chunks + manifest (§9)");
  {
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 1, blockSize: 1024 };            // the p2p.html demo config
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 5, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    // Nothing about durability is a config field: r = m+1 and the low-water
    // mark come off each chunk's signed descriptor, so overriding k/m cannot leave a
    // stale knob behind (an unreachable low-water would make repair never settle). The
    // "2 holders" + idempotence checks below exercise both end-to-end.
    const data = file(4096, 11);                           // 4 blocks → 4 RS(1,1) chunks
    const put = await owner.put(data);
    // put.blockIds = each chunk's single (replicated) block id + the index chunk's.
    t.eq(minHolders(nodes, net, put.blockIds), 2, "every block — chunks and manifest — is on 2 holders after PUT");

    let holder = null;
    for (const n of nodes) { if (n !== owner && n.store.list().length > 0) { holder = n; break; } }
    net.setOffline(holder.peerId);                  // a holder leaves (tab closes)
    t.eq(minHolders(nodes, net, put.blockIds), 1, "redundancy drops to 1 copy for the blocks it held");

    const online = nodes.filter((n) => n !== owner && net.isOnline(n.peerId));
    let replaced = 0;
    for (const n of online) replaced += await n.runRepair();
    t.ok(replaced >= 1, `repair re-replicated the lost copies (placed=${replaced})`);
    t.ok(await eventually(() => minHolders(nodes, net, put.blockIds) >= 2), "every block — incl. the index — is back on >= 2 holders");
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
    // RS(1,4) is replication r = m+1 = 5, loss margin 4 vs low-water ceil(m/2)=2.
    // Repair must read the *full* live-holder set — a capped sample would read a
    // lower margin and re-place forever, never settling.
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 4, blockSize: 1024 };
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 7, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT }); // owner + 6 holders >= r=5
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
    // §4.1's mixed-geometry promise only holds if the replica target is
    // descriptor-math too: the owner writes RS(1,4) (r=5, low-water 2) while
    // every holder is configured RS(1,1) (r=2). A repairer reading its own
    // config would see 2 live copies of a 5-copy chunk and call it healthy.
    const net = new LoopbackNetwork();
    const ownerId = sodium.crypto_sign_keypair();
    const owner = await bootStorageNode(inProcessStandUp, {
      sodium, bundleBlob: wasm.bundleBlob, identity: ownerId,
      suppressLinkLog: true, channels: net.view(toHex(ownerId.publicKey)), listen: [{ label: "tcp", host: "127.0.0.1", port: 0 }],
      config: { k: 1, m: 4, blockSize: 1024 }, timeoutMs: TIMEOUT,
    });
    const holders = [];
    for (let i = 0; i < 7; i++) {
      const id = sodium.crypto_sign_keypair();
      holders.push(await bootStorageNode(inProcessStandUp, {
        sodium, bundleBlob: wasm.bundleBlob, identity: id,
        suppressLinkLog: true, channels: net.view(toHex(id.publicKey)), listen: [{ label: "tcp", host: "127.0.0.1", port: 0 }],
        config: { k: 1, m: 1, blockSize: 1024 }, timeoutMs: TIMEOUT,
      }));
    }
    const all = [owner, ...holders];
    for (let i = 0; i < all.length; i++) for (let j = i + 1; j < all.length; j++) await StorageNode.connect(all[i], all[j]);
    await joinGroup(all);

    const data = file(1024, 47);                           // 1 block → k=1 chunk
    const put = await owner.put(data);
    t.eq(minHolders(all, net, put.blockIds), 5, "r = m+1 = 5 copies of every block, per the WRITER's geometry");

    // Lose three copies of the chunk's block: margin 5−1 = 4 drops to 1, under the
    // descriptor's low-water margin of 2.
    const chunkId = put.blockIds[0];
    const held = [];
    for (const n of holders) if (n.store.has(chunkId)) held.push(n);
    for (const n of held.slice(0, 3)) net.setOffline(n.peerId);
    t.eq(minHolders(all, net, [chunkId]), 2, "two copies live — healthy under the repairer's own RS(1,1), not under the chunk's");

    let replaced = 0;
    for (const n of holders) if (net.isOnline(n.peerId)) replaced += await n.runRepair();
    t.ok(replaced > 0, `a differently-configured holder still healed the chunk (placed=${replaced})`);
    await eventually(() => minHolders(all, net, [chunkId]) > 2);
    t.ok(minHolders(all, net, [chunkId]) > 2, `copies restored toward the descriptor's r=5 (now ${minHolders(all, net, [chunkId])})`);
    t.ok(bytesEqual(await owner.get(put.root, put.key), data), "the file still reads after the mixed-geometry repair");
    all.forEach((n) => n.close());
    net.close();
  }

  t.group("startRepairLoop runs repair on a jittered interval, then settles (§9)");
  {
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 1, blockSize: 1024 };
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 5, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const put = await owner.put(file(4096, 13));           // multi-block → windowed replication

    let holder = null;
    for (const n of nodes) { if (n !== owner && n.store.list().length > 0) { holder = n; break; } }
    net.setOffline(holder.peerId);

    let passes = 0;
    const online = nodes.filter((n) => n !== owner && net.isOnline(n.peerId));
    for (const n of online) n.startRepairLoop({ intervalMs: 25, jitter: 0.3, onPass: () => { passes++; } });
    await new Promise((r) => setTimeout(r, 800));
    for (const n of online) n.stopRepairLoop();

    t.ok(passes > 0, `the loop fired at least one pass on its own (passes=${passes})`);
    t.ok(await eventually(() => minHolders(nodes, net, put.blockIds) >= 2), "the loop restored redundancy with no manual call");
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
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0], recipient = nodes[1];
    const data = file(3200, 11);
    const put = await owner.put(data);
    // Owner seals K to the recipient's node key; recipient opens and reads.
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
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const data = file(3200, 13);
    const put = await owner.put(data);
    // Crypto-shred = discard K. A reader with the wrong key recovers nothing.
    const wrongK = owner.crypto.randomKey();
    let leaked = false;
    try { leaked = bytesEqual(await owner.get(put.root, wrongK), data); }
    catch { leaked = false; } // the index fails to decrypt under the wrong key
    t.ok(!leaked, "ciphertext on holders is permanent noise once K is gone");
    nodes.forEach((n) => n.close());
    net.close();
  }

  t.group("reciprocity: serving raises a holder's local standing (§13)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const put = await owner.put(file(3200, 17));
    await owner.get(put.root, put.key); // verification-fetches feed scoring
    let anyPositive = false;
    for (const n of nodes) {
      if (n === owner) continue;
      // Reputation lives in the installed reputation module the guest scores
      // through; the owner reads a holder's standing the same way (§13).
      if (await owner.score(n.identity.publicKey) > 0) anyPositive = true;
    }
    t.ok(anyPositive, "holders that served the owner gained positive standing");
    nodes.forEach((n) => n.close());
    net.close();
  }

  // The browser demos run k=1 on two or three holders — a shape the groups
  // above never use (all RS(2,2) on a full cohort). Cover the two ways it breaks:
  // a duplicate id leaking into blockIds, and a cohort smaller than n=k+m failing
  // the whole PUT.
  t.group("k=1 replication on a 2-holder cohort (RS(1,9) on an undersized cohort)");
  {
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 9, blockSize: 1024 };
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 3, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT }); // owner + 2 holders
    const owner = nodes[0];
    const data = file(6400, 23); // > 1 block → windowed, several chunks

    const put = await owner.put(data);

    // The returned set must name each placed id once: a duplicate would make a holder
    // probe read as storing more blocks than it does.
    const hexes = put.blockIds.map(toHex);
    t.eq(new Set(hexes).size, hexes.length, "PUT reports each placed block id once (no dup-id leak)");

    // has() must agree with list() on every holder — has reporting an id the
    // holder does not actually store would misreport redundancy.
    let consistent = true;
    for (const n of nodes.filter((x) => x !== owner)) {
      const held = new Set(n.store.list().map(toHex));
      for (const h of hexes) if (n.store.has(fromHex(h)) !== held.has(h)) consistent = false;
    }
    t.ok(consistent, "every holder's has(id) matches its store.list()");

    // Both holders have every block. A read that asks the best-scored holder for all of
    // them leaves the other's links idle, so count the ids each one was asked for.
    const holders = nodes.filter((x) => x !== owner);
    const asked = async (n) => { const s = (await n.stats()).get(MsgType.FETCH); return s ? (s.recvBytes - 4 * s.recv) / 32 : 0; };
    await Promise.all(holders.map(asked)); // clear — only the GET below is counted
    t.ok(bytesEqual(await owner.get(put.root, put.key), data), "GET round-trips on a 2-holder cohort");
    const [askedA, askedB] = await Promise.all(holders.map(asked));
    t.ok(Math.min(askedA, askedB) * 3 >= askedA + askedB,
      `a replicated file is read from both its holders (${askedA} and ${askedB} blocks asked)`);

    // What the demo user actually did: kill a holder, then read. k=1 means any one
    // surviving copy reconstructs the file.
    net.setOffline(nodes[1].peerId);
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
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 4, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT }); // owner + 3 holders < n=4
    const owner = nodes[0];
    const data = file(4800, 29);
    const put = await owner.put(data); // best-effort: places what the cohort takes, no throw
    t.ok(put.blockIds.length > 0, "PUT places across the 3 available holders instead of failing");
    t.ok(bytesEqual(await owner.get(put.root, put.key), data), "GET reconstructs from a sub-n placement");
    nodes.forEach((n) => n.close());
    net.close();
  }

  t.group("PUT on fewer linked holders than k fails naming that, not a timeout (§6)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 2, network: net, sodium, wasm, config: { k: 2, m: 2, blockSize: 1024 }, timeoutMs: TIMEOUT }); // owner + 1 holder < k=2
    let err = null;
    try { await nodes[0].put(file(4800, 31)); } catch (x) { err = x; }
    t.ok(err && /has 1 linked member\(s\) besides this node, and a chunk needs 2/.test(err.message), `the error names the shortfall (${err?.message})`);
    nodes.forEach((n) => n.close());
    net.close();
  }

  t.group("maxMessageBytes mismatch: a holder's smaller FETCH cap degrades, never fails (§18)");
  {
    // maxMessageBytes is per-node operator policy, so a cohort can diverge: this
    // owner sizes FETCH for 4 blocks/response (cap 4480), holders serve only
    // ~1 block/response (cap 1600). A block past the holder's cap comes back
    // FETCH_UNANSWERED (held, no room) — distinct from a genuine miss — and the
    // reader re-requests it (runFetchTasks), so the mismatch costs round trips, not data.
    const net = new LoopbackNetwork();
    const ownerCfg = { k: 2, m: 2, blockSize: 1024, maxMessageBytes: 4480 };
    const holderCfg = { ...ownerCfg, maxMessageBytes: 1600 };
    const mk = (cfg, tag) => bootStorageNode(inProcessStandUp, {
      sodium, bundleBlob: wasm.bundleBlob, identity: tag,
      suppressLinkLog: true, channels: net.view(toHex(tag.publicKey)), listen: [{ label: "tcp", host: "127.0.0.1", port: 0 }],
      config: cfg, timeoutMs: TIMEOUT,
    });
    const owner = await mk(ownerCfg, sodium.crypto_sign_keypair());
    const holders = [];
    for (let i = 0; i < 4; i++) holders.push(await mk(holderCfg, sodium.crypto_sign_keypair()));
    const nodes = [owner, ...holders];
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) await StorageNode.connect(nodes[i], nodes[j]);
    }
    await joinGroup(nodes);

    const data = file(4096, 41); // 4 blocks → 2 RS(2,2) chunks, block i of each on holder i
    const put = await owner.put(data);

    // Pin the scenario at the wire: a raw 2-id FETCH to a holder that stores both
    // must come back with the first block served (the progress guarantee) and the second
    // marked UNANSWERED (over the holder's 1600-byte cap, but held). If this ever stops
    // hitting the cap, the GET below no longer exercises the mismatch.
    let holder = null;
    for (const h of holders) { if (h.store.list().length >= 2) { holder = h; break; } }
    t.ok(!!holder, "a holder carries at least two blocks");
    const [idA, idB] = holder.store.list();
    const raw = await owner.request(holder.peerId, typed(MsgType.FETCH, encodeFetchBatchReq([idA, idB])));
    const served = decodeFetchBatchRes(raw);
    t.ok(served[0] !== null && bytesEqual(served[0], holder.store.get(idA).bytes), "the first present block is always served, even near the cap");
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
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 2, network: net, sodium, wasm, config: cfg, quota: 0, timeoutMs: TIMEOUT });
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
    // Conflating the two is expensive in the field: a
    // holder has no console, so the verdict byte is its only voice, and reporting a
    // broken backend as "quota" sends an operator to raise a budget that was never the
    // constraint. Here the budget is enormous and the write still fails.
    const net = new LoopbackNetwork();
    const writerId = sodium.crypto_sign_keypair();
    const holderId = sodium.crypto_sign_keypair();
    const mk = (id, standUp) => bootStorageNode(standUp, {
      sodium, bundleBlob: wasm.bundleBlob, identity: id,
      suppressLinkLog: true, channels: net.view(toHex(id.publicKey)), listen: [{ label: "tcp", host: "127.0.0.1", port: 0 }],
      config: { ...config, k: 1, m: 0 }, quota: 1 << 30, timeoutMs: TIMEOUT,
    });
    // A store that accepts reads and refuses the record write — a full disk, near
    // enough.
    const failing = memoryRawFiles();
    const write0 = failing.write.bind(failing);
    failing.write = (path, bytes) => {
      if (path.endsWith(".rec")) throw new Error("ENOSPC: no space left on device");
      return write0(path, bytes);
    };
    const writer = await mk(writerId, inProcessStandUp);
    const holder = await mk(holderId, (cfg) => inProcessHost(failing).standUp(cfg));
    try {
      await StorageNode.connect(writer, holder);
      await joinGroup([writer, holder]);
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
    // The envelope carries its own author pubkey, so a signature checked
    // against it alone proves nothing about WHO signed — any peer could mint a
    // fresh keypair and self-sign. Anchoring the author to a known peer is what
    // makes a forgery attributable (§13).
    const net = new LoopbackNetwork();
    const [a, b] = await createConnectedCohort({ suppressLinkLog: true, count: 2, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    try {
      const bytes = file(config.blockSize, 77);
      const bid = a.crypto.blockId(a.identity.publicKey, bytes);
      const desc = (id, sk) => signDescriptor(
        sodium, { group: "cohort", level: 0, k: 1, m: 0, blockSize: config.blockSize, tailBytes: config.blockSize, authTag: new Uint8Array(16), blockIds: [bid] },
        id.publicKey, id.privateKey,
      );

      // Signed by a real cohort peer (a, which b knows): admitted.
      const known = decodeMask(await a.request(b.peerId, typed(MsgType.STORE, encodeStoreBatch([{ blockId: bid, descriptor: desc(a.identity), bytes }]))));
      t.eq(known[0], VERDICT_ACCEPTED, "a descriptor signed by a peer the holder knows is admitted");

      // Byte-for-byte the same descriptor, signed under a FRESH keypair in the same
      // scope. The signature verifies perfectly; the author is a stranger.
      const stranger = newKey();
      const bytes2 = file(config.blockSize, 78);
      const bid2 = a.crypto.blockId(stranger.publicKey, bytes2);
      const forged = signDescriptor(
        sodium, { group: "cohort", level: 0, k: 1, m: 0, blockSize: config.blockSize, tailBytes: config.blockSize, authTag: new Uint8Array(16), blockIds: [bid2] },
        stranger.publicKey, stranger.privateKey,
      );
      const unknown = decodeMask(await a.request(b.peerId, typed(MsgType.STORE, encodeStoreBatch([{ blockId: bid2, descriptor: forged, bytes: bytes2 }]))));
      t.eq(unknown[0], VERDICT_GROUP, "a self-signed descriptor from a fresh keypair is declined — its author is in no group the holder lists");
      t.ok(!b.store.has(bid2), "nothing committed for the unanchored descriptor");
    } finally { [a, b].forEach((n) => n.close()); }
  }

  // ── §6/§10 a repeated id is a sibling of itself ────────────────────────────
  t.group("a holder declines a block it already holds, so a replica slot is not burned (§6)");
  {
    // With replication expressed as MULTIPLICITY, a k=1 chunk's m+1 listings are m+1
    // distinct peers. Silently overwriting an existing copy would fill a slot without
    // adding a holder — the chunk would look placed and be short a replica.
    const net = new LoopbackNetwork();
    const [a, b] = await createConnectedCohort({ suppressLinkLog: true, count: 2, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    try {
      const bytes = file(config.blockSize, 91);
      const bid = a.crypto.blockId(a.identity.publicKey, bytes);
      const env = signDescriptor(
        sodium, { group: "cohort", level: 0, k: 1, m: 2, blockSize: config.blockSize, tailBytes: config.blockSize, authTag: new Uint8Array(16), blockIds: [bid, bid, bid] },
        a.identity.publicKey, a.identity.privateKey,
      );
      const first = decodeMask(await a.request(b.peerId, typed(MsgType.STORE, encodeStoreBatch([{ blockId: bid, descriptor: env, bytes }]))));
      t.eq(first[0], VERDICT_ACCEPTED, "the first copy is admitted");
      const second = decodeMask(await a.request(b.peerId, typed(MsgType.STORE, encodeStoreBatch([{ blockId: bid, descriptor: env, bytes }]))));
      t.eq(second[0], VERDICT_SIBLING, "a second copy of the SAME id on the same holder is declined");
    } finally { [a, b].forEach((n) => n.close()); }
  }

  // ── §4.3 the index descent is checked, not assumed ────────────────────────
  t.group("GET rejects an index level that does not descend (§4.3, §7)");
  {
    // A reader is HANDED (root, K), so a hostile sharer can produce valid AEAD at
    // every level — nothing else stops a root at
    // level ℓ from naming a list also at level ℓ. Only the strict descent check does.
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 1, blockSize: 512 };
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 4, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    const [owner] = nodes;
    try {
      const K = owner.crypto.randomKey();
      const sign = (d) => signDescriptor(sodium, d, owner.identity.publicKey, owner.identity.privateKey);
      const at = (level, sealed, tailBytes) => {
        const id = owner.crypto.blockId(owner.identity.publicKey, sealed.ciphertext);
        return { id, ciphertext: sealed.ciphertext, env: sign({ group: "cohort", level, k: 1, m: 1, blockSize: cfg.blockSize, tailBytes, authTag: sealed.authTag, blockIds: [id, id] }) };
      };
      // Inner: a level-1 chunk. Outer: ANOTHER level-1 chunk whose plaintext is a list
      // naming the inner one. The walk therefore goes 1 → 1 and never descends. tailBytes
      // is set honestly to the list length — zero padding would be caught earlier, by
      // decodeDescriptorList refusing a zero-length entry.
      const inner = at(1, owner.crypto.encrypt(K, 1, 0, new Uint8Array(cfg.blockSize)), cfg.blockSize);
      const list = encodeDescriptorList([inner.env]);
      const outerPlain = new Uint8Array(cfg.blockSize);
      outerPlain.set(list);
      const outer = at(1, owner.crypto.encrypt(K, 1, 0, outerPlain), list.length);
      plantBlock(nodes[1].fs, toHex(outer.id), outer.ciphertext, outer.env);

      let err = null;
      try { await owner.get(outer.env, K); } catch (e) { err = e; }
      t.ok(err !== null, "a non-descending index is rejected rather than walked further");
      t.ok(err && /descend/.test(err.message), "the error names the failed descent");
    } finally { nodes.forEach((n) => n.close()); }
  }

  // ── §4.3 the index is a file, so it has no size ceiling ────────────────────
  t.group("a file whose index needs several levels still round-trips (§4.3)");
  {
    // The index is chunked like any file, so a bigger file only changes how many
    // levels the roll-up takes. Squeeze the geometry so this file needs a
    // genuinely multi-level index — a single root descriptor could never cover it.
    const net = new LoopbackNetwork();
    const cfg = { k: 2, m: 2, blockSize: 272 };            // one index chunk holds just 2 tagged descriptors
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 6, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    try {
      const data = file(cfg.k * cfg.blockSize * 9 - 77, 55); // 9 chunks → 9 → 5 → 3 → 2 → 1: four index levels
      const put = await nodes[0].put(data);
      t.eq(put.chunkCount, 9, "nine leaf chunks");
      t.ok(put.root.length === 32 + 64 + 13 + 1 + "cohort".length + 16 + 4 * 32, "the root is a signed descriptor envelope, not a 32-byte id");
      t.ok(parseSignedDescriptor(put.root).descriptor.level >= 2, "the roll-up needed more than one index level");
      t.ok(bytesEqual(await nodes[0].get(put.root, put.key), data), "a multi-level index round-trips");
      // Every block placed is exactly blockSize, index blocks included, so no block
      // grows with the file and nothing caps its size.
      let oversize = 0;
      for (const n of nodes) {
        for (const id of n.store.list()) {
          if (n.store.get(id).bytes.length !== cfg.blockSize) oversize++;
        }
      }
      t.eq(oversize, 0, "no block on the wire exceeds blockSize — the index has no size ceiling");
    } finally { nodes.forEach((n) => n.close()); }
  }

  t.group("a linked peer outside the roster is answered nothing, and the roster changes at runtime (§5.1)");
  {
    const net = new LoopbackNetwork();
    // Four linked nodes, three of them a group: a link alone admits nothing.
    const [a, b, c, stranger] = await createConnectedCohort({ suppressLinkLog: true, count: 4, network: net, sodium, wasm, config, timeoutMs: TIMEOUT,
      groups: (ids) => ({ cohort: ids.slice(0, 3) }) });
    const have = async () => (await stranger.request(b.peerId, typed(MsgType.HAVE, encodeHaveReq([new Uint8Array(32)])))).length;
    try {
      t.ok((await b.linkedPeers()).includes(stranger.peerId), "the stranger is linked");
      t.eq(await have(), 0, "a linked stranger's HAVE is answered with nothing");
      const put = await a.put(file(2048, 91));
      t.ok(bytesEqual(await a.get(put.root, put.key), file(2048, 91)), "members still store and read");
      t.eq(stranger.store.list().length, 0, "nothing was placed on the stranger");

      await b.setGroups({ cohort: [a.peerId, b.peerId, c.peerId, stranger.peerId] });
      t.eq(await have(), 1, "once b adds it to the group, b answers it");
      await b.setGroups({ cohort: [a.peerId, b.peerId, c.peerId] });
      t.eq(await have(), 0, "and once b drops it again, b goes quiet");
    } finally { [a, b, c, stranger].forEach((n) => n.close()); net.close(); }
  }

  t.group("a PUT stays inside its group, and goodwill earned in one group counts only there (§5.1, §13)");
  {
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 1, blockSize: 1024 };
    // Owner a is in both groups; b, c only in x; d, e only in y.
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 5, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT,
      groups: ([a, b, c, d, e]) => ({ x: [a, b, c], y: [a, d, e] }) });
    try {
      const [a, b, c, d, e] = nodes;
      let err = null;
      try { await a.put(file(1024, 92)); } catch (x) { err = x; }
      t.ok(err && /name a group/.test(err.message), "with two groups, a PUT must name one");
      const put = await a.put(file(4096, 93), { group: "x" });
      t.ok(b.store.list().length > 0 && c.store.list().length > 0, "the group's members hold the file");
      t.eq(d.store.list().length + e.store.list().length, 0, "no block landed outside the group");
      t.ok(bytesEqual(await a.get(put.root, put.key), file(4096, 93)), "the file reads back");
      t.ok(await a.score(b.identity.publicKey, "x") > 0, "serving the read earned b standing in x");
      t.eq(await a.score(b.identity.publicKey, "y"), 0, "and none in y");

      // A chunk naming a group the holder does not list it in is refused, whatever its signature.
      const bytes = file(1024, 94);
      const id = b.crypto.blockId(d.identity.publicKey, bytes);
      const env = signDescriptor(sodium, { group: "x", level: 0, k: 1, m: 0, blockSize: 1024, tailBytes: 1024, authTag: new Uint8Array(16), blockIds: [id] },
        d.identity.publicKey, d.identity.privateKey);
      const verdict = decodeMask(await d.request(b.peerId, typed(MsgType.STORE, encodeStoreBatch([{ blockId: id, descriptor: env, bytes }]))));
      t.eq(verdict[0], VERDICT_GROUP, "d may not store into x, a group b does not list it in");
    } finally { nodes.forEach((n) => n.close()); net.close(); }
  }

  // The distinct chunks a node holds a block of, told apart by descriptor signature.
  const chunksHeld = (node) => new Set(node.store.list().map((id) => toHex(node.store.get(id).descriptor.subarray(32, 96)))).size;

  t.group("a repair audit samples verification-fetches instead of fetching every block (§8, §9)");
  {
    const net = new LoopbackNetwork();
    const cfg = { k: 2, m: 6, blockSize: 1024 };            // n = 8: an audit sees 7 other holders per chunk
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 10, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    try {
      const put = await nodes[0].put(file(8192, 61));
      const holder = nodes.slice(1).sort((x, y) => chunksHeld(y) - chunksHeld(x))[0];
      const chunks = chunksHeld(holder);
      t.ok(chunks >= 2, `the holder holds blocks of several chunks (${chunks})`);
      t.eq(await holder.runRepair(), 0, "a healthy file needs no repair");
      await holder.stats();
      t.eq(await holder.runRepair(), 0, "nor on a second pass");
      const fetches = (await holder.stats()).get(MsgType.FETCH).sent;
      t.ok(fetches <= 2 * chunks, `once its peers are verified, a pass samples at most 2 per chunk (${fetches} FETCHes, ${chunks} chunks; a full audit is 7 per chunk)`);
      t.ok(bytesEqual(await nodes[0].get(put.root, put.key), new Uint8Array(file(8192, 61))), "the file still reads");
    } finally { nodes.forEach((n) => n.close()); net.close(); }
  }

  t.group("a holder that advertises a block it no longer serves is caught by the sample and routed around (§8)");
  {
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 1, blockSize: 1024 };
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 5, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    try {
      const put = await nodes[0].put(file(1024, 67));
      const id = put.blockIds[0];
      const [repairer, liar] = nodes.filter((n) => n !== nodes[0] && n.store.has(id));
      t.eq(await repairer.runRepair(), 0, "both copies verify on the first pass");
      // Gone from disk, but still in the holder's index, so it keeps answering HAVE yes.
      liar.fs.delete(toHex(id) + ".rec");
      t.ok(!liar.store.has(id), "the liar no longer holds the block");
      const replaced = await repairer.runRepair();
      t.ok(replaced >= 1, `the freshly verified liar was re-sampled, failed, and the copy re-placed (placed=${replaced})`);
      const fresh = () => nodes.filter((n) => n !== repairer && n !== liar && n.store.has(id));
      await eventually(() => fresh().length > 0);
      t.eq(fresh().length, 1, "the restored copy is on a peer other than the liar, which rebuilt it itself");
    } finally { nodes.forEach((n) => n.close()); net.close(); }
  }

  t.group("a copy past its block's target drops to cache, and is committed again when needed (§14)");
  {
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 1, blockSize: 1024 };            // target: 2 copies
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 5, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    try {
      const owner = nodes[0];
      const put = await owner.put(file(1024, 71));
      const id = put.blockIds[0];
      const first = nodes.filter((n) => n !== owner && n.store.has(id));
      // A third copy, as two repairers healing at once would leave.
      const extra = nodes.find((n) => n !== owner && !n.store.has(id));
      const rec = first[0].store.get(id);
      const verdict = decodeMask(await owner.request(extra.peerId, typed(MsgType.STORE, encodeStoreBatch([{ blockId: id, descriptor: rec.descriptor, bytes: rec.bytes }]))));
      t.eq(verdict[0], VERDICT_ACCEPTED, "a third copy lands");
      const holders = [...first, extra];
      let replaced = 0;
      for (const n of holders) replaced += await n.runRepair();
      t.eq(replaced, 0, "an over-replicated chunk needs no repair");
      const cached = holders.filter((n) => n.store.tier(id) === TIER_CACHE);
      const last = [...holders].sort((a, b) => (a.peerId < b.peerId ? -1 : 1))[2];
      t.eq(cached.length, 1, "exactly one of the three copies stepped down to cache");
      t.ok(cached[0] === last, "the one that sorts past the target, as every holder computes it");

      net.setOffline(holders.find((n) => n !== last).peerId);
      replaced = 0;
      for (const n of holders) if (net.isOnline(n.peerId)) replaced += await n.runRepair();
      t.eq(replaced, 0, "two copies remain: still healthy");
      t.eq(last.store.tier(id), TIER_COMMITTED, "the cached copy is committed again once the chunk needs it");
    } finally { nodes.forEach((n) => n.close()); net.close(); }
  }

  t.group("over quota, a holder releases a commitment only once another member has repaired a copy (§14)");
  {
    const net = new LoopbackNetwork();
    // Each planted block costs 1168 (1000 + 164 + 4): two overrun a 1500-byte quota.
    const [a, b, c] = await createConnectedCohort({ suppressLinkLog: true, count: 3, network: net, sodium, wasm, quota: 1500, config: { newcomerShare: 1 }, timeoutMs: TIMEOUT });
    try {
      const ids = [];
      for (const seed of [81, 82]) {
        const bytes = file(1000, seed);
        const id = b.crypto.blockId(a.identity.publicKey, bytes);
        const env = signDescriptor(sodium, { group: "cohort", level: 0, k: 1, m: 0, blockSize: 1000, tailBytes: 1000, authTag: new Uint8Array(16), blockIds: [id] },
          a.identity.publicKey, a.identity.privateKey);
        plantBlock(b.fs, toHex(id), bytes, env);
        ids.push(id);
      }
      t.ok(b.store.usedBytes() > 1500, `the holder starts over quota (${b.store.usedBytes()} B)`);
      // The first pass asks a member to repair the copy it would shed; a later one drops it
      // once that copy has landed.
      await b.runRepair();
      await eventually(() => ids.some((id) => a.store.has(id) || c.store.has(id)));
      await b.runRepair();
      t.ok(b.store.usedBytes() <= 1500, `repair passes bring it back under quota (${b.store.usedBytes()} B)`);
      const released = ids.filter((id) => !b.store.has(id));
      t.eq(released.length, 1, "one commitment released, no more than needed");
      t.ok(released.length === 1 && (a.store.has(released[0]) || c.store.has(released[0])), "the released block lives on another peer");
    } finally { a.close(); b.close(); c.close(); net.close(); }
  }
}

// Does `node` hold any of `ids`?
function storeHoldsAny(node, ids) {
  for (const id of ids) if (node.store.has(id)) return true;
  return false;
}

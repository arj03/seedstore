// End-to-end multi-node tests over the loopback network: a storage node booted
// on the real seedkernel, then PUT → place → GET → repair across simulated
// peers (README Part I). These are the integration tests that exercise the
// whole onion together.

import {
  LoopbackNetwork, loadWasmBytes, loadSodium, createConnectedCohort,
} from "../build/host/node.js";
import { parseSignedDescriptor } from "../build/host/manifest.js";
import { toHex, bytesEqual } from "../build/host/util.js";

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

async function liveCount(observer, blockIds) {
  return observer.cohort.liveBlockCount(blockIds, true);
}

export async function run(t) {
  const sodium = await loadSodium();
  const wasm = await loadWasmBytes();
  const config = { k: 2, m: 2, blockSize: 64 };

  t.group("node boots on seedkernel: bridges + pure handlers installed (§19)");
  {
    const net = new LoopbackNetwork();
    const [node] = await createConnectedCohort({ count: 1, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    t.ok(node.handlersInstalled(), "codec + reputation installed as kernel handlers");
    t.eq(node.codec.info().version, 1, "host-owned codec is live");
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

    const before = await liveCount(owner, ids);
    t.eq(before, 4, "all n=4 blocks live after PUT");

    // Find two online peers holding a block of this chunk and take them offline
    // (Lost, §8).
    const holders = nodes.filter((n) => n !== owner && ids.some((id) => n.store.has(id)));
    net.setOnline(holders[0].peerId, false);
    net.setOnline(holders[1].peerId, false);
    const degraded = await liveCount(owner, ids);
    t.ok(degraded <= 2, `redundancy dropped after losing two holders (live=${degraded})`);

    // Any online block-holder runs the repair loop; it reconstructs the missing
    // blocks and places them on fresh peers (idempotent, §9).
    const online = nodes.filter((n) => n !== owner && net.isOnline(n.peerId));
    for (const n of online) await n.runRepair();

    const healed = await liveCount(owner, ids);
    t.ok(healed >= config.k + Math.ceil(config.m / 2), `repair lifted redundancy back above low-water (live=${healed})`);
    const got = await owner.get(put.manifestId, put.key);
    t.ok(bytesEqual(got, data), "file still reads after loss + repair");
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
    const now = owner.now();
    let anyPositive = false;
    for (const n of nodes) {
      if (n === owner) continue;
      if (owner.reputation.score(n.identity.publicKey, now) > 0) anyPositive = true;
    }
    t.ok(anyPositive, "holders that served the owner gained positive standing");
    nodes.forEach((n) => n.close());
  }
}

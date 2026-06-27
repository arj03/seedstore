// End-to-end multi-node tests over the loopback network: a storage node booted
// on the real seedkernel, then PUT → place → GET → repair across simulated
// peers (README Part I). These are the integration tests that exercise the
// whole onion together.

import {
  LoopbackNetwork, loadWasmBytes, loadSodium, createConnectedCohort,
} from "../build/host/node.js";
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

  t.group("node boots on seedkernel: bridges + pure handlers installed (§19)");
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
  // matters for a degenerate RS(1,1) block (one distinct id per chunk, replicated),
  // where the distinct-*id* live count (liveCount) maxes out at 1 and hides the loss.
  const minHolders = (nodes, net, ids) =>
    Math.min(...ids.map((id) => nodes.filter((n) => net.isOnline(n.peerId) && n.store.has(id)).length));

  t.group("self-healing re-replicates a degenerate RS(1,1) file — chunks + manifest (§9)");
  {
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 1, blockSize: 64 };            // the p2p.html demo config
    const nodes = await createConnectedCohort({ count: 5, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    // Overriding k/m must re-derive the durability fields, not keep the (2,2)
    // defaults — an unreachable lowWater > n would make repair never settle.
    t.eq(owner.config.lowWater, 2, "lowWater re-derived for RS(1,1) (k + ceil(m/2))");
    t.eq(owner.config.replicas, 2, "replicas re-derived for RS(1,1) (m + 1)");

    const data = file(256, 11);                            // 4 blocks → 4 RS(1,1) chunks
    const put = await owner.put(data);
    t.ok(!put.replicated, "a multi-block k=1 file takes the coded path (healCoded), not replication");
    // put.blockIds = each chunk's (single, parity≡data) block + the manifest.
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

  t.group("repair settles on a high-redundancy degenerate config (RS(1,4)) (§9)");
  {
    // RS(1,4): n=5, replicas=5, lowWater=3. The lone id (parity≡data) lives on 5
    // distinct holders. Repair must read the *full* live-holder set, never a
    // capped sample: a sample of, say, 2 reads redundancy 2 < lowWater 3 and would
    // re-place on every pass, never settling. A freshly-PUT, fully-healthy file
    // must therefore be a strict no-op for repair.
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 4, blockSize: 64 };
    const nodes = await createConnectedCohort({ count: 7, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT }); // owner + 6 holders >= n=5
    const owner = nodes[0];
    t.eq(owner.config.replicas, 5, "replicas re-derived for RS(1,4) (m + 1)");
    const data = file(256, 41);                            // 4 blocks → coded path
    const put = await owner.put(data);
    t.ok(!put.replicated, "multi-block k=1 file takes the coded path");

    let replaced = 0;
    for (const n of nodes.filter((x) => x !== owner)) replaced += await n.runRepair();
    t.eq(replaced, 0, "repair places nothing on an already-healthy file (reads the full holder set, §9)");
    t.ok(bytesEqual(await owner.get(put.manifestId, put.key), data), "file still reads after the repair pass");
    nodes.forEach((n) => n.close());
  }

  t.group("startRepairLoop runs repair on a jittered interval, then settles (§9)");
  {
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 1, blockSize: 64 };
    const nodes = await createConnectedCohort({ count: 5, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const put = await owner.put(file(256, 13));            // multi-block → coded path

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

  // The browser demos run RS(1,·) on two or three holders — a shape the groups
  // above never used (they are all RS(2,2) on a full cohort). That blind spot is
  // why two real bugs shipped: a k=1 parity block is byte-identical to the lone
  // data block, so its id repeated in the returned set (the "13/13" holder probe),
  // and a cohort smaller than n=k+m used to fail the whole PUT. Cover both.
  t.group("degenerate k=1 on a 2-holder cohort (RS(1,9) on an undersized cohort)");
  {
    const net = new LoopbackNetwork();
    const cfg = { k: 1, m: 9, blockSize: 64 };
    const nodes = await createConnectedCohort({ count: 3, network: net, sodium, wasm, config: cfg, timeoutMs: TIMEOUT }); // owner + 2 holders
    const owner = nodes[0];
    const data = file(400, 23); // > 1 block → RS path, several chunks

    const put = await owner.put(data);
    t.ok(!put.replicated, "k=1 multi-block file takes the RS path");

    // The returned set must name each placed id once: the 13/13 probe was a
    // duplicate id leaking into blockIds (parity≡data), not the store lying.
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
}

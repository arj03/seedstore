// The real Tier-2 port (BUN.md §2.1): the storage orchestration — PUT, GET, and
// repair — driven *inside* the zero-authority QuickJS realm against a real cohort
// of nodes on the loopback network. Where storage.test.mjs exercises the same
// paths with the host-side Coordinator/Repair classes, this proves the identical
// behaviour when the orchestration policy runs confined and reaches every
// capability only through the single host.call seam (host/tier2-coordinator.ts).
//
// This is the end-to-end answer to "can seedstore's trust model actually run on
// Bun": the cap-rich coordinator is not trusted host code here, it is guest JS in
// a sandbox that cannot name fs/net/Bun/process — yet a file round-trips, survives
// holder loss, and self-heals, byte-for-byte compatible with the reference path.
//
//   node tests/tier2-port.test.mjs
//   bun  tests/tier2-port.test.mjs

import {
  LoopbackNetwork, loadWasmBytes, loadSodium, createConnectedCohort, Tier2Coordinator,
} from "../build/host/node.js";
import { parseSignedDescriptor } from "../build/host/manifest.js";
import { toHex, bytesEqual } from "../build/host/util.js";
import { makeT } from "./harness.mjs";

const TIMEOUT = 40; // ms — snappy offline-peer timeouts in tests

function file(n, seed = 1) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + seed * 7) & 255;
  return out;
}

// The block-ids of each distinct chunk, scanned from holders' stores (every
// holder carries the chunk's signed descriptor, §4.3).
function chunkBlockIds(nodes) {
  const seen = new Map();
  for (const node of nodes) {
    for (const id of node.store.list()) {
      const sb = node.store.get(id);
      if (!sb || !sb.descriptor) continue;
      const key = toHex(node.crypto.hash(sb.descriptor));
      if (!seen.has(key)) seen.set(key, parseSignedDescriptor(sb.descriptor).descriptor.blockIds);
    }
  }
  return [...seen.values()];
}

export async function run(t) {
  const sodium = await loadSodium();
  const wasm = await loadWasmBytes();
  const config = { k: 2, m: 2, blockSize: 64 };

  t.group("tier2: PUT → GET round trip orchestrated inside the realm (RS, §6/§7)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const t2 = new Tier2Coordinator(owner);
    const data = file(200); // 4 blocks → 2 RS chunks

    const put = await t2.put(data);
    t.ok(!put.replicated, "a multi-block file takes the RS path");
    t.eq(put.chunkCount, 2, "200 bytes / (k=2 × 64) → 2 chunks");
    t.eq(put.key.length, 32, "the realm returned the per-file content key K");

    const got = await t2.get(put.manifestId, put.key);
    t.ok(bytesEqual(got, data), "GET reconstructs the original file from inside the sandbox");

    // The confined orchestration really placed blocks on distinct peers, not self.
    const holders = nodes.filter((n) => n !== owner && n.store.list().length > 0);
    t.ok(holders.length >= 4, "the guest placed blocks across several distinct peers");
    t.eq(owner.store.list().length, 0, "owner holds no blocks — durability leans on the cohort");

    t2.dispose();
    nodes.forEach((n) => n.close());
  }

  t.group("tier2: small file replication path (§4.1)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const t2 = new Tier2Coordinator(owner);
    const data = file(40, 9); // < 1 block → replicated, not coded

    const put = await t2.put(data);
    t.ok(put.replicated, "a sub-chunk file is replicated, not RS-coded");
    const got = await t2.get(put.manifestId, put.key);
    t.ok(bytesEqual(got, data), "replicated small file reads back through the realm");

    t2.dispose();
    nodes.forEach((n) => n.close());
  }

  t.group("tier2: cross-path parity — Tier-2 and host-side coordinator are wire-compatible");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const t2 = new Tier2Coordinator(owner);

    // Written confined, read by the trusted reference path.
    const a = file(300, 21);
    const putT2 = await t2.put(a);
    const gotHost = await owner.get(putT2.manifestId, putT2.key);
    t.ok(bytesEqual(gotHost, a), "a file PUT inside the realm reads back via the host-side Coordinator");

    // Written by the reference path, read confined.
    const b = file(260, 22);
    const putHost = await owner.put(b);
    const gotT2 = await t2.get(putHost.manifestId, putHost.key);
    t.ok(bytesEqual(gotT2, b), "a file PUT host-side reads back inside the realm");

    t2.dispose();
    nodes.forEach((n) => n.close());
  }

  t.group("tier2: offline tolerance — any k of n still reads from the sandbox (§7/§8)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const t2 = new Tier2Coordinator(owner);
    const data = file(200, 3);
    const put = await t2.put(data);

    // Take two holders offline (≤ m of any chunk; blocks are on distinct peers).
    net.setOnline(nodes[1].peerId, false);
    net.setOnline(nodes[2].peerId, false);
    const got = await t2.get(put.manifestId, put.key);
    t.ok(bytesEqual(got, data), "read succeeds with two holders offline");

    t2.dispose();
    nodes.forEach((n) => n.close());
  }

  t.group("tier2: self-healing — repair orchestrated in the realm restores redundancy (§9)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 8, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const t2 = new Tier2Coordinator(owner);
    const data = file(128, 5); // 2 blocks → 1 RS chunk (n=4)
    const put = await t2.put(data);

    const ids = chunkBlockIds(nodes.filter((n) => n !== owner))[0];
    t.ok(ids && ids.length === 4, "found the n=4 chunk descriptor among holders");
    const before = await owner.cohort.liveBlockCount(ids, true);
    t.eq(before, 4, "all n=4 blocks live after PUT");

    // Lose two block-holders of this chunk (Lost, §8).
    const holders = nodes.filter((n) => n !== owner && ids.some((id) => n.store.has(id)));
    net.setOnline(holders[0].peerId, false);
    net.setOnline(holders[1].peerId, false);
    const degraded = await owner.cohort.liveBlockCount(ids, true);
    t.ok(degraded <= 2, `redundancy dropped after losing two holders (live=${degraded})`);

    // Every online block-holder runs the repair loop — confined in its own realm,
    // driven sequentially so the realms never overlap host calls (§2.1 caveat).
    const online = nodes.filter((n) => n !== owner && net.isOnline(n.peerId));
    for (const n of online) {
      const r = new Tier2Coordinator(n);
      await r.repair();
      r.dispose();
    }

    const healed = await owner.cohort.liveBlockCount(ids, true);
    t.ok(healed >= config.k + Math.ceil(config.m / 2), `repair lifted redundancy back above low-water (live=${healed})`);
    const got = await t2.get(put.manifestId, put.key);
    t.ok(bytesEqual(got, data), "file still reads after loss + repair, all from inside sandboxes");

    t2.dispose();
    nodes.forEach((n) => n.close());
  }

  t.group("tier2: crypto-shredding — without K the sandbox recovers nothing (§11)");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config, timeoutMs: TIMEOUT });
    const owner = nodes[0];
    const t2 = new Tier2Coordinator(owner);
    const data = file(200, 13);
    const put = await t2.put(data);
    const wrongK = owner.crypto.randomKey();
    let leaked = false;
    try { leaked = bytesEqual(await t2.get(put.manifestId, wrongK), data); }
    catch { leaked = false; } // manifest fails to parse under the wrong key
    t.ok(!leaked, "ciphertext on holders is permanent noise once K is gone");
    t2.dispose();
    nodes.forEach((n) => n.close());
  }
}

// Allow running this module directly (node/bun tests/tier2-port.test.mjs).
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("tier2-port.test.mjs")) {
  const t = makeT();
  run(t).then(() => process.exit(t.summary() > 0 ? 1 : 0));
}

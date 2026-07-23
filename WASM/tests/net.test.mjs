// Networking + filesystem integration (README §16, §12). Exercises the real
// fabric that replaces the loopback:
//   - FsBlobView reads the durable store.local layout back, across reopen
//   - a full cohort over real TCP sockets, blocks landing on holders' disks
//   - a browser-like node reaching a server node over a real WebSocket
//
// The transport's own behaviour — RFC 6455 framing and channel identity pinning
// — now lives in seedkernel (the `./ws` and `./net-node` exports) and is tested
// there. This file keeps only the storage-level integration on top of it.

import { mkdtempSync, rmSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadSodium, loadWasmBytes } from "../build/host/node.js";
import { StorageNode } from "../build/host/storage-node.js";
import { NodeNetwork } from "seedkernel-wasm/net-node";
import { FsBlobView } from "../build/host/store-view.js";
import { NodeFs } from "seedkernel-wasm/fs-node";
// `bytesCompare` is a transport helper from the seedkernel `./net` barrel, used
// by the cohort below to canonicalise dial direction (lower pubkey dials higher).
import { bytesCompare } from "seedkernel-wasm/net";
import {
  MsgType, encodeHaveReq, decodeMask, encodeStoreBatch, encodeFetchBatchReq, decodeFetchBatchRes,
  VERDICT_ACCEPTED, VERDICT_DECLINED,
} from "../build/host/protocol.js";
import { signDescriptor } from "../build/host/manifest.js";
import { toHex, fromHex, bytesEqual } from "../build/host/util.js";
import { plantBlock } from "./helpers.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const enc = new TextEncoder();
const SEEDSTORE_PROTO = enc.encode("seedstore");

function file(n, seed = 1) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + seed * 7) & 255;
  return out;
}

function newKey(sodium) {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

// Stand up `count` storage nodes on real TCP loopback sockets, each with its own
// on-disk store.local directory, fully connected. Dial direction is canonical (lower pubkey
// dials higher) so no pair double-connects.
async function tcpCohort({ count, sodium, wasm, config, baseDir }) {
  const ids = Array.from({ length: count }, () => newKey(sodium));
  const nets = ids.map((id) => new NodeNetwork({ identity: id, sodium, listen: { host: "127.0.0.1", port: 0 } }));
  await Promise.all(nets.map((n) => n.start()));

  for (let i = 0; i < count; i++) {
    for (let j = 0; j < count; j++) {
      if (i === j) continue;
      if (bytesCompare(ids[i].publicKey, ids[j].publicKey) < 0) {
        nets[i].addPeerAddr(toHex(ids[j].publicKey), { host: "127.0.0.1", port: nets[j].port, transport: "tcp" });
      }
    }
  }

  const dirs = [];
  const nodes = [];
  for (let i = 0; i < count; i++) {
    const dir = join(baseDir, `n${i}`);
    dirs.push(dir);
    // Give the node a disk-backed fs; its default store view reads that same fs, so
    // what the confined guest holder writes via fs.* lands on disk and node.store
    // reflects it (the view must read the fs the guest serves).
    nodes.push(await StorageNode.create({
      network: nets[i], sodium, ...wasm, identity: ids[i], fs: new NodeFs(dir), config, timeoutMs: 3000,
    }));
  }
  for (let i = 0; i < count; i++) for (let j = i + 1; j < count; j++) StorageNode.connect(nodes[i], nodes[j]);

  await Promise.all(nets.map((n) => n.ready(8000)));
  await sleep(100); // let inbound links finish promoting
  return { nodes, nets, ids, dirs };
}

export async function run(t) {
  const sodium = await loadSodium();
  const wasm = await loadWasmBytes();

  // ── FsBlobView ─────────────────────────────────────────────────────────────
  // A pure READ view of the durable store.local layout (§12): the write half —
  // admission, the §14 quota, the <hex>.blk/.dsc writes — belongs to the confined
  // guest holder alone (protocol.test.mjs drives it over the real wire). So this
  // writes the layout the way the guest does, through `fs.*`, and checks the view
  // reads it back.
  t.group("FsBlobView: reading back the durable store.local layout (§12)");
  {
    const dir = mkdtempSync(join(tmpdir(), "seedstore-fs-"));
    try {
      const fs = new NodeFs(dir);
      const view = new FsBlobView(fs);
      const bytes = file(64, 2);
      const id = sodium.crypto_generichash(32, bytes);
      const desc = new Uint8Array([9, 8, 7, 6]);

      t.ok(!view.has(id), "absent before anything is written");
      t.eq(view.usedBytes(), 0, "used starts at zero");

      plantBlock(fs, toHex(id), bytes, desc);
      t.ok(view.has(id), "present once the block is on the backend");
      const got = view.get(id);
      t.ok(got && bytesEqual(got.bytes, bytes), "get returns the bytes");
      t.ok(got && got.descriptor && bytesEqual(got.descriptor, desc), "descriptor read from the sibling .dsc");
      t.eq(view.usedBytes(), bytes.length + desc.length, "used counts ciphertext + descriptor — what the holder charges (§14)");
      t.eq(view.list().length, 1, "list sees the one block");

      // The view holds no index of its own, so it sees writes it did not make —
      // which is the point: on a live node the guest is the one writing.
      const bytes2 = file(32, 5);
      const id2 = sodium.crypto_generichash(32, bytes2);
      plantBlock(fs, toHex(id2), bytes2, null);
      t.eq(view.list().length, 2, "a write made behind the view's back still shows up");
      t.eq(view.get(id2).descriptor, null, "a bare block reads back with a null descriptor");

      // Durability: a fresh view over the same directory sees the same blocks.
      const reopened = new FsBlobView(new NodeFs(dir));
      t.ok(reopened.has(id), "reopened view still has the block");
      t.eq(reopened.usedBytes(), bytes.length + desc.length + bytes2.length, "reopened used is correct (blks + dscs)");
      t.ok(bytesEqual(reopened.get(id).bytes, bytes), "reopened get returns the bytes");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  // ── full cohort over real TCP, blocks on disk ──────────────────────────────
  t.group("PUT → GET across a cohort over real TCP, blocks persisted to disk");
  {
    const baseDir = mkdtempSync(join(tmpdir(), "seedstore-tcp-"));
    const { nodes, nets } = await tcpCohort({
      count: 6, sodium, wasm, config: { k: 2, m: 2, blockSize: 64 }, baseDir,
    });
    try {
      const owner = nodes[0];
      const data = file(200); // 4 blocks → 2 RS chunks
      const put = await owner.put(data);
      t.ok(!put.replicated, "a multi-block file takes the RS path");
      t.eq(put.chunkCount, 2, "200 bytes / (k=2 × 64) → 2 chunks");

      const got = await owner.get(put.manifestId, put.key);
      t.ok(bytesEqual(got, data), "GET reconstructs the file over the wire");

      const holders = nodes.filter((n) => n !== owner && n.store.list().length > 0);
      t.ok(holders.length >= 4, "blocks placed across several distinct peers");
      t.eq(owner.store.list().length, 0, "owner holds no blocks");

      t.ok(holders[0].store.list().length > 0, "a holder kept at least one block");
      t.ok(nets.some((n) => n.framesDelivered > 0), "frames actually crossed sockets");
    } finally {
      nodes.forEach((n) => n.close());
      nets.forEach((n) => n.close());
      rmSync(baseDir, { recursive: true, force: true });
    }
  }

  // ── disk persistence of a holder, isolated and explicit ────────────────────
  t.group("a holder's blocks survive a store reopen (real files on disk)");
  {
    const baseDir = mkdtempSync(join(tmpdir(), "seedstore-persist-"));
    const { nodes, nets, dirs } = await tcpCohort({
      count: 6, sodium, wasm, config: { k: 2, m: 2, blockSize: 64 }, baseDir,
    });
    try {
      const owner = nodes[0];
      const put = await owner.put(file(256, 7));
      t.ok(put.chunkCount >= 1, "file placed");

      // Find a holder index with blocks and reopen *its* directory cold.
      let holderIdx = -1;
      for (let i = 1; i < nodes.length; i++) if (nodes[i].store.list().length > 0) { holderIdx = i; break; }
      t.ok(holderIdx > 0, "located a holder with blocks");
      const idsBefore = nodes[holderIdx].store.list().map(toHex).sort();
      const cold = new FsBlobView(new NodeFs(dirs[holderIdx]));
      const idsAfter = cold.list().map(toHex).sort();
      t.eq(idsAfter.join(","), idsBefore.join(","), "cold reopen sees exactly the same block ids");
      const onDisk = readdirSync(dirs[holderIdx]).filter((f) => f.endsWith(".blk"));
      t.eq(onDisk.length, idsBefore.length, "one .blk file per held block on disk");
    } finally {
      nodes.forEach((n) => n.close());
      nets.forEach((n) => n.close());
      rmSync(baseDir, { recursive: true, force: true });
    }
  }

  // ── browser ↔ node over a real WebSocket ───────────────────────────────────
  t.group("control plane round-trips over a real WebSocket (browser ↔ node, §16)");
  {
    const idS = newKey(sodium), idB = newKey(sodium);
    const netS = new NodeNetwork({ identity: idS, sodium, listen: { host: "127.0.0.1", port: 0 }, wsListen: { host: "127.0.0.1", port: 0 } });
    await netS.start();
    const netB = new NodeNetwork({ identity: idB, sodium }); // browser-like: dials out only
    netB.addPeerAddr(toHex(idS.publicKey), { host: "127.0.0.1", port: netS.wsPort, transport: "ws" });

    // Default store = FsBlobView over each node's (in-RAM) fs, so S.store reflects
    // what the confined guest holder writes via fs.* when B stores to it.
    const S = await StorageNode.create({ network: netS, sodium, ...wasm, identity: idS, timeoutMs: 3000 });
    const B = await StorageNode.create({ network: netB, sodium, ...wasm, identity: idB, timeoutMs: 3000 });
    StorageNode.connect(S, B);
    await netB.ready(8000);
    await sleep(50);

    try {
      const bytes = file(64, 21);
      const bid = S.crypto.hash(bytes);

      const have0 = await B.transport.request(S.peerId, SEEDSTORE_PROTO, MsgType.HAVE, encodeHaveReq([bid]));
      t.eq(decodeMask(have0)[0], VERDICT_DECLINED, "HAVE → false before the block exists (over ws)");

      // The block travels with its author-signed chunk descriptor (§4.3) — the holder
      // verifies it before admitting, here as on any other transport. Both nodes load the
      // same bundle, so they share one signing scope.
      const desc = signDescriptor(sodium, { k: 1, m: 0, blockSize: bytes.length, blockIds: [bid] }, idB.publicKey, idB.privateKey, S.signScope);

      const stored = decodeMask(await B.transport.request(S.peerId, SEEDSTORE_PROTO, MsgType.STORE, encodeStoreBatch([{ blockId: bid, descriptor: desc, bytes }])));
      t.eq(stored[0], VERDICT_ACCEPTED, "STORE acknowledged over ws");
      t.ok(S.store.has(bid), "server now holds the block");

      const have1 = await B.transport.request(S.peerId, SEEDSTORE_PROTO, MsgType.HAVE, encodeHaveReq([bid]));
      t.eq(decodeMask(have1)[0], VERDICT_ACCEPTED, "HAVE → true after STORE (over ws)");

      const fetched = await B.transport.request(S.peerId, SEEDSTORE_PROTO, MsgType.FETCH, encodeFetchBatchReq([bid]));
      const back = decodeFetchBatchRes(fetched)[0];
      t.ok(back && bytesEqual(back, bytes), "FETCH returns the bytes over ws");
      t.ok(netS.framesDelivered > 0, "server received frames over the websocket");
    } finally {
      S.close(); B.close();
      netS.close(); netB.close();
    }
  }

}

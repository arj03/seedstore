// Networking + filesystem integration (README §16, §12). Exercises the real
// fabric that replaces LoopbackNetwork/MemoryBlobStore:
//   - FsBlobStore round-trips and persists across reopen
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
import { WebRtcDirectNetwork, makeCertKeys } from "seedkernel-wasm/webrtc-direct";
import { FsBlobStore } from "../build/host/store-fs.js";
import { NodeFs } from "seedkernel-wasm/fs-node";
import { MemoryBlobStore } from "../build/host/store-local.js";
// `bytesCompare` is a transport helper from the seedkernel `./net` barrel, used
// by the cohort below to canonicalise dial direction (lower pubkey dials higher).
import { bytesCompare } from "seedkernel-wasm/net";
import {
  MsgType, encodeHaveReq, decodeHaveRes, encodeStore, encodeFetchReq, decodeFetchRes,
} from "../build/host/protocol.js";
import { toHex, fromHex, bytesEqual } from "../build/host/util.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
// on-disk FsBlobStore, fully connected. Dial direction is canonical (lower pubkey
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
    const store = new FsBlobStore(new NodeFs(dir), 64 * 1024 * 1024);
    nodes.push(await StorageNode.create({
      network: nets[i], sodium, ...wasm, identity: ids[i], store, config, timeoutMs: 3000,
    }));
  }
  for (let i = 0; i < count; i++) for (let j = i + 1; j < count; j++) StorageNode.connect(nodes[i], nodes[j]);

  await Promise.all(nets.map((n) => n.ready(8000)));
  await sleep(100); // let inbound links finish promoting
  return { nodes, nets, ids, dirs };
}

// Stand up an owner + `holderCount` holders whose fabric is relay-less
// WebRTC-Direct (no signaling relay in the path). PUT/GET is coordinated entirely
// by the owner — it offers blocks to, and fetches them from, the holders — so a
// star is the minimal topology: the owner dials each holder's dial token, and the
// link is bidirectional, so each holder can answer back. This is the storage-level
// proof that a console `serveDirect` node is a first-class storage peer, reachable
// by a static token, not just an echo pipe (the Transport-level proof lives in
// seedkernel's testWebRtcDirectNetwork).
async function directStar({ holderCount, sodium, wasm, config, baseDir }) {
  const ownerKp = newKey(sodium);
  const ownerHex = toHex(ownerKp.publicKey);
  const holderKps = Array.from({ length: holderCount }, () => newKey(sodium));

  // Each holder listens with its own pinned DTLS cert (its certhash rides the
  // token it publishes); the owner dials out only, so it needs no cert.
  const holderCerts = await Promise.all(holderKps.map(() => makeCertKeys()));
  const holderNets = holderKps.map((kp, i) =>
    new WebRtcDirectNetwork({ identity: kp, sodium, keys: holderCerts[i], listen: { host: "127.0.0.1" } }));
  const ownerNet = new WebRtcDirectNetwork({ identity: ownerKp, sodium });

  await Promise.all(holderNets.map((n) => n.listen()));
  const tokens = holderNets.map((n) => n.token("127.0.0.1"));
  await Promise.all(tokens.map((tok) => ownerNet.dial(tok)));

  // The dial resolves on the owner's side of the in-channel AUTH; wait for each
  // holder's reverse link to promote too, so it can answer the owner's requests.
  const t0 = Date.now();
  while (holderNets.some((n) => !n.linkedPeers().includes(ownerHex)) && Date.now() - t0 < 5000) await sleep(50);

  const dirs = [];
  const mk = async (net, kp, label) => {
    const dir = join(baseDir, label);
    dirs.push(dir);
    const store = new FsBlobStore(new NodeFs(dir), 64 * 1024 * 1024);
    return StorageNode.create({ network: net, sodium, ...wasm, identity: kp, store, config, timeoutMs: 3000 });
  };
  const owner = await mk(ownerNet, ownerKp, "owner");
  const holders = [];
  for (let i = 0; i < holderCount; i++) holders.push(await mk(holderNets[i], holderKps[i], `h${i}`));
  for (const h of holders) StorageNode.connect(owner, h);

  return { owner, holders, ownerNet, holderNets, dirs };
}

export async function run(t) {
  const sodium = await loadSodium();
  const wasm = await loadWasmBytes();

  // ── FsBlobStore ────────────────────────────────────────────────────────────
  t.group("FsBlobStore: durable store.local backend (§12)");
  {
    const dir = mkdtempSync(join(tmpdir(), "seedstore-fs-"));
    try {
      const store = new FsBlobStore(new NodeFs(dir), 1024);
      const id = sodium.crypto_generichash(32, file(64, 2));
      const bytes = file(64, 2);
      const desc = new Uint8Array([9, 8, 7, 6]);

      t.ok(!store.has(id), "absent before put");
      store.put(id, bytes, desc);
      t.ok(store.has(id), "present after put");
      const got = store.get(id);
      t.ok(got && bytesEqual(got.bytes, bytes), "get returns the bytes");
      t.ok(got && got.descriptor && bytesEqual(got.descriptor, desc), "descriptor persisted alongside");
      t.eq(store.stat().used, bytes.length, "used reflects ciphertext size");
      t.eq(store.list().length, 1, "list sees the one block");

      // Persistence: a fresh store over the same dir rebuilds its index.
      const reopened = new FsBlobStore(new NodeFs(dir), 1024);
      t.ok(reopened.has(id), "reopened store still has the block");
      t.eq(reopened.stat().used, bytes.length, "reopened used is correct");
      const got2 = reopened.get(id);
      t.ok(got2 && bytesEqual(got2.bytes, bytes), "reopened get returns the bytes");

      t.ok(store.delete(id), "delete reports removal");
      t.ok(!store.has(id), "absent after delete");
      t.eq(store.stat().used, 0, "used returns to zero");

      // Quota is enforced exactly like MemoryBlobStore.
      let threw = false;
      try { store.put(id, file(2048), null); } catch { threw = true; }
      t.ok(threw, "put past quota throws");
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
      const cold = new FsBlobStore(new NodeFs(dirs[holderIdx]));
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

    const S = await StorageNode.create({ network: netS, sodium, ...wasm, identity: idS, store: new MemoryBlobStore(), timeoutMs: 3000 });
    const B = await StorageNode.create({ network: netB, sodium, ...wasm, identity: idB, store: new MemoryBlobStore(), timeoutMs: 3000 });
    StorageNode.connect(S, B);
    await netB.ready(8000);
    await sleep(50);

    try {
      const bytes = file(64, 21);
      const bid = S.crypto.hash(bytes);

      const have0 = await B.transport.request(S.peerId, MsgType.HAVE, encodeHaveReq([bid]));
      t.eq(decodeHaveRes(have0)[0], false, "HAVE → false before the block exists (over ws)");

      const stored = await B.transport.request(S.peerId, MsgType.STORE, encodeStore({ blockId: bid, descriptor: null, bytes }));
      t.eq(stored[0], 1, "STORE acknowledged over ws");
      t.ok(S.store.has(bid), "server now holds the block");

      const have1 = await B.transport.request(S.peerId, MsgType.HAVE, encodeHaveReq([bid]));
      t.eq(decodeHaveRes(have1)[0], true, "HAVE → true after STORE (over ws)");

      const fetched = await B.transport.request(S.peerId, MsgType.FETCH, encodeFetchReq(bid));
      const back = decodeFetchRes(fetched);
      t.ok(back && bytesEqual(back, bytes), "FETCH returns the bytes over ws");
      t.ok(netS.framesDelivered > 0, "server received frames over the websocket");
    } finally {
      S.close(); B.close();
      netS.close(); netB.close();
    }
  }

  // ── full PUT → GET over relay-less WebRTC-Direct ────────────────────────────
  t.group("PUT → GET over relay-less WebRTC-Direct (a serveDirect node is a full storage peer)");
  {
    const baseDir = mkdtempSync(join(tmpdir(), "seedstore-direct-"));
    let owner, holders, ownerNet, holderNets;
    try {
      ({ owner, holders, ownerNet, holderNets } = await directStar({
        holderCount: 5, sodium, wasm, config: { k: 2, m: 2, blockSize: 64 }, baseDir,
      }));
      t.eq(owner.cohortPeers().length, 5, "owner linked to all five holders over WebRTC-Direct");
      t.ok(holderNets.every((n) => n.linkedPeers().includes(owner.peerId)), "every holder holds the reverse link");

      const data = file(200); // 4 blocks → 2 RS chunks, each spread over 4 distinct holders
      const put = await owner.put(data);
      t.ok(!put.replicated, "a multi-block file takes the RS path");
      t.eq(put.chunkCount, 2, "200 bytes / (k=2 × 64) → 2 chunks");

      const got = await owner.get(put.manifestId, put.key);
      t.ok(bytesEqual(got, data), "GET reconstructs the file over relay-less links");

      const occupied = holders.filter((h) => h.store.list().length > 0);
      t.ok(occupied.length >= 4, "blocks placed across several distinct holders");
      t.eq(owner.store.list().length, 0, "owner (coordinator) holds no blocks");
      t.ok(ownerNet.framesDelivered > 0, "responses crossed the relay-less links to the owner");
      t.ok(holderNets.some((n) => n.framesDelivered > 0), "requests crossed to the holders");
    } finally {
      holders?.forEach((h) => h.close());
      owner?.close();
      holderNets?.forEach((n) => n.close());
      ownerNet?.close();
      rmSync(baseDir, { recursive: true, force: true });
    }
  }

}

// Networking + filesystem integration (README §16, §12). Exercises the real
// fabric that replaces the loopback:
//   - FsBlobView reads the durable store.local layout back, across reopen
//   - a full cohort over real TCP sockets, blocks landing on holders' disks
//   - a browser-like node reaching a server node over a real WebSocket
//
// The transport's own behaviour (RFC 6455 framing, AKE, contact-secret gate)
// lives in seedkernel and is tested there; this file covers only the
// storage-level integration on top of the real NodeChannelFactory socket seam.

import { mkdtempSync, rmSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadSodium, loadWasmBytes } from "../build/host/node.js";
import { StorageNode } from "../build/host/storage-node.js";
import { NodeChannelFactory } from "seedkernel-wasm/net-node";
import { FsBlobView } from "../build/host/store-view.js";
import { NodeFs } from "seedkernel-wasm/fs-node";
import { scopedFs } from "seedkernel-wasm/shell-core";
import {
  MsgType, encodeHaveReq, decodeMask, encodeStoreBatch, encodeFetchBatchReq, decodeFetchBatchRes,
  VERDICT_ACCEPTED, VERDICT_DECLINED,
} from "../build/host/protocol.js";
import { signDescriptor } from "../build/host/manifest.js";
import { toHex, fromHex, bytesEqual } from "../build/host/util.js";
import { plantBlock } from "./helpers.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

function newKey(sodium) {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

// Stand up `count` storage nodes on real TCP loopback sockets, each with its own
// on-disk store.local directory, fully connected (StorageNode.connect wires the
// addresses + dials; the transport's own router collapses the simultaneous dials).
async function tcpCohort({ count, sodium, wasm, config, baseDir }) {
  const dirs = [];
  const nodes = [];
  for (let i = 0; i < count; i++) {
    const dir = join(baseDir, `n${i}`);
    dirs.push(dir);
    // The socket seam is a real node:net factory; the node binds an ephemeral port.
    nodes.push(await StorageNode.create({
      sodium, ...wasm, identity: newKey(sodium), config, timeoutMs: 3000,
      channels: new NodeChannelFactory(),
      listen: { host: "127.0.0.1", port: 0 },
      // Give the node a disk-backed fs; its default store view reads that same fs, so
      // what the confined guest holder writes via `fs` lands on disk and node.store
      // reflects it (the view must read the fs the guest serves).
      fs: new NodeFs(dir),
    }));
  }
  for (let i = 0; i < count; i++) for (let j = i + 1; j < count; j++) await StorageNode.connect(nodes[i], nodes[j]);
  await sleep(100); // let inbound links finish promoting
  return { nodes, dirs };
}

export async function run(t) {
  const sodium = await loadSodium();
  const wasm = await loadWasmBytes();

  // ── FsBlobView ─────────────────────────────────────────────────────────────
  // A pure READ view of the durable store.local layout (§12) — the write half
  // (admission, quota, the writes) belongs to the confined guest holder alone
  // (protocol.test.mjs drives it over the real wire). This writes the layout
  // the way the guest does, through `fs`, and checks the view reads it back.
  t.group("FsBlobView: reading back the durable store.local layout (§12)");
  {
    const dir = mkdtempSync(join(tmpdir(), "seedstore-fs-"));
    try {
      const fs = new NodeFs(dir);
      const view = new FsBlobView(fs);
      const bytes = file(64, 2);
      const id = sodium.crypto_generichash(32, bytes);
      const desc = new Uint8Array([9, 8, 7, 6]);

      t.ok(!(await view.has(id)), "absent before anything is written");
      t.eq(await view.usedBytes(), 0, "used starts at zero");

      await plantBlock(fs, toHex(id), bytes, desc);
      t.ok(await view.has(id), "present once the block is on the backend");
      const got = await view.get(id);
      t.ok(got && bytesEqual(got.bytes, bytes), "get returns the bytes");
      t.ok(got && got.descriptor && bytesEqual(got.descriptor, desc), "descriptor read from the sibling .dsc");
      t.eq(await view.usedBytes(), bytes.length + desc.length, "used counts ciphertext + descriptor — what the holder charges (§14)");
      t.eq((await view.list()).length, 1, "list sees the one block");

      // The view holds no index of its own, so it sees writes it did not make —
      // which is the point: on a live node the guest is the one writing.
      const bytes2 = file(32, 5);
      const id2 = sodium.crypto_generichash(32, bytes2);
      await plantBlock(fs, toHex(id2), bytes2, null);
      t.eq((await view.list()).length, 2, "a write made behind the view's back still shows up");
      t.eq((await view.get(id2)).descriptor, null, "a bare block reads back with a null descriptor");

      // Durability: a fresh view over the same directory sees the same blocks.
      const reopened = new FsBlobView(new NodeFs(dir));
      t.ok(await reopened.has(id), "reopened view still has the block");
      t.eq(await reopened.usedBytes(), bytes.length + desc.length + bytes2.length, "reopened used is correct (blks + dscs)");
      t.ok(bytesEqual((await reopened.get(id)).bytes, bytes), "reopened get returns the bytes");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  // ── full cohort over real TCP, blocks on disk ──────────────────────────────
  t.group("PUT → GET across a cohort over real TCP, blocks persisted to disk");
  {
    const baseDir = mkdtempSync(join(tmpdir(), "seedstore-tcp-"));
    const { nodes } = await tcpCohort({
      count: 6, sodium, wasm, config: { k: 2, m: 2, blockSize: 1024 }, baseDir,
    });
    try {
      const owner = nodes[0];
      const data = file(3200); // 4 blocks → 2 RS chunks
      const put = await owner.put(data);
      t.eq(put.chunkCount, 2, "3200 bytes / (k=2 × 1024) → 2 chunks");

      const got = await owner.get(put.root, put.key);
      t.ok(bytesEqual(got, data), "GET reconstructs the file over the wire");

      const holders = [];
      for (const n of nodes) { if (n !== owner && (await n.store.list()).length > 0) holders.push(n); }
      t.ok(holders.length >= 4, "blocks placed across several distinct peers");
      t.eq((await owner.store.list()).length, 0, "owner holds no blocks");

      t.ok((await holders[0].store.list()).length > 0, "a holder kept at least one block");
      // The driver's `framesDelivered` mirror is gone with the request facade it counted:
      // frames are the transport's now, and the host holds only sockets. What proves the same
      // thing — that this ran over real sockets rather than in-process — is the transport's
      // own authenticated set, which only a completed AKE over a live channel fills.
      const linked = await Promise.all(nodes.map((n) => n.net.linkedPeers()));
      t.ok(linked.some((peers) => peers.length > 0), "links authenticated over real sockets");
    } finally {
      nodes.forEach((n) => n.close());
      rmSync(baseDir, { recursive: true, force: true });
    }
  }

  // ── disk persistence of a holder, isolated and explicit ────────────────────
  t.group("a holder's blocks survive a store reopen (real files on disk)");
  {
    const baseDir = mkdtempSync(join(tmpdir(), "seedstore-persist-"));
    const { nodes, dirs } = await tcpCohort({
      count: 6, sodium, wasm, config: { k: 2, m: 2, blockSize: 1024 }, baseDir,
    });
    try {
      const owner = nodes[0];
      const put = await owner.put(file(4096, 7));
      t.ok(put.chunkCount >= 1, "file placed");

      // Find a holder index with blocks and reopen *its* directory cold.
      let holderIdx = -1;
      for (let i = 1; i < nodes.length; i++) if ((await nodes[i].store.list()).length > 0) { holderIdx = i; break; }
      t.ok(holderIdx > 0, "located a holder with blocks");
      const idsBefore = (await nodes[holderIdx].store.list()).map(toHex).sort();
      // Cold reopen enters through the app's fs scope, exactly as the live node does
      // (seedkernel §12.2): the holder's keys are `appScope + <hex>.rec` on the raw
      // backend, so a view over the unwrapped NodeFs would list nothing.
      const cold = new FsBlobView(scopedFs(new NodeFs(dirs[holderIdx]), nodes[holderIdx].appScope));
      const idsAfter = (await cold.list()).map(toHex).sort();
      t.eq(idsAfter.join(","), idsBefore.join(","), "cold reopen sees exactly the same block ids");
      const onDisk = readdirSync(dirs[holderIdx]).filter((f) => f.endsWith(".rec"));
      t.eq(onDisk.length, idsBefore.length, "one .rec file per held block on disk");
    } finally {
      nodes.forEach((n) => n.close());
      rmSync(baseDir, { recursive: true, force: true });
    }
  }

  // ── browser ↔ node over a real WebSocket ───────────────────────────────────
  t.group("control plane round-trips over a real WebSocket (browser ↔ node, §16)");
  {
    const idS = newKey(sodium), idB = newKey(sodium);
    // S gates its listener; B is a dialer only, so it has no inbound secret of its own —
    // it carries S's on the address it dials.
    const secretS = sodium.randombytes_buf(32);
    const S = await StorageNode.create({
      sodium, ...wasm, identity: idS, timeoutMs: 3000,
      channels: new NodeChannelFactory(),
      listen: { host: "127.0.0.1", port: 0 },
      wsListen: { host: "127.0.0.1", port: 0 },
      contactSecret: secretS,
    });
    const B = await StorageNode.create({
      sodium, ...wasm, identity: idB, timeoutMs: 3000,
      channels: new NodeChannelFactory(),
    });
    B.addPeer(S.peerId);
    S.addPeer(B.peerId);
    B.net.addPeerAddr(S.peerId,
      { host: "127.0.0.1", port: S.net.wsPort, transport: "ws", contactSecret: secretS });
    await B.net.ready(8000);
    await sleep(50);

    try {
      const bytes = file(64, 21);
      const bid = S.crypto.hash(bytes);

      const have0 = await B.request(S.peerId, typed(MsgType.HAVE, encodeHaveReq([bid])));
      t.eq(decodeMask(have0)[0], VERDICT_DECLINED, "HAVE → false before the block exists (over ws)");

      // The block travels with its author-signed chunk descriptor (§4.3) — the holder
      // verifies it before admitting, here as on any other transport. Both nodes load the
      // same bundle, so they share one signing scope (author).
      const desc = signDescriptor(sodium, { level: 0, k: 1, m: 0, blockSize: bytes.length, tailBytes: bytes.length, authTag: new Uint8Array(16), blockIds: [bid] }, idB.publicKey, idB.privateKey, S.signAuthor);

      const stored = decodeMask(await B.request(S.peerId, typed(MsgType.STORE, encodeStoreBatch([{ blockId: bid, descriptor: desc, bytes }]))));
      t.eq(stored[0], VERDICT_ACCEPTED, "STORE acknowledged over ws");
      t.ok(await S.store.has(bid), "server now holds the block");

      const have1 = await B.request(S.peerId, typed(MsgType.HAVE, encodeHaveReq([bid])));
      t.eq(decodeMask(have1)[0], VERDICT_ACCEPTED, "HAVE → true after STORE (over ws)");

      const fetched = await B.request(S.peerId, typed(MsgType.FETCH, encodeFetchBatchReq([bid])));
      const back = decodeFetchBatchRes(fetched)[0];
      t.ok(back && bytesEqual(back, bytes), "FETCH returns the bytes over ws");
      t.ok((await S.net.linkedPeers()).length > 0, "the server holds an authenticated link over the websocket");
    } finally {
      S.close(); B.close();
    }
  }
}

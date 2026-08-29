// Headless storage-over-RtcNetwork smoke: an owner + N holders, all werift-backed
// RtcNetworks wired by an IN-PROCESS signaling hub (no relay process, no
// WebSocket), connect over real WebRTC (ICE -> DTLS -> SCTP on loopback) and
// PUT -> GET a file. Node-parity of the relay + STUN path browser/p2p.html runs —
// the same RtcNetwork + StorageNode, with loopback candidates standing in for
// STUN-punched ones; the real demo swaps in seedrelay's WebSocket adapter.
//
//   node scripts/smoke-rtc.mjs            (or: bun scripts/smoke-rtc.mjs)   HOLDERS=n

import { loadSodium, loadWasmBytes } from "../build/host/node.js";
import { StorageNode, bootTransportShell } from "../build/host/storage-node.js";
import { MsgType, encodeHaveReq, decodeMask } from "../build/host/protocol.js";
import { bytesEqual, toHex } from "../build/host/util.js";
import { RtcNetwork } from "seedkernel-wasm/net-rtc";
import { createRelaySignaling } from "seedrelay";
import { weriftPeerConnectionFactory } from "./werift-pc.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function typed(type, data) {
  const out = new Uint8Array(1 + data.length);
  out[0] = type; out.set(data, 1);
  return out;
}
const HOLDERS = Number(process.env.HOLDERS) || 3;

// Two modes. Default: an in-process signaling hub (offline, Node or Bun). With
// RELAY=ws://host:port set: the REAL seedrelay path against a running server —
// the exact transport serve-rtc-holder.mjs + p2p.html use. That needs a global
// WebSocket, so run it on Bun:  RELAY=ws://127.0.0.1:8080 bun scripts/smoke-rtc.mjs
const RELAY = process.env.RELAY ? process.env.RELAY.replace(/\/+$/, "") : null;
const ROOM = process.env.ROOM ?? "smoke-rtc-" + Math.random().toString(16).slice(2, 10);
if (RELAY && typeof WebSocket === "undefined") {
  console.error("RELAY mode needs a global WebSocket — run on Bun (`bun scripts/smoke-rtc.mjs`) or Node ≥22.");
  process.exit(1);
}

// An in-memory N-party signaling hub: every JSON signal from one member is
// delivered to all OTHER members (RtcNetwork filters by from/to itself).
// Delivery is DEFERRED (setTimeout 0): RtcNetwork's perfect-negotiation state
// machine assumes async arrival, and a synchronous/reentrant send() reorders the
// offer/answer/ICE handshake and wedges the mesh.
function makeSignalingHub() {
  const members = new Set();
  return () => {
    const m = { cb: () => {} };
    members.add(m);
    return {
      send: (msg) => {
        for (const o of members) {
          if (o === m) continue;
          const cb = o.cb;
          setTimeout(() => { try { cb(msg); } catch { /* a bad handler must not wedge signaling */ } }, 0);
        }
      },
      onMessage: (fn) => { m.cb = fn; },
      close: () => { members.delete(m); },
    };
  };
}

const sodium = await loadSodium();
const wasm = await loadWasmBytes();
// `join()` mints one signaling endpoint per node — the in-process hub by default, or
// a fresh seedrelay client (same room) in RELAY mode.
const join = RELAY ? () => {
  const relay = createRelaySignaling({ webSocketFactory: (url) => new WebSocket(url) });
  relay.connect(`${RELAY}/${encodeURIComponent(ROOM)}`);
  return relay.signaling;
} : makeSignalingHub();
// Loopback host candidate so every pair connects with no STUN (the smoke is offline).
const pcFactory = weriftPeerConnectionFactory({ iceAdditionalHostAddresses: ["127.0.0.1"] });
// Small file, replicated to every holder; 48 KiB stays under werift's 64 KiB
// data-channel reassembly cap, and maxMessageBytes holds batched OFFER/STORE/
// FETCH to the same ceiling.
const config = { k: 1, m: HOLDERS, blockSize: 48 * 1024, maxMessageBytes: 48 * 1024 };

// The room's shared, symmetric contact secret. Gating this smoke (rather than
// running it open) covers the credential path the real demos use too.
const CONTACT = process.env.CONTACT
  ? Uint8Array.from(process.env.CONTACT.match(/../g).map((b) => parseInt(b, 16)))
  : sodium.randombytes_buf(32);

// A WebRTC-edge node (no TCP/WS listeners); storage geometry does not ride
// here — it goes on StorageNode.create, so the transport guest never sees it.
async function makeNode(contact = CONTACT) {
  const identity = (() => { const kp = sodium.crypto_sign_keypair(); return { publicKey: kp.publicKey, privateKey: kp.privateKey }; })();
  const entry = { node: null, runtime: null, net: null };
  entry.net = new RtcNetwork({
    peerId: toHex(identity.publicKey),
    signaling: join(), peerConnectionFactory: pcFactory,
  });
  entry.runtime = await bootTransportShell({
    sodium, identity, timeoutMs: 8000, contactSecret: contact, channels: entry.net,
  });
  return entry;
}

const nodes = [];
let ok = false;
try {
  for (let i = 0; i < HOLDERS + 1; i++) {
    const e = await makeNode();
    e.node = await StorageNode.create({ runtime: e.runtime, sodium, ...wasm, config, quota: 64 * 1024 * 1024, timeoutMs: 8000 });
    nodes.push(e);
  }
  const owner = nodes[0];
  for (const e of nodes) e.net.join(); // announce into the room → the WebRTC dance begins

  console.log(`booted owner + ${HOLDERS} holder(s); forming the WebRTC mesh (${RELAY ? `via relay ${RELAY} room ${ROOM}` : "in-process signaling, no relay"})…`);

  // Wait for the owner to link every holder (werift's pure-JS DTLS/SCTP is slow).
  const t0 = Date.now();
  let ownerPeers = await owner.node.linkedPeers();
  while (ownerPeers.length < HOLDERS && Date.now() - t0 < 30000) {
    await sleep(150);
    ownerPeers = await owner.node.linkedPeers();
  }
  if (ownerPeers.length < HOLDERS) {
    throw new Error(`owner linked only ${ownerPeers.length}/${HOLDERS} holders in time`);
  }

  const data = new Uint8Array(1000);
  for (let i = 0; i < data.length; i++) data[i] = (i * 7 + 3) & 255;
  const r = await owner.node.put(data);
  console.log(`\nowner PUT ${data.length} B → ${r.chunkCount} chunk(s), ${r.blockIds.length} block(s) across ${ownerPeers.length} holder(s)`);

  let onAll = true;
  for (const p of ownerPeers) {
    const res = await owner.node.request(p, typed(MsgType.HAVE, encodeHaveReq(r.blockIds)));
    const held = decodeMask(res).filter((v) => v === 1).length;
    console.log(`  ${p.slice(0, 8)}…  ${held}/${r.blockIds.length} blocks`);
    if (held < r.blockIds.length) onAll = false;
  }

  const got = await owner.node.get(r.root, r.key);
  const roundTrip = bytesEqual(got, data);

  // Negative: a stranger with the right room but the WRONG contact secret. Refusal
  // is SILENT by design (§12.6.2), so we assert "never links" within the same 30 s window.
  const stranger = await makeNode(sodium.randombytes_buf(32));
  nodes.push(stranger);
  stranger.node = await StorageNode.create({
    runtime: stranger.runtime, sodium, ...wasm, config, timeoutMs: 8000 });
  stranger.net.join();
  const before = (await owner.node.linkedPeers()).length;
  const t1 = Date.now();
  let strangerPeers = await stranger.node.linkedPeers();
  while (strangerPeers.length === 0 && Date.now() - t1 < 30000) {
    await sleep(150);
    strangerPeers = await stranger.node.linkedPeers();
  }
  const ownerAfter = (await owner.node.linkedPeers()).length;
  const gated = strangerPeers.length === 0 && ownerAfter === before;
  console.log(gated
    ? `\ngate holds — a peer with the wrong contact secret linked 0 nodes in 30 s (refused in silence)`
    : `\nGATE FAILED — stranger linked ${strangerPeers.length}, owner links ${before} → ${ownerAfter}`);

  ok = roundTrip && onAll && gated;
  console.log(ok
    ? `\nOK — file replicated to all ${HOLDERS} holders + retrieved over RtcNetwork (data peer-to-peer; relay = signaling only in the real demo)`
    : `\nFAIL — roundTrip=${roundTrip}, onAllHolders=${onAll}, gated=${gated}`);
} catch (e) {
  console.error("\nFAILED:", e?.message ?? e);
} finally {
  for (const e of nodes) { try { e.node?.close(); } catch { /* ignore */ } try { e.net.close(); } catch { /* ignore */ } }
}
process.exit(ok ? 0 : 1);

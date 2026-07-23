// Headless storage-over-RtcNetwork smoke: an owner + N holders, all werift-backed
// RtcNetworks wired by an IN-PROCESS signaling hub (no relay process, no WebSocket),
// connect over real WebRTC (ICE → DTLS → SCTP on loopback) and PUT → GET a file.
//
// This is the node-parity of the relay + STUN path browser/p2p.html runs: the SAME
// RtcNetwork + StorageNode, only the signaling rendezvous is in-memory here instead
// of the relay WebSocket (relaySignaling), and loopback host candidates stand in for
// STUN-punched ones. A green smoke means the console serveRtc holder path is sound;
// the real demo only swaps the in-memory hub for `relaySignaling(relay/room)`.
//
//   node scripts/smoke-rtc.mjs            (or: bun scripts/smoke-rtc.mjs)   HOLDERS=n

import { loadSodium, loadWasmBytes } from "../build/host/node.js";
import { StorageNode } from "../build/host/storage-node.js";
import { MsgType, encodeHaveReq, decodeMask } from "../build/host/protocol.js";
import { bytesEqual } from "../build/host/util.js";
import { RtcNetwork, relaySignaling } from "seedkernel-wasm/net-rtc";
import { weriftPeerConnectionFactory } from "seedkernel-wasm/net-rtc-node";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const enc = new TextEncoder();
const SEEDSTORE_PROTO = enc.encode("seedstore");

function typed(type, data) {
  const out = new Uint8Array(1 + data.length);
  out[0] = type; out.set(data, 1);
  return out;
}
const HOLDERS = Number(process.env.HOLDERS) || 3;

// Two modes. Default: an in-process signaling hub (offline, Node or Bun). With
// RELAY=ws://host:port set: the REAL relaySignaling path against a running relay —
// the exact transport serve-rtc-holder.mjs + p2p.html use. That needs a global
// WebSocket, so run it on Bun:  RELAY=ws://127.0.0.1:8080 bun scripts/smoke-rtc.mjs
const RELAY = process.env.RELAY ? process.env.RELAY.replace(/\/+$/, "") : null;
const ROOM = process.env.ROOM ?? "smoke-rtc-" + Math.random().toString(16).slice(2, 10);
if (RELAY && typeof WebSocket === "undefined") {
  console.error("RELAY mode needs a global WebSocket — run on Bun (`bun scripts/smoke-rtc.mjs`) or Node ≥22.");
  process.exit(1);
}

// An in-memory N-party signaling hub: every JSON signal from one member is delivered
// to all OTHER members in the room — exactly what scripts/relay.mjs does over a
// WebSocket, minus the network. RtcNetwork filters by from/to itself.
//
// Delivery is DEFERRED (setTimeout 0), not synchronous: RtcNetwork's perfect-
// negotiation state machine assumes signals arrive asynchronously (as they do over
// the relay WebSocket). Delivering them synchronously/reentrantly inside send()
// reorders the offer/answer/ICE handshake and wedges the mesh — only the first pair
// links. So we mimic the network's async hop.
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
// a fresh relay WebSocket (same room) in RELAY mode.
const join = RELAY ? () => relaySignaling(`${RELAY}/${encodeURIComponent(ROOM)}`) : makeSignalingHub();
// Loopback host candidate so every pair connects with no STUN (the smoke is offline).
const pcFactory = weriftPeerConnectionFactory({ iceAdditionalHostAddresses: ["127.0.0.1"] });
// Small file → replicated to every holder (≤ blockSize); 48 KiB stays under werift's
// 64 KiB data-channel reassembly cap on the receiving (console) side. maxMessageBytes
// holds a batched OFFER/STORE/FETCH to the same ceiling, so a larger file can't pack
// a batch past the data channel either.
const config = { k: 1, m: HOLDERS, blockSize: 48 * 1024, maxMessageBytes: 48 * 1024 };

function makeNode() {
  const identity = (() => { const kp = sodium.crypto_sign_keypair(); return { publicKey: kp.publicKey, privateKey: kp.privateKey }; })();
  const entry = { identity, node: null };
  entry.net = new RtcNetwork({
    identity, sodium, signaling: join(), peerConnectionFactory: pcFactory,
    onPeerUp: (pid) => entry.node?.addPeer(pid),
    onPeerDown: (pid) => entry.node?.removePeer(pid),
  });
  return entry;
}

const nodes = [];
let ok = false;
try {
  for (let i = 0; i < HOLDERS + 1; i++) {
    const e = makeNode();
    e.node = await StorageNode.create({ network: e.net, sodium, ...wasm, identity: e.identity, config, timeoutMs: 8000 });
    nodes.push(e);
  }
  const owner = nodes[0];
  for (const e of nodes) e.net.join(); // announce into the room → the WebRTC dance begins

  console.log(`booted owner + ${HOLDERS} holder(s); forming the WebRTC mesh (${RELAY ? `via relay ${RELAY} room ${ROOM}` : "in-process signaling, no relay"})…`);

  // Wait for the owner to link every holder (werift's pure-JS DTLS/SCTP is slow).
  const t0 = Date.now();
  while (owner.node.cohortPeers().length < HOLDERS && Date.now() - t0 < 30000) await sleep(150);
  if (owner.node.cohortPeers().length < HOLDERS) {
    throw new Error(`owner linked only ${owner.node.cohortPeers().length}/${HOLDERS} holders in time`);
  }

  const data = new Uint8Array(1000);
  for (let i = 0; i < data.length; i++) data[i] = (i * 7 + 3) & 255;
  const r = await owner.node.put(data);
  console.log(`\nowner PUT ${data.length} B → ${r.replicated ? "replicated" : r.chunkCount + " RS chunk(s)"}, ${r.blockIds.length} block(s) across ${owner.node.cohortPeers().length} holder(s)`);

  let onAll = true;
  for (const p of owner.node.cohortPeers()) {
    const res = await owner.node.transport.request(p, SEEDSTORE_PROTO, typed(MsgType.HAVE, encodeHaveReq(r.blockIds)));
    const held = decodeMask(res).filter((v) => v === 1).length;
    console.log(`  ${p.slice(0, 8)}…  ${held}/${r.blockIds.length} blocks`);
    if (held < r.blockIds.length) onAll = false;
  }

  const got = await owner.node.get(r.manifestId, r.key);
  const roundTrip = bytesEqual(got, data);
  ok = roundTrip && onAll;
  console.log(ok
    ? `\nOK — file replicated to all ${HOLDERS} holders + retrieved over RtcNetwork (data peer-to-peer; relay = signaling only in the real demo)`
    : `\nFAIL — roundTrip=${roundTrip}, onAllHolders=${onAll}`);
} catch (e) {
  console.error("\nFAILED:", e?.message ?? e);
} finally {
  for (const e of nodes) { try { e.node?.close(); } catch { /* ignore */ } try { e.net.close(); } catch { /* ignore */ } }
}
process.exit(ok ? 0 : 1);

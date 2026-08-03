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
import { StorageNode, bootTransportShell } from "../build/host/storage-node.js";
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
// to all OTHER members in the room — exactly what seedchat's scripts/relay.mjs does over a
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
// Small file — replicated to every holder (≤ blockSize); 48 KiB stays under werift's
// 64 KiB data-channel reassembly cap on the receiving (console) side. maxMessageBytes
// holds a batched OFFER/STORE/FETCH to the same ceiling, so a larger file can't pack
// a batch past the data channel either.
const config = { k: 1, m: HOLDERS, blockSize: 48 * 1024, maxMessageBytes: 48 * 1024 };

// The room's shared contact secret. A cohort in one room is symmetric — every node both
// accepts and dials — so one value serves as both the secret we demand of callers and
// the one we present when dialing. Gating this smoke (rather than running it open) is
// what makes it cover the credential path the real demos use, not just the transport.
const CONTACT = process.env.CONTACT
  ? Uint8Array.from(process.env.CONTACT.match(/../g).map((b) => parseInt(b, 16)))
  : sodium.randombytes_buf(32);

// The transport is a signed bundle: each node boots a shared shell with it admitted
// (the node's network standing — no TCP/WS listeners, a WebRTC-edge node), then the
// RtcNetwork puts the WebRTC socket seam under the driver. The geometry rides in as
// operator config — a shared shell's APP is fixed at boot, so the operator config
// must be here, not on StorageNode.create.
async function makeNode(contact = CONTACT) {
  const identity = (() => { const kp = sodium.crypto_sign_keypair(); return { publicKey: kp.publicKey, privateKey: kp.privateKey }; })();
  const entry = { identity, node: null, shell: null };
  entry.shell = (await bootTransportShell({
    sodium, identity, timeoutMs: 8000, contactSecret: contact,
    config: { ...config, quota: 64 * 1024 * 1024 },
    // The guest's NET_PEERS (cohortPeers) reads this; the node's cohort set is
    // populated by onPeerUp before any PUT/repair runs.
    livePeers: () => entry.node ? entry.node.cohortPeers() : [],
  })).shell;
  entry.net = new RtcNetwork({
    driver: entry.shell.net,
    signaling: join(), peerConnectionFactory: pcFactory,
    peerContactFor: () => contact,
    onPeerUp: (pid) => entry.node?.addPeer(pid),
    onPeerDown: (pid) => entry.node?.removePeer(pid),
  });
  return entry;
}

const nodes = [];
let ok = false;
try {
  for (let i = 0; i < HOLDERS + 1; i++) {
    const e = await makeNode();
    e.node = await StorageNode.create({ shell: e.shell, sodium, ...wasm, identity: e.identity, config, timeoutMs: 8000 });
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
  console.log(`\nowner PUT ${data.length} B → ${r.chunkCount} chunk(s), ${r.blockIds.length} block(s) across ${owner.node.cohortPeers().length} holder(s)`);

  let onAll = true;
  for (const p of owner.node.cohortPeers()) {
    const res = await owner.node.transport.request(p, SEEDSTORE_PROTO, typed(MsgType.HAVE, encodeHaveReq(r.blockIds)));
    const held = decodeMask(res).filter((v) => v === 1).length;
    console.log(`  ${p.slice(0, 8)}…  ${held}/${r.blockIds.length} blocks`);
    if (held < r.blockIds.length) onAll = false;
  }

  const got = await owner.node.get(r.root, r.key);
  const roundTrip = bytesEqual(got, data);

  // Negative: a stranger with the right room but the WRONG contact secret. It reaches
  // signaling and gets as far as a data channel — the gate is in the handshake, not the
  // rendezvous — and then draws nothing. Refusal is SILENT by design (§12.6.2), so the
  // only observable is a peer that never links; we assert exactly that, giving it the
  // same 30 s the real holders got so a slow werift handshake can't fake a pass.
  const stranger = await makeNode(sodium.randombytes_buf(32));
  nodes.push(stranger);
  stranger.node = await StorageNode.create({
    shell: stranger.shell, sodium, ...wasm, identity: stranger.identity, config, timeoutMs: 8000 });
  stranger.net.join();
  const before = owner.node.cohortPeers().length;
  const t1 = Date.now();
  while (stranger.node.cohortPeers().length === 0 && Date.now() - t1 < 30000) await sleep(150);
  const gated = stranger.node.cohortPeers().length === 0 && owner.node.cohortPeers().length === before;
  console.log(gated
    ? `\ngate holds — a peer with the wrong contact secret linked 0 nodes in 30 s (refused in silence)`
    : `\nGATE FAILED — stranger linked ${stranger.node.cohortPeers().length}, owner cohort ${before} → ${owner.node.cohortPeers().length}`);

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

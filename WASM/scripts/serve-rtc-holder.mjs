// A console storage HOLDER that joins a ROOM on a seedrelay and serves the holder side
// of the protocol. Peers meet and link through the relay, then move to real
// peer-to-peer WebRTC via the relay's STUN, and close the splice; where WebRTC cannot
// connect, the link stays on the relay. Console counterpart of browser/p2p.html: run a
// few of these, open p2p.html on the SAME relay + room, drop a file.
//
//   node scripts/serve-rtc-holder.mjs                (npm run serve:rtc-holder)
//   RELAY=ws://localhost:8080 ROOM=seedstore-demo node scripts/serve-rtc-holder.mjs
//   RELAY_SECRET=$(cat relay.secret) ...      a private relay, started with --secret
//
// The transport bundle speaks the relay itself, over a node:net socket and its own
// RFC 6455 framing, so no WebSocket global is needed. Start the relay first, on NODE
// not Bun (Bun's http upgrade swallows writes):
//   cd ../../seedshell && npm run relay

import { loadSodium, loadWasmBytes } from "../build/host/node.js";
import { StorageNode } from "../build/host/storage-node.js";
import { RtcNetwork } from "seedkernel-wasm/net-rtc";
import { NodeChannelFactory } from "seedkernel-wasm/net-node";
import { combineChannels } from "seedkernel-wasm/socket-seam";
import { weriftPeerConnectionFactory } from "./werift-pc.mjs";
import { joinRelayRoom } from "./relay-room.mjs";

const short = (id) => id.slice(0, 12) + "…";
const base = (process.env.RELAY ?? "ws://localhost:8080").replace(/\/+$/, "");
const room = process.env.ROOM ?? "seedstore-demo";
// RELAY_SECRET — a private relay's secret (seedrelay's `--secret`), proved and never sent.
// Unset => an open relay.
const relaySecret = process.env.RELAY_SECRET || undefined;

// CONTACT — the room's shared contact secret, 32 bytes of hex. The cohort is
// symmetric, so the value we demand of callers and present when dialing is the
// same. Unset => open room. A mismatched secret has no error path (§12.6.2) — a
// gated peer refuses in silence, so "peers never link" is the symptom.
//
//   CONTACT=$(openssl rand -hex 32) ROOM=my-room node scripts/serve-rtc-holder.mjs
const contactSecret = (() => {
  const hex = process.env.CONTACT;
  if (!hex) return undefined;
  if (!/^[0-9a-f]{64}$/i.test(hex)) {
    console.error("CONTACT must be 32-byte hex (64 chars) — e.g. CONTACT=$(openssl rand -hex 32)");
    process.exit(1);
  }
  return Uint8Array.from(hex.match(/../g).map((b) => parseInt(b, 16)));
})();

// Defaults match p2p.html so a mixed browser/console cohort agrees on RS params.
// maxMessageBytes mirrors the browser's WebRTC value — under werift's ~64 KiB channel.
const config = { k: Number(process.env.K) || 1, m: Number(process.env.M) || 1, blockSize: Number(process.env.BS) || 256, maxMessageBytes: 48 * 1024 };

const sodium = await loadSodium();
const wasm = await loadWasmBytes();
const identity = (() => { const kp = sodium.crypto_sign_keypair(); return { publicKey: kp.publicKey, privateKey: kp.privateKey }; })();

// A browser-edge-style node with no listeners. Its sockets are a node:net factory for the
// relay and an RtcNetwork for the peer connections; the transport bundle registers and
// links through the first, signals over those links, and drives the second. A room
// shares one contact secret, so this node's own is the one its peers present.
const net = combineChannels(
  new NodeChannelFactory(),
  // werift's RTCPeerConnection: pure-JS, no native addon (bundles into `bun --compile`).
  new RtcNetwork({ peerConnectionFactory: weriftPeerConnectionFactory() }),
);
const { bootTransportShell } = await import("../build/host/storage-node.js");
const runtime = await bootTransportShell({
  sodium, identity, timeoutMs: 6000, contactSecret, channels: net,
  // No app config here — it travels with the storage bundle's own load below.
});

// A real StorageNode serving HAVE / OFFER / STORE / FETCH over the P2P links. Default
// store.local is an in-RAM fs, read back through the node's FsBlobView.
const node = await StorageNode.create({ runtime, sodium, ...wasm, config, quota: 64 * 1024 * 1024, timeoutMs: 6000 });
// Meet in the room: members are dialed through the relay, then move to WebRTC.
await joinRelayRoom({ shell: runtime.shell, identity, sodium, relay: base, room, secret: contactSecret, relaySecret });

console.log(`\nseedstore RTC holder ${short(node.peerId)} ready — handlers installed: ${node.handlersInstalled()}`);
console.log(`joined room "${room}" on ${base}${relaySecret ? " (private relay)" : ""}  (RS k=${config.k} m=${config.m}, ${config.blockSize} B blocks)`);
console.log(`open browser/p2p.html with the SAME relay + room "${room}" (or run more holders), then store a file.`);
console.log(contactSecret
  ? `contact secret: SET — peers must dial with the same CONTACT value or they draw silence.`
  : `contact secret: none (open room) — set CONTACT=<32-byte hex> to gate who may reach this holder.`);

// Self-healing per spec §9: repair on a jittered interval rebuilds missing
// blocks onto fresh peers when a chunk drops below its redundancy target — no
// button, no operator. Tune with REPAIR_MS (ms); REPAIR_MS=0 turns it off.
const repairMs = process.env.REPAIR_MS != null ? Number(process.env.REPAIR_MS) : 20_000;
if (repairMs > 0) {
  node.startRepairLoop({
    intervalMs: repairMs,
    onPass: (n) => { if (n > 0) console.log(`  ↻ repair re-placed ${n} block(s) on fresh peers — redundancy restored (§9)`); },
  });
  console.log(`self-healing on: repair pass every ~${(repairMs / 1000).toFixed(0)}s (jittered) — set REPAIR_MS to tune, =0 to disable.`);
} else {
  console.log("self-healing off (REPAIR_MS=0).");
}
console.log("(Ctrl+C to stop)\n");

// Show blocks landing: poll the store for newly-held ids.
const known = new Set();
const timer = setInterval(() => {
  for (const id of node.store.list().map(toHex)) {
    if (!known.has(id)) {
      known.add(id);
      const used = node.store.usedBytes();
      console.log(`  ✓ stored block ${short(id)}  (${known.size} held, ${(used / 1024).toFixed(1)} KB of ${(node.quota / 1024 / 1024).toFixed(0)} MB)`);
    }
  }
}, 300);

process.on("SIGINT", () => { clearInterval(timer); node.close(); process.exit(0); });

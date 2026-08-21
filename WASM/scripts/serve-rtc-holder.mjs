// A console storage HOLDER that joins a WebRTC signaling-relay ROOM and serves the
// holder side of the protocol over real peer-to-peer WebRTC. The relay carries ONLY
// signaling (SDP/ICE) — file bytes flow directly peer-to-peer via STUN, so the relay
// is killable once channels are up. Console counterpart of browser/p2p.html: run a
// few of these, open p2p.html on the SAME relay + room, drop a file.
//
//   bun scripts/serve-rtc-holder.mjs                 (npm run serve:rtc-holder)
//   RELAY=ws://localhost:8080 ROOM=seedstore-demo bun scripts/serve-rtc-holder.mjs
//
// Needs a global WebSocket (relaySignaling) → run on Bun (or Node >=22). Start the
// relay first, on NODE not Bun (Bun's http upgrade swallows writes):
//   cd ../../seedchat && npm run relay

import { loadSodium, loadWasmBytes } from "../build/host/node.js";
import { StorageNode } from "../build/host/storage-node.js";
import { RtcNetwork, relaySignaling } from "seedkernel-wasm/net-rtc";
import { weriftPeerConnectionFactory } from "seedkernel-wasm/net-rtc-node";
import { toHex } from "../build/host/util.js";

if (typeof WebSocket === "undefined") {
  console.error("relaySignaling needs a global WebSocket — run on Bun (`bun scripts/serve-rtc-holder.mjs`) or Node ≥22.");
  process.exit(1);
}

const short = (id) => id.slice(0, 12) + "…";
const base = (process.env.RELAY ?? "ws://localhost:8080").replace(/\/+$/, "");
const room = process.env.ROOM ?? "seedstore-demo";
const url = `${base}/${encodeURIComponent(room)}`;

// CONTACT — the room's shared contact secret, 32 bytes of hex. The cohort is
// symmetric, so the value we demand of callers and present when dialing is the
// same. Unset => open room. A mismatched secret has no error path (§12.6.2) — a
// gated peer refuses in silence, so "peers never link" is the symptom.
//
//   CONTACT=$(openssl rand -hex 32) ROOM=my-room bun scripts/serve-rtc-holder.mjs
const contactSecret = (() => {
  const hex = process.env.CONTACT;
  if (!hex) return undefined;
  if (!/^[0-9a-f]{64}$/i.test(hex)) {
    console.error("CONTACT must be 32-byte hex (64 chars) — e.g. CONTACT=$(openssl rand -hex 32)");
    process.exit(1);
  }
  return Uint8Array.from(hex.match(/../g).map((b) => parseInt(b, 16)));
})();

// Public STUN so the data channel can punch NAT/CGNAT to a browser/peer off-LAN —
// the same list browser/p2p.html uses. (Symmetric CGNAT with no IPv6 can still
// defeat hole punching; that is the ~5–10% case TURN exists for.)
const RTC_CONFIG = { iceServers: [{ urls: ["stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478"] }] };

// Defaults match p2p.html so a mixed browser/console cohort agrees on RS params.
// maxMessageBytes mirrors the browser's WebRTC value — under werift's ~64 KiB channel.
const config = { k: Number(process.env.K) || 1, m: Number(process.env.M) || 1, blockSize: Number(process.env.BS) || 256, maxMessageBytes: 48 * 1024 };

const sodium = await loadSodium();
const wasm = await loadWasmBytes();
const identity = (() => { const kp = sodium.crypto_sign_keypair(); return { publicKey: kp.publicKey, privateKey: kp.privateKey }; })();

// A browser-edge-style node — no TCP/WS listeners; links arrive through the
// driver's openLink. The room's contact secret gates the accepting side (the
// driver's), and `peerContactFor` presents the same value when dialing.
const { bootTransportShell } = await import("../build/host/storage-node.js");
const { shell, transport } = await bootTransportShell({
  sodium, identity, timeoutMs: 6000, contactSecret,
  // No app config here — it travels with the storage bundle's own load below.
});

let node = null;
const net = new RtcNetwork({
  driver: transport,
  rtcConfig: RTC_CONFIG,
  signaling: relaySignaling(url),
  peerContactFor: () => contactSecret,
  // werift's RTCPeerConnection: pure-JS, no native addon (bundles into `bun --compile`).
  peerConnectionFactory: weriftPeerConnectionFactory(),
  onPeerUp: (pid) => { node?.addPeer(pid); console.log(`· peer linked: ${short(pid)} (in-channel AUTH; relay = signaling only)`); },
  onPeerDown: (pid) => { node?.removePeer(pid); console.log(`· peer dropped: ${short(pid)}`); },
});

// A real StorageNode serving HAVE / OFFER / STORE / FETCH over the P2P links. Default
// store.local is an in-RAM fs, read back through the node's FsBlobView.
node = await StorageNode.create({ shell, transport, sodium, ...wasm, identity, config, quota: 64 * 1024 * 1024, timeoutMs: 6000 });
net.join(); // announce into the room → present peers begin the WebRTC handshake

console.log(`\nseed store RTC holder ${short(node.peerId)} ready — handlers installed: ${node.handlersInstalled()}`);
console.log(`joined ${url}  (RS k=${config.k} m=${config.m}, ${config.blockSize} B blocks)`);
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

process.on("SIGINT", () => { clearInterval(timer); node.close(); net.close(); process.exit(0); });

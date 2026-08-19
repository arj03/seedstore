// A console storage HOLDER that joins a WebRTC signaling-relay ROOM and serves the
// holder side of the protocol over real peer-to-peer WebRTC. The relay carries ONLY
// signaling (SDP / ICE) — the file bytes flow directly peer-to-peer, punched through
// NAT / CGNAT by STUN. So there is no server in the data path; the relay is killable
// once channels are up. This is the console counterpart of browser/p2p.html (the
// Spike-1 `serveRtc` role): run a few of these, open p2p.html in a tab on the SAME
// relay + room, drop a file, and watch the blocks land here.
//
//   bun scripts/serve-rtc-holder.mjs                 (npm run serve:rtc-holder)
//   RELAY=ws://localhost:8080 ROOM=seedstore-demo bun scripts/serve-rtc-holder.mjs
//
// Needs a global WebSocket (relaySignaling) → run on Bun (or Node ≥22). Start the
// relay first, on NODE not Bun (Bun's http upgrade swallows writes). It ships with
// seedchat rather than here — it is app-neutral infrastructure, and seed store's own
// default demo (p2p.html's Direct WebSocket mode) needs no signaling at all:
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

// CONTACT — the room's shared contact secret, 32 bytes of hex. A cohort in one room is
// symmetric: every node both accepts and dials, so the secret we demand of callers and
// the one we present when dialing are the same value. It gates the RELAY out too — the
// relay carries our signaling and therefore knows the room, but without this it cannot
// complete a handshake with us. Unset ⇒ open: anyone who finds the room is served.
//
//   CONTACT=$(openssl rand -hex 32) ROOM=my-room bun scripts/serve-rtc-holder.mjs
//
// A mismatched secret has NO error path — a gated peer refuses in silence (§12.6.2), so
// the symptom is peers that never link, not a message. Hence the hard check here.
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

// The transport is now a signed bundle: boot the shared shell with it admitted
// (the node's network standing), then put the WebRTC socket seam under the driver.
// This is a browser-edge-style node — no TCP/WS listeners; links arrive through the
// driver's openLink. The room's contact secret gates the ACCEPTING side, so it is
// the driver's (the shell's platform), and `peerContactFor` presents it when dialing.
const { bootTransportShell } = await import("../build/host/storage-node.js");
const { shell, transport } = await bootTransportShell({
  sodium, identity, timeoutMs: 6000, contactSecret,
  // No app config here: it travels with the storage bundle's own load, so it goes on
  // StorageNode.create below and this shell's transport guest never sees it.
});

let node = null;
const net = new RtcNetwork({
  driver: transport,
  rtcConfig: RTC_CONFIG,
  signaling: relaySignaling(url),
  // Symmetric room: the accepting side gate is the driver's contactSecret (above);
  // `peerContactFor` is what we present when dialing. One shared value, so both
  // sides are the same secret.
  peerContactFor: () => contactSecret,
  // Console side: drive the very same RtcNetwork as the browser, but with werift's
  // RTCPeerConnection (pure-JS, no native addon — bundles into `bun --compile`).
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

// Self-healing per spec §9: a holder runs repair on a jittered interval, so when a
// peer leaves and a chunk drops below its redundancy target, the surviving holders
// rebuild the missing blocks onto fresh peers — no button, no operator. Console
// holders are the long-lived peers the durable m leans on (§8), so this is exactly
// where the loop belongs. Tune with REPAIR_MS (ms); REPAIR_MS=0 turns it off.
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

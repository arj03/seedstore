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
// relay first, on NODE not Bun (Bun's http upgrade swallows writes):
//   npm run demo:relay        (= node ../../seedkernel/WASM/scripts/relay.mjs)

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

let node = null;
const net = new RtcNetwork({
  identity, sodium, rtcConfig: RTC_CONFIG,
  signaling: relaySignaling(url),
  // Console side: drive the very same RtcNetwork as the browser, but with werift's
  // RTCPeerConnection (pure-JS, no native addon — bundles into `bun --compile`).
  peerConnectionFactory: weriftPeerConnectionFactory(),
  onPeerUp: (pid) => { node?.addPeer(pid); console.log(`· peer linked: ${short(pid)} (in-channel AUTH; relay = signaling only)`); },
  onPeerDown: (pid) => { node?.removePeer(pid); console.log(`· peer dropped: ${short(pid)}`); },
});

// A real StorageNode serving HAVE / OFFER / STORE / FETCH over the P2P links. Default
// store.local is an in-RAM fs, read back through the node's FsBlobView.
node = await StorageNode.create({ network: net, sodium, ...wasm, identity, config, timeoutMs: 6000 });
net.join(); // announce into the room → present peers begin the WebRTC handshake

console.log(`\nseed store RTC holder ${short(node.peerId)} ready — handlers installed: ${node.handlersInstalled()}`);
console.log(`joined ${url}  (RS k=${config.k} m=${config.m}, ${config.blockSize} B blocks)`);
console.log(`open browser/p2p.html with the SAME relay + room "${room}" (or run more holders), then store a file.`);

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

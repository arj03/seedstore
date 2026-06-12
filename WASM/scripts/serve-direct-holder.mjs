// A console (Node/Bun) storage HOLDER reachable from a dial token ALONE — the
// server side of the browser/direct.html demo. Run several of these in separate
// terminals; each prints a dial token. Paste the tokens into direct.html, drop a
// file, and watch the blocks land here.
//
//   bun scripts/serve-direct-holder.mjs        (or: node …)
//     → prints  /ip4/<ip>/udp/<port>/certhash/<mb>/p2p/<pubkey>
//
// This is a real StorageNode on the seedkernel — not an echo pipe: it admits
// OFFER/STORE/FETCH, so a browser owner erasure-codes / replicates a file across
// every connected holder (README §6, §12). No relay is in the path — the browser
// fabricates this node's answer from the token's certhash.
//
// Bind a reachable address for off-box / cross-NAT browsers:
//   WD_HOST=0.0.0.0 WD_PORT=4001 WD_ADVERTISE=<your LAN/public IP> bun scripts/serve-direct-holder.mjs

import { networkInterfaces } from "node:os";

import { loadSodium, loadWasmBytes } from "../build/host/node.js";
import { StorageNode } from "../build/host/storage-node.js";
import { WebRtcDirectNetwork, makeCertKeys } from "seedkernel-wasm/webrtc-direct";
import { toHex } from "../build/host/util.js";

// A reachable IPv4 to ADVERTISE in the token. We bind 0.0.0.0 but a browser sends
// its STUN from a LAN/mDNS candidate, and a packet to 127.0.0.1 from the LAN IP
// never reaches a loopback-bound socket — so even same-machine browser↔console
// must use the real LAN IP, not loopback.
function lanIPv4() {
  for (const list of Object.values(networkInterfaces())) {
    for (const ni of list ?? []) {
      if (ni.family === "IPv4" && !ni.internal) return ni.address;
    }
  }
  return "127.0.0.1";
}

const short = (id) => id.slice(0, 12) + "…";

const sodium = await loadSodium();
const wasm = await loadWasmBytes();

const identity = (() => {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
})();
const keys = await makeCertKeys();

const net = new WebRtcDirectNetwork({
  identity, sodium, keys,
  listen: { host: process.env.WD_HOST ?? "0.0.0.0", port: Number(process.env.WD_PORT) || 0 },
  onPeerUp: (pid) => console.log(`· owner connected: ${short(pid)} (in-channel AUTH; certhash untrusted)`),
  onPeerDown: (pid) => console.log(`· owner disconnected: ${short(pid)}`),
});

// A real StorageNode: it serves the holder side of the protocol (HAVE/OFFER/STORE/
// FETCH) over the relay-less link. The default store is an in-RAM FsBlobStore.
const node = await StorageNode.create({ network: net, sodium, ...wasm, identity, timeoutMs: 5000 });

await net.listen();
const host = process.env.WD_ADVERTISE ?? lanIPv4();
const token = net.token(host);

console.log(`\nseed store holder ${short(node.peerId)} ready — handlers installed: ${node.handlersInstalled()}`);
console.log(`listening on 0.0.0.0:${net.token().match(/udp\/(\d+)/)[1]}, advertising ${host} (override with WD_ADVERTISE)`);
console.log("\npaste this dial token into direct.html (no relay needed):\n");
console.log("  " + token + "\n");
console.log("(Ctrl+C to stop)\n");

// Show blocks landing: poll the store for newly-held block ids. This is what makes
// the browser PUT visible — each terminal prints the chunks/replicas it received.
const known = new Set();
setInterval(() => {
  for (const id of node.store.list().map(toHex)) {
    if (!known.has(id)) {
      known.add(id);
      const { used } = node.store.stat();
      console.log(`  ✓ stored block ${short(id)}  (${known.size} held, ${(used / 1024).toFixed(1)} KB)`);
    }
  }
}, 300);

process.on("SIGINT", () => { node.close(); net.close(); process.exit(0); });

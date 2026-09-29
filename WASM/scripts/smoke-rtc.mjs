// Headless storage-over-WebRTC smoke: an owner + N holders, all werift-backed
// RtcNetworks, meet in a room on a seedrelay, link through it, move to real WebRTC
// (ICE -> DTLS -> SCTP on loopback) and PUT -> GET a file. Node-parity of the relay +
// STUN path browser/p2p.html runs: the same transport and StorageNode, with loopback
// candidates standing in for STUN-punched ones. It starts the sibling seedrelay
// checkout's server on a free port; RELAY= points it at a running one instead.
//
//   node scripts/smoke-rtc.mjs            (or: bun scripts/smoke-rtc.mjs)   HOLDERS=n

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { loadSodium, loadWasmBytes } from "../build/host/node.js";
import { StorageNode, bootTransportShell, netRelay } from "../build/host/storage-node.js";
import { MsgType, encodeHaveReq, decodeMask } from "../build/host/protocol.js";
import { bytesEqual } from "../build/host/util.js";
import { RtcNetwork } from "seedkernel-wasm/net-rtc";
import { NodeChannelFactory } from "seedkernel-wasm/net-node";
import { combineChannels } from "seedkernel-wasm/socket-seam";
import { weriftPeerConnectionFactory } from "./werift-pc.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function typed(type, data) {
  const out = new Uint8Array(1 + data.length);
  out[0] = type; out.set(data, 1);
  return out;
}
const HOLDERS = Number(process.env.HOLDERS) || 3;

// The relay: a running one at RELAY=ws://host:port, or the sibling seedrelay checkout's
// server, started here on a free port (seedrelay is a sibling checkout, as seedkernel is).
const ROOM = process.env.ROOM ?? "smoke-rtc-" + Math.random().toString(16).slice(2, 10);
let relayProcess = null;
async function startRelay() {
  if (process.env.RELAY) return process.env.RELAY.replace(/\/+$/, "");
  const server = fileURLToPath(new URL("../../../seedrelay/server.mjs", import.meta.url));
  if (!existsSync(server)) throw new Error(`no seedrelay at ${server}; check it out beside seedstore, or set RELAY`);
  relayProcess = spawn(process.execPath, [server, "0"], { stdio: ["ignore", "pipe", "inherit"] });
  return new Promise((resolve, reject) => {
    let out = "";
    relayProcess.stdout.on("data", (d) => {
      out += d;
      const m = /listening on (ws:\/\/[^/\s]+)\//.exec(out);
      if (m) resolve(m[1]);
    });
    relayProcess.once("exit", (code) => reject(new Error(`seedrelay exited ${code}`)));
  });
}
const RELAY = await startRelay();
const RELAY_URL = `${RELAY}/${encodeURIComponent(ROOM)}`;

const sodium = await loadSodium();
const wasm = await loadWasmBytes();
// Loopback host candidate so every pair connects with no STUN (the smoke is offline).
// Every peer connection is kept, to check the peers moved off the relay.
const werift = weriftPeerConnectionFactory({ iceAdditionalHostAddresses: ["127.0.0.1"] });
const pcs = [];
const pcFactory = (cfg) => { const pc = werift(cfg); pcs.push(pc); return pc; };
const connected = () => pcs.filter((pc) => pc.connectionState === "connected").length;
// Small file, replicated to every holder; 48 KiB stays under werift's 64 KiB
// data-channel reassembly cap, and maxMessageBytes holds batched OFFER/STORE/
// FETCH to the same ceiling.
const config = { k: 1, m: HOLDERS, blockSize: 48 * 1024, maxMessageBytes: 48 * 1024 };

// The room's shared, symmetric contact secret. Gating this smoke (rather than
// running it open) covers the credential path the real demos use too.
const CONTACT = process.env.CONTACT
  ? Uint8Array.from(process.env.CONTACT.match(/../g).map((b) => parseInt(b, 16)))
  : sodium.randombytes_buf(32);

// A node with no listeners, reachable only through the relay; storage geometry does not
// ride here: it goes on StorageNode.create, so the transport guest never sees it.
async function makeNode(contact = CONTACT) {
  const identity = (() => { const kp = sodium.crypto_sign_keypair(); return { publicKey: kp.publicKey, privateKey: kp.privateKey }; })();
  const entry = { node: null, runtime: null, net: null };
  entry.net = combineChannels(new NodeChannelFactory(), new RtcNetwork({ peerConnectionFactory: pcFactory }));
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
  for (const e of nodes) await netRelay(e.runtime.shell, RELAY_URL); // join the room: link through the relay, then WebRTC

  console.log(`booted owner + ${HOLDERS} holder(s); linking via relay ${RELAY} room ${ROOM}, then over WebRTC…`);

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
  // Every pair in the cohort moves to WebRTC: one connected peer connection at each end.
  const pairs = (HOLDERS + 1) * HOLDERS / 2;
  while (connected() < 2 * pairs && Date.now() - t0 < 30000) await sleep(150);
  console.log(`${connected() / 2}/${pairs} pairs moved to WebRTC`);

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
  const direct = connected() >= 2 * pairs;

  // Negative: a stranger in the room with the WRONG contact secret. Refusal is SILENT by
  // design (§12.6.2), so we assert "never links" within the same 30 s window.
  const stranger = await makeNode(sodium.randombytes_buf(32));
  nodes.push(stranger);
  stranger.node = await StorageNode.create({
    runtime: stranger.runtime, sodium, ...wasm, config, timeoutMs: 8000 });
  await netRelay(stranger.runtime.shell, RELAY_URL);
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
    ? `\ngate holds: a peer with the wrong contact secret linked 0 nodes in 30 s (refused in silence)`
    : `\nGATE FAILED: stranger linked ${strangerPeers.length}, owner links ${before} → ${ownerAfter}`);

  ok = roundTrip && onAll && gated && direct;
  console.log(ok
    ? `\nOK: file replicated to all ${HOLDERS} holders and retrieved; every pair met through the relay and moved to WebRTC`
    : `\nFAIL: roundTrip=${roundTrip}, onAllHolders=${onAll}, gated=${gated}, direct=${direct}`);
} catch (e) {
  console.error("\nFAILED:", e?.message ?? e);
} finally {
  for (const e of nodes) { try { e.node?.close(); } catch { /* ignore */ } try { e.net.close(); } catch { /* ignore */ } }
  relayProcess?.kill();
}
process.exit(ok ? 0 : 1);

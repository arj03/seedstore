// Smoke: a console OWNER dials a real `serve-direct-holder.mjs` over relay-less
// WebRTC-Direct and PUT→GETs a file through it. This is the node-side parity of
// what browser/direct.html does — BrowserWebRtcDirectNetwork (browser) mirrors
// WebRtcDirectNetwork (werift, used here), and both dial the same holder token —
// so a green smoke here means the holder + dial + StorageNode path is sound; only
// the platform RTCPeerConnection differs in the browser.
//
//   node scripts/smoke-direct.mjs     (or: bun scripts/smoke-direct.mjs)

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { loadSodium, loadWasmBytes } from "../build/host/node.js";
import { StorageNode } from "../build/host/storage-node.js";
import { WebRtcDirectNetwork } from "seedkernel-wasm/webrtc-direct";
import { MsgType, encodeHaveReq, decodeHaveRes } from "../build/host/protocol.js";
import { bytesEqual } from "../build/host/util.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const __dirname = dirname(fileURLToPath(import.meta.url));
const holderScript = join(__dirname, "serve-direct-holder.mjs");

const HOLDERS = Number(process.env.HOLDERS) || 3;

// Start `HOLDERS` holders (advertising loopback so a same-host node dialer reaches
// them) and collect each one's printed dial token.
function startHolder() {
  const proc = spawn(process.execPath, [holderScript], {
    env: { ...process.env, WD_HOST: "127.0.0.1", WD_ADVERTISE: "127.0.0.1" },
    stdio: ["ignore", "pipe", "inherit"],
  });
  const token = new Promise((resolve, reject) => {
    let buf = "";
    const to = setTimeout(() => reject(new Error("holder did not print a token in time")), 25000);
    proc.stdout.on("data", (d) => {
      buf += d.toString();
      const m = buf.match(/(\/ip4\/\S+\/p2p\/[0-9a-f]+)/);
      if (m) { clearTimeout(to); resolve(m[1]); }
    });
    proc.on("exit", (c) => reject(new Error("holder exited early, code " + c)));
  });
  return { proc, token };
}

const holders = Array.from({ length: HOLDERS }, startHolder);
const tokens = await Promise.all(holders.map((h) => h.token));
console.log(`started ${HOLDERS} holder(s); dialing all directly (no relay)…`);

const sodium = await loadSodium();
const wasm = await loadWasmBytes();
const identity = (() => { const kp = sodium.crypto_sign_keypair(); return { publicKey: kp.publicKey, privateKey: kp.privateKey }; })();
const net = new WebRtcDirectNetwork({ identity, sodium }); // dial-only, like the browser
const blockSize = Number(process.env.BS) || 48 * 1024;     // same default as direct.html
const config = { k: 1, m: 9, blockSize };                   // (werift caps a data-channel message at 65536 B)

let ok = false;
let owner = null;
try {
  owner = await StorageNode.create({ network: net, sodium, ...wasm, identity, config, timeoutMs: 5000 });
  for (const tok of tokens) owner.addPeer(await net.dial(tok));

  // Wait for each holder's reverse link to promote — a fixed sleep is flaky under
  // load (the WebRTC-Direct handshake can lag the owner-side dial). The holders are
  // separate processes, so we can't read their link maps the way net.test.mjs does;
  // instead poll the observable effect — a holder can only answer a HAVE once it has
  // authenticated the owner, so a returned response is the readiness signal.
  const probe = encodeHaveReq([new Uint8Array(32)]);
  const answers = async (peer) => {
    try { await owner.transport.request(peer, MsgType.HAVE, probe); return true; } catch { return false; }
  };
  const t0 = Date.now();
  let linksReady = false;
  while (Date.now() - t0 < 8000) {
    const up = await Promise.all(owner.cohortPeers().map(answers));
    if (up.length === HOLDERS && up.every(Boolean)) { linksReady = true; break; }
    await sleep(100);
  }
  if (!linksReady) throw new Error("holder reverse links did not promote in time");

  const data = new Uint8Array(1000);
  for (let i = 0; i < data.length; i++) data[i] = (i * 7 + 3) & 255;
  const r = await owner.put(data);
  console.log(`\nowner PUT ${data.length} B → ${r.replicated ? "replicated" : r.chunkCount + " RS chunk(s)"}, ${r.blockIds.length} block(s) placed across ${owner.cohortPeers().length} holder(s)`);

  // The same HAVE probe the browser runs: where did the file land?
  let onAll = true;
  for (const p of owner.cohortPeers()) {
    const res = await owner.transport.request(p, MsgType.HAVE, encodeHaveReq(r.blockIds));
    const held = decodeHaveRes(res).filter(Boolean).length;
    console.log(`  ${p.slice(0, 8)}…  ${held}/${r.blockIds.length} blocks`);
    if (held < r.blockIds.length) onAll = false;
  }

  const got = await owner.get(r.manifestId, r.key);
  const roundTrip = bytesEqual(got, data);
  ok = roundTrip && onAll;
  console.log(ok
    ? `\nOK — file replicated to all ${owner.cohortPeers().length} holders + retrieved through them (relay-less)`
    : `\nFAIL — roundTrip=${roundTrip}, onAllHolders=${onAll}`);
} catch (e) {
  console.error("\nFAILED:", e?.message ?? e);
} finally {
  owner?.close();
  net.close();
  for (const h of holders) h.proc.kill("SIGINT");
}
process.exit(ok ? 0 : 1);

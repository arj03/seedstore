// p2p-cli — a headless "p2p.html light": boots the SAME WsNetwork + StorageNode the
// browser demo uses (WS mode: 256 KiB blocks, 1 MiB batches, window 64) and drives
// PUT/GET against real `seedloader --ws-listen` nodes from the terminal, printing a
// wire-level timeline so a slow transfer can be attributed to a phase. All four are
// CUMULATIVE TIMESTAMPS — ms since the operation started, NOT durations — so read them
// as points on one clock and subtract to get a phase:
//
//   encode  = first STORE frame handed to a socket (guest CPU up to that point:
//             XChaCha20 + RS + BLAKE2b + Ed25519, plus the OFFER round trip)
//   queue   = LAST STORE frame handed to a socket (guest → socket handoff, incl.
//             the per-frame AEAD seal, whose cost is also totalled separately)
//   drain   = socket buffers last sampled non-empty (from ws.bufferedAmount)
//   settle  = last STORE response (holder verify/store + RTT)
//
// They are NOT ordered: `drain` BEFORE `queue` is the diagnostic that matters. It means
// the buffers ran dry while frames were still being handed over — the wire was STARVED
// and the link was waiting on us, not the reverse, with `peak buffered` pinning at ~one
// window's ciphertext.
//
// CORRECTED 2026-08-03 — that signature was long read as the streamed PUT's per-window
// OFFER→STORE→ack barrier idling the wire, i.e. an APP-side serialisation to be
// pipelined away. It is not. Raising --conns makes it vanish (drain<queue 3/3 runs at
// conns 2 → 0/3 at conns 16, peak buffered 42 MB → 0) while a window sweep at fixed
// conns moves throughput only ~6%. So the starved wire means we were handing frames to
// TOO FEW TCP FLOWS to absorb them, not that the window was too shallow: the buffers
// drain early because a loss-limited path's per-flow cwnd caps each socket, and the
// remaining frames then trickle. Read drain<queue as "add flows", not "deepen window".
//
// CAVEAT on the "MB/s upload" printed with drain: it divides ALL bulk bytes by
// (drain − encode). Whenever drain < queue that span did not carry all of them, so the
// figure OVER-REPORTS and must not be read as "the link is saturated". Sustained rate is
// the "N MB/s wire" on the headline PUT line, which uses the true total.
//
// Usage (Node ≥20 needs the WebSocket global):
//   node --experimental-websocket scripts/p2p-cli.mjs \
//     --peers "pk[.secret]@host:port,…" [--size 10] [--file path] \
//     [--puts 1] [--gets 1] [--author hex|none] [--block 256] [--batch 1024] [--window 64]
//
// The optional `.secret` is THAT PEER's 32-byte hex contact secret — what it demands of
// anyone dialing it (`seedloader --contact-secret <file of 64 hex chars>`, so the secret
// itself never appears in an argument list). It is the peer's credential,
// not ours: we are a dialer only, we never listen, so we have no inbound secret of our
// own. Omit it for an open peer. Get it wrong and the dial draws SILENCE rather than an
// error — a gated node refuses without answering, by design — so a peer that never
// reaches "link up" with a secret set is the symptom to look for.
//
// NOTE each PUT permanently costs every holder ~fileSize bytes of its §14 quota
// (content-addressed under a fresh random K, so re-putting the same file never
// dedups). Keep --puts low against live nodes.

import { readFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";

import { WsNetwork } from "seedkernel-wasm/net-ws";
import { createStorageNode, loadSodium, defaultConfig, PRODUCTION_BLOCK_SIZE, toHex } from "../build/host/node.js";
import { DEFAULT_QUOTA_BYTES } from "../build/host/core.js";

// ── args ─────────────────────────────────────────────────────────────────────
const args = new Map();
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  // A next token starting with "--" is read as the next flag, not this flag's value (so a
  // bare `--flag` reads as "true"). No knob here takes a "--"-leading value, so this is
  // fine; a genuinely-negative value would need to be spelled without a leading "--".
  if (a.startsWith("--")) args.set(a.slice(2), process.argv[i + 1] && !process.argv[i + 1].startsWith("--") ? process.argv[++i] : "true");
}
const num = (k, d) => (args.has(k) ? Number(args.get(k)) : d);
const peersArg = args.get("peers") ?? "";
const specs = peersArg.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
if (specs.length === 0) {
  console.error("need --peers \"pk[.secret]@host:port,…\"  (.secret = that peer's 32-byte hex contact secret, if it gates)");
  process.exit(1);
}
const puts = num("puts", 1);
const gets = num("gets", 1);
const sizeMB = num("size", 10);
// k + m = blocks per chunk = distinct holders (and TCP flows) a chunk spreads across.
// Default RS(1,1) = 2 flows; raise to match the cohort (e.g. --k 2 --m 2 across 4
// holders) to test whether more parallel upload flows beat the per-flow cwnd cap.
const kParam = num("k", 1);
const mParam = num("m", 1);
// Parallel connections per holder — bulk transfers stripe frames across them so N TCP
// flows fill a link one flow can't, once the window no longer idles the wire. Independent
// of k/m: raises flows-per-holder rather than holders-per-chunk. Holders must run the
// multi-link core. --conns 1 to A/B against a single flow.
//
// Default 16 (raised from 2 on 2026-08-03) — flow count, not load shape, is what the
// long-standing "app gets half the link" gap was made of. Interleaved sweep to the live
// iola holders: 4.9 / 5.8 / 6.8 / 9.0 / 10.4 / 11.7 / 13.3 MB/s wire at conns
// 1/2/4/8/16/32/64, monotonic, while --batch barely moved and moved the wrong way for a
// burstiness story (256 KiB was the WORST config, 4 MiB beat it). 50 MB A/B, conns 2 →
// 16: 6.5 → 10.3 MB/s wire, 15.4 → 9.7 s. See the long note in browser/p2p.html.
const connsN = num("conns", 16);
const blockSize = num("block", PRODUCTION_BLOCK_SIZE / 1024) * 1024;
const maxMessageBytes = num("batch", 1024) * 1024;
const windowN = num("window", 64);
// Streamed PUT/GET window (--wtarget MB): the host feeds the guest one chunk-aligned
// window at a time and awaits it fully before the next, so a small window idles the
// wire between windows on a fat link. Bigger windows = fewer barriers but a larger
// guest heap footprint (peak ≈ 3× window at RS(1,1)), so raise --heap (realm memory,
// MB) with it. Defaults 24/256 = the measured-best config; --wtarget 4 --heap 64
// reproduces the old barrier, --wtarget 0 uses the guest's built-in 4 MiB fallback.
const wtargetMB = num("wtarget", 24);
const heapMB = num("heap", 256);
const timeoutMs = num("timeout", 5000);

const hex = toHex; // toHex/fromHex come from the host build (node.js) — one hex pair, not a re-decl
const now = () => performance.now();
const MB = 1024 * 1024;
const mbs = (bytes, ms) => (bytes / MB / (ms / 1000)).toFixed(1);

// ── instrumentation ──────────────────────────────────────────────────────────
// One stats epoch per operation; the socket wrapper + sodium wrapper append into
// whichever epoch is current.
let epoch = null;
function newEpoch(name) {
  epoch = { name, t0: now(), sends: [], recvs: [], samples: [], seal: { n: 0, bytes: 0, ms: 0 }, open: { n: 0, bytes: 0, ms: 0 } };
  return epoch;
}

const sockets = [];
const wsFactory = (url) => {
  const ws = new WebSocket(url);
  sockets.push(ws);
  const raw = ws.send.bind(ws);
  ws.send = (data) => {
    const n = data.byteLength ?? data.length ?? 0;
    epoch?.sends.push({ t: now(), n });
    raw(data);
  };
  ws.addEventListener("message", (ev) => {
    const n = ev.data?.byteLength ?? 0;
    epoch?.recvs.push({ t: now(), n });
  });
  return ws;
};

// Sample total unsent bytes across sockets — the drain curve.
setInterval(() => {
  if (!epoch) return;
  let buf = 0;
  for (const ws of sockets) buf += ws.bufferedAmount ?? 0;
  epoch.samples.push({ t: now(), buf });
}, 10).unref();

function wrapTransportSodium(sodium) {
  const t = Object.create(sodium);
  t.crypto_aead_chacha20poly1305_ietf_encrypt = (m, ad, ns, npub, key) => {
    const t0 = now();
    const r = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(m, ad, ns, npub, key);
    if (epoch) { epoch.seal.n++; epoch.seal.bytes += m.length; epoch.seal.ms += now() - t0; }
    return r;
  };
  t.crypto_aead_chacha20poly1305_ietf_decrypt = (ns, c, ad, npub, key) => {
    const t0 = now();
    const r = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(ns, c, ad, npub, key);
    if (epoch) { epoch.open.n++; epoch.open.bytes += c.length; epoch.open.ms += now() - t0; }
    return r;
  };
  return t;
}

// Timeline report for one epoch. "big" frames are the bulk direction's payloads.
function report(e, totalMs, bulk /* "send" | "recv" */) {
  const rel = (t) => (t - e.t0).toFixed(0).padStart(6) + " ms";
  const big = (list) => list.filter((x) => x.n > 64 * 1024);
  const sum = (list) => list.reduce((a, x) => a + x.n, 0);
  const bigSends = big(e.sends), bigRecvs = big(e.recvs);
  console.log(`    frames: sent ${e.sends.length} (${(sum(e.sends) / MB).toFixed(1)} MB, ${bigSends.length} bulk), ` +
              `recv ${e.recvs.length} (${(sum(e.recvs) / MB).toFixed(1)} MB, ${bigRecvs.length} bulk)`);
  if (e.seal.n) console.log(`    seal (AEAD encrypt): ${e.seal.n} frames, ${(e.seal.bytes / MB).toFixed(1)} MB in ${e.seal.ms.toFixed(0)} ms (${mbs(e.seal.bytes, e.seal.ms)} MB/s)`);
  if (e.open.n) console.log(`    open (AEAD decrypt): ${e.open.n} frames, ${(e.open.bytes / MB).toFixed(1)} MB in ${e.open.ms.toFixed(0)} ms (${mbs(e.open.bytes, e.open.ms)} MB/s)`);
  if (bulk === "send" && bigSends.length) {
    const firstSend = bigSends[0].t, lastSend = bigSends[bigSends.length - 1].t;
    // Buffers-empty time: last sample with buf>0 before the final response.
    const nonEmpty = e.samples.filter((s) => s.buf > 0);
    const drained = nonEmpty.length ? nonEmpty[nonEmpty.length - 1].t : lastSend;
    const lastRecv = e.recvs.length ? e.recvs[e.recvs.length - 1].t : drained;
    const bulkBytes = sum(bigSends);
    console.log(`    encode  ${rel(firstSend)}  (start → first bulk send)`);
    console.log(`    queue   ${rel(lastSend)}  (all ${bigSends.length} bulk frames handed to sockets)`);
    console.log(`    drain   ${rel(drained)}  (socket buffers empty — ${mbs(bulkBytes, drained - firstSend)} MB/s upload)`);
    console.log(`    settle  ${rel(lastRecv)}  (last response)`);
    const peak = e.samples.reduce((a, s) => Math.max(a, s.buf), 0);
    console.log(`    peak buffered ${(peak / MB).toFixed(1)} MB across ${sockets.length} socket(s)`);
  }
  if (bulk === "recv" && bigRecvs.length) {
    const first = bigRecvs[0].t, last = bigRecvs[bigRecvs.length - 1].t;
    console.log(`    first bulk recv ${rel(first)}, last ${rel(last)} (${mbs(sum(bigRecvs), last - first)} MB/s download)`);
  }
  console.log(`    total ${totalMs.toFixed(0)} ms`);
}

// ── boot ─────────────────────────────────────────────────────────────────────
const sodium = await loadSodium();
const identity = sodium.crypto_sign_keypair();
console.log(`me: ${hex(identity.publicKey).slice(0, 16)}…`);

// The node loads the staged seedstore bundle (bundle/seedstore.skb, via loadWasmBytes
// inside createStorageNode) and derives its signing scope (§16) from that bundle's
// verified author. Every p2p-cli node running the same staged bundle therefore agrees on
// scope automatically — there is no separate --author to keep in sync any more.
console.log("signing scope: derived from the loaded seedstore bundle author");

// Base on defaultConfig so the fan-out/window defaults are all set (the §4.1 durability
// math — r = m+1, the low-water mark — is derived from k/m and from each
// chunk's signed descriptor, never config). The injection is total — a partial config
// would feed the strict guest an undefined knob. realmMemoryBytes is host-only (the
// QuickJS heap bound) — split out of the APP config, passed to the shell as the realm
// limit; the rest merges over the bundle's signed config into the guest's APP.
const config = { ...defaultConfig(kParam, mParam, blockSize), maxMessageBytes, fanoutWindow: windowN,
  ...(wtargetMB > 0 ? { windowTargetBytes: Math.round(wtargetMB * 1024 * 1024) } : {}),
  ...(heapMB > 0 ? { realmMemoryBytes: Math.round(heapMB * 1024 * 1024) } : {}) };
const { realmMemoryBytes, ...appConfig } = config;

// The transport is now a signed bundle: boot the shared shell with it admitted
// (the node's network standing), then put the WS socket seam under the driver.
// The wrapped sodium rides into the shell, so the record-layer AEAD costs are
// still instrumented. The geometry rides in as operator config (the shell merges
// it over the bundle's signed config into the guest's APP).
const peerUp = new Set();
let onQuorum = null;
const { bootTransportShell } = await import("../build/host/storage-node.js");
const { shell } = await bootTransportShell({
  sodium: wrapTransportSodium(sodium),
  identity,
  timeoutMs,
  config: { ...appConfig, quota: DEFAULT_QUOTA_BYTES },
  realmMemoryBytes,
  livePeers: () => [...peerUp],
});
const net = new WsNetwork({
  driver: shell.transport,
  webSocketFactory: wsFactory,
  connsPerPeer: connsN,
  onPeerUp: (pid) => { node?.addPeer(pid); peerUp.add(pid); console.log(`link up: ${pid.slice(0, 8)}…`); if (peerUp.size >= specs.length) onQuorum?.(); },
  onPeerDown: (pid) => { node?.removePeer(pid); peerUp.delete(pid); console.log(`link DOWN: ${pid.slice(0, 8)}…`); },
});

let node = await createStorageNode({ shell, identity, config, timeoutMs });
for (const pid of peerUp) node.addPeer(pid);
console.log(`node ready: RS(${kParam},${mParam}), ${blockSize / 1024} KiB blocks, batch ${Math.round(maxMessageBytes / 1024)} KiB, window ${windowN}, conns/peer ${connsN}, wtarget ${wtargetMB > 0 ? wtargetMB + " MB" : "4 MiB (default)"}, heap ${heapMB > 0 ? heapMB + " MB" : "64 MiB (default)"}, timeout ${timeoutMs} ms`);

for (const spec of specs) net.connect(spec);
await new Promise((res, rej) => {
  const t = setTimeout(() => rej(new Error(`only ${peerUp.size}/${specs.length} peers linked after 10 s`)), 10000);
  onQuorum = () => { clearTimeout(t); res(); };
  if (peerUp.size >= specs.length) onQuorum();
});
console.log(`${peerUp.size} peer(s) linked\n`);

// Pay the codec + crypto cold-JIT tax now (throwaway encode/decode, no network), so
// the first measured PUT reflects steady-state encode, not V8 realm warmup.
const tw = now();
await node.warm();
console.log(`node warmed in ${(now() - tw).toFixed(0)} ms\n`);

// ── data ─────────────────────────────────────────────────────────────────────
const data = args.has("file")
  ? new Uint8Array(await readFile(args.get("file")))
  : new Uint8Array(randomBytes(Math.round(sizeMB * MB)));
console.log(`payload: ${data.length} B (${(data.length / MB).toFixed(1)} MB)${args.has("file") ? " from " + args.get("file") : " random"}`);

// ── PUT / GET rounds ─────────────────────────────────────────────────────────
const tokens = [];
for (let i = 0; i < puts; i++) {
  const e = newEpoch(`put${i}`);
  const t0 = now();
  try {
    const r = await node.put(data);
    const ms = now() - t0;
    tokens.push(r);
    const fileMBn = data.length / MB;
    const wireMBn = fileMBn * (node.config.k + node.config.m) / node.config.k;
    console.log(`PUT #${i + 1}: ${ms.toFixed(0)} ms — ${mbs(data.length, ms)} MB/s file, ${mbs(wireMBn * MB, ms)} MB/s wire (${r.chunkCount} chunks)`);
    if (r.replicasLanded < r.replicasIntended) {
      console.log(`  ⚠️  UNDER-REPLICATED: ${r.replicasLanded}/${r.replicasIntended} replicas landed — a reachable holder declined (full/quota) or the cohort is smaller than k+m. The file met the ≥k floor but has less redundancy than configured.`);
    }
    report(e, ms, "send");
  } catch (err) {
    console.log(`PUT #${i + 1} FAILED after ${(now() - t0).toFixed(0)} ms: ${err?.message ?? err}`);
    report(e, now() - t0, "send");
    break;
  }
  epoch = null;
}

for (let i = 0; i < gets && tokens.length; i++) {
  const tok = tokens[i % tokens.length];
  const e = newEpoch(`get${i}`);
  const t0 = now();
  try {
    const out = await node.get(tok.root, tok.key);
    const ms = now() - t0;
    const ok = out.length === data.length;
    console.log(`GET #${i + 1}: ${ms.toFixed(0)} ms — ${mbs(out.length, ms)} MB/s ${ok ? "(bytes match)" : "(LENGTH MISMATCH!)"}`);
    report(e, ms, "recv");
  } catch (err) {
    console.log(`GET #${i + 1} FAILED after ${(now() - t0).toFixed(0)} ms: ${err?.message ?? err}`);
    report(e, now() - t0, "recv");
  }
  epoch = null;
}

node.close();
process.exit(0);

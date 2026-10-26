// The Tier-2 guest: the whole storage protocol (SPEC §6/§7/§9) as zero-authority
// JS running inside the QuickJS realm (§2.1) — placement, k-of-n, admission, wire
// format, and repair. Reached only through `host.call(name, bytes)` (seedkernel §12.2),
// whose every name answers a Promise: module and `_net` calls settle on a later turn,
// crypto, fs and node calls within the same one.
//
// Both roles (initiator and holder) share this one realm/entrypoint (`handle`,
// split by `callerOf`/`readOp`); the realm's per-realm FIFO (seedkernel
// realm-queue.ts) keeps them from interleaving.
//
// A plain script (no imports/exports/ambient authority), prepended with `APP`/`LOCAL`
// config and the realm preamble by the host before running. It runs in a seedkernel
// QuickJS realm, the same engine on every target.

"use strict";

// ── byte helpers ────────────────────────────────────────────────────────────
// toHex/fromHex/bytesEqual/concatBytes/writeU32BE/readU32BE/writeU64BE/callerOf/readOp/writeOp are stitched
// in from host/util.ts by scripts/build-guest.mjs. Short local aliases for this body.
const concat = concatBytes, wU32 = writeU32BE, rU32 = readU32BE;
// Views, not copies: every consumer of a block (a frame, a hash or AEAD request) copies it anyway.
function splitBlocks(buf, blockSize) {
  const out = [];
  for (let o = 0; o < buf.length; o += blockSize) out.push(buf.subarray(o, o + blockSize));
  return out;
}
function padTo(buf, len) {
  if (buf.length === len) return buf;
  const out = new Uint8Array(len);
  out.set(buf.subarray(0, Math.min(buf.length, len)));
  return out;
}

const EMPTY = new Uint8Array(0);

// fs keys are ASCII (hex + a short suffix); QuickJS has no TextEncoder, so map
// chars to bytes by hand, the same way toHex/fromHex avoid Buffer.
function strBytes(s) { const o = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i) & 255; return o; }
function bytesToStr(b) { let s = ""; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return s; }

// ── the guest seam: storage policy over GENERIC host names ────────────────
// Thin wrappers over the seam's application-neutral names (crypto/fs/module/
// clock/node, seedkernel host/guest-seam.ts). All storage STRUCTURE — nonce
// convention, signed-descriptor envelope, wire format, store layout — lives here,
// never in the host.

// The op bytes of the codec module (the guest owns its ABI). The reputation module's
// op bytes + request framing (REP_OBSERVE/REP_SCORE, encodeScoreReq/encodeObserveReq)
// come from the SHARED host/reputation-core.ts, stitched in ahead of this body — the same
// framing StorageNode.score uses host-side, so the two agree by construction.
const CODEC_ENCODE = 1, CODEC_DECODE = 2;     // assembly/codec/index.ts
// Message types (MsgType), their entry framing, and the protocol id (STORAGE_PROTO,
// which the bundle manifest's `protocols` claims) come from host/protocol.ts; the
// `<hex>.rec` record layout from host/store-record.ts.
const NET_PROTO = strBytes(STORAGE_PROTO);
// The logical names this app's own modules are installed under. The guest calls them
// by the logical name from its manifest, straight through `host.call` — a name this
// realm did not declare as a local service, and that is not a host method (`service/call`),
// is this app's module (seedkernel §12.2). The seam resolves it against this app's own
// map, so no other app's modules are nameable from here.
const CODEC_NAME = "codec";
const REP_NAME = "reputation";

// ── request statistics (§18, for the latency/bench harnesses) ────────────────
// The host has no host-side inbound seam, so these counters live here: `netSend`
// counts+peaks outbound requests, `handle` counts+times inbound holder work.
// Read and cleared by the Op.STATS local op. Indexed by MsgType byte (256 slots).
const statsSent = new Uint32Array(256);
const statsInFlight = new Uint32Array(256);
const statsPeak = new Uint32Array(256);
const statsRecv = new Uint32Array(256);
const statsRecvBytes = new Uint32Array(256);
const statsRecvMs = new Float64Array(256);
function encodeStats() {
  const out = new Uint8Array(STATS_TYPES.length * STATS_RECORD_BYTES);
  for (let i = 0; i < STATS_TYPES.length; i++) {
    const t = STATS_TYPES[i];
    const off = i * STATS_RECORD_BYTES;
    wU32(out, off, statsSent[t]);
    wU32(out, off + 4, statsPeak[t]);
    wU32(out, off + 8, statsRecv[t]);
    wU32(out, off + 12, statsRecvBytes[t]);
    new DataView(out.buffer, off + 16, 8).setFloat64(0, statsRecvMs[t], true);
    statsSent[t] = statsPeak[t] = statsInFlight[t] = statsRecv[t] = statsRecvBytes[t] = 0;
    statsRecvMs[t] = 0;
  }
  return out;
}

// `APP` (author-signed) and `LOCAL` (this install) merge with LOCAL winning
// (seedkernel §12.4, ABI 8) — mixed cohort geometry is fine since reads use the
// DESCRIPTOR's, not CFG's (§4.1/§4.3). `quota` is deliberately not merged in here;
// quota() reads LOCAL alone so an author can't sign one. StorageNode.config is the
// same merge over the same LOCAL (host/storage-node.ts).
const CFG = { ...APP, ...LOCAL };

// ── the realm's host-call budget, as one ledger ──
// The host refuses a call past its advertised per-realm ceilings (HOST) outright, failing
// the PUT or GET, so every call takes its charge here first and concurrent phases share the
// budget. FIFO within a class. FOREGROUND (crypto, codec, OFFER, HAVE) goes before BULK
// (STORE, FETCH), which always leaves room for foreground's largest call. HOLDER work (a
// peer's message to `handle`) has its own share: behind our own traffic, two nodes storing
// to each other would wait on each other until their requests time out.
const FOREGROUND = 0, BULK = 1, HOLDER = 2;
const hostBudget = (() => {
  const advertised = (key) => {
    const v = typeof HOST === "object" && HOST ? HOST[key] : 0;
    return typeof v === "number" && v > 0 ? v : Infinity;
  };
  // Read on first use: the charge sizes below are declared further down this file.
  let callCap = 0, byteCap = 0, bulkCallCap = 0, bulkByteCap = 0, holderCallCap = 0, holderByteCap = 0;
  let calls = 0, bytes = 0, bulkCalls = 0, bulkBytes = 0, holderCalls = 0, holderBytes = 0;
  const queues = [[], [], []]; // by class; foreground is admitted before bulk
  const init = () => {
    const allCalls = advertised("maxOutstandingHostCalls"), allBytes = advertised("maxOutstandingHostCallBytes");
    holderCallCap = Math.max(1, Math.min(64, Math.floor(allCalls / 4)));
    holderByteCap = Math.min(allBytes, maxCallChargeBytes());
    // The initiator gets the rest, less the call whose answer resumed the continuation now
    // spending (the host releases it only after that continuation runs).
    callCap = Math.max(1, allCalls - 1 - holderCallCap);
    byteCap = allBytes - maxCallChargeBytes() - holderByteCap;
    bulkCallCap = Math.max(1, callCap - (CFG.k + CFG.m + 2));
    bulkByteCap = byteCap - maxCallChargeBytes();
  };
  // A charge over the whole cap still runs once nothing else of its class holds the ledger.
  const fits = (n, cls) => {
    if (callCap === 0) init();
    if (cls === HOLDER) return holderCalls < holderCallCap && (holderBytes === 0 || holderBytes + n <= holderByteCap);
    if (calls >= callCap || (bytes > 0 && bytes + n > byteCap)) return false;
    return cls !== BULK || (bulkCalls < bulkCallCap && (bulkBytes === 0 || bulkBytes + n <= bulkByteCap));
  };
  const take = (n, cls, sign) => {
    if (cls === HOLDER) { holderCalls += sign; holderBytes += sign * n; return; }
    calls += sign; bytes += sign * n;
    if (cls === BULK) { bulkCalls += sign; bulkBytes += sign * n; }
  };
  const admit = () => {
    for (const q of queues) {
      while (q.length > 0 && fits(q[0].n, q[0].cls)) {
        const w = q.shift();
        take(w.n, w.cls, 1);
        w.go();
      }
    }
  };
  return async function run(n, fn, cls = FOREGROUND) {
    const q = queues[cls];
    if (q.length > 0 || (cls === BULK && queues[FOREGROUND].length > 0) || !fits(n, cls)) {
      await new Promise((go) => q.push({ n, cls, go }));
    } else {
      take(n, cls, 1);
    }
    try { return await fn(); }
    finally { take(n, cls, -1); admit(); }
  };
})();
// One host call, charged its request plus the answer it expects: `call` for the
// initiator's, `holderCall` for the holder's. Helpers both roles share take one as `via`.
function call(name, payload, answerBytes = MSG_ENVELOPE_BYTES) {
  return hostBudget(payload.length + answerBytes, () => host.call(name, payload));
}
function holderCall(name, payload, answerBytes = MSG_ENVELOPE_BYTES) {
  return hostBudget(payload.length + answerBytes, () => host.call(name, payload), HOLDER);
}

// ── crypto primitives + storage framing ──
// Pure transforms reach the host under the `crypto/` prefix (seedkernel §12.2):
// BLAKE2b-256 for block-ids and ChaCha20-Poly1305 for at-rest encryption.
// node/sign and node/verify apply the scoped `DOMAIN_guest ‖ scope` prefix on the
// host side — the guest never holds or reconstructs it. Every seam name answers a
// Promise, so every helper here is awaited by its callers.
// `crypto/blake2b` takes [outLen][keyLen][key][msg]; block-ids are its unkeyed 32 bytes.
function blake2b(req, via) { return via("crypto/blake2b", req, 32); }
// The request is built around the block in one buffer: blockHashInput leaves room for the head.
function blockHash(d, bytes, via) {
  const req = blockHashInput(d.authorPk, bytes, 2);
  req[0] = 32;
  return blake2b(req, via);
}
const P_SEAL = "crypto/chacha20poly1305-ietf/seal";
const P_OPEN = "crypto/chacha20poly1305-ietf/open";
// The AEAD names take [npub 12][key 32][adLen u32][ad][bytes]; chunks bind no associated
// data (the nonce already names level and index), so adLen stays four zero bytes. The
// message's pieces are written straight in, so they need no join of their own.
const AEAD_HEAD = 12 + 32 + 4;
function aeadRequest(K, level, index, parts) {
  let len = AEAD_HEAD;
  for (const p of parts) len += p.length;
  const req = new Uint8Array(len);
  req.set(chunkNonce(level, index), 0);
  req.set(K, 12);
  let o = AEAD_HEAD;
  for (const p of parts) { req.set(p, o); o += p.length; }
  return req;
}
function randomKey() { const n = new Uint8Array(4); wU32(n, 0, 32); return call("crypto/random", n, 32); }
// This node's channel public key, as the host hands it over in `HOST` (seedkernel §12.4).
// Read at the call rather than at load, so the unit tests can evaluate this file bare.
function identity() { return fromHex(HOST.identity); }
function myPeer() { return HOST.identity; }
// The nonce (chunkNonce, LEVEL_BODY) comes from host/descriptor-core.ts.
// The host's seal result is [ciphertext][tag 16]. Keep the tag in the signed
// descriptor so the ciphertext remains exactly k·blockSize for systematic RS.
// The ciphertext is a view of the answer; the tag is copied out, since the signed
// descriptor keeps it long after the blocks are placed.
async function encrypt(K, level, index, msg) {
  const sealed = await call(P_SEAL, aeadRequest(K, level, index, [msg]), msg.length + AUTH_TAG_LEN);
  if (sealed.length !== msg.length + AUTH_TAG_LEN) throw new Error("encrypt: unexpected ChaCha20-Poly1305 output length");
  return { ciphertext: sealed.subarray(0, msg.length), authTag: sealed.slice(msg.length) };
}
// `ctParts` is the chunk's ciphertext as its blocks, in order (assembleChunk).
async function decrypt(K, level, index, ctParts, authTag) {
  if (!authTag || authTag.length !== AUTH_TAG_LEN) throw new Error("get: malformed ciphertext authentication tag");
  const req = aeadRequest(K, level, index, [...ctParts, authTag]);
  const ctLen = req.length - AEAD_HEAD - AUTH_TAG_LEN;
  const opened = await call(P_OPEN, req, 1 + ctLen);
  if (opened.length !== ctLen + 1 || opened[0] !== 1) throw new Error("get: ciphertext authentication failed");
  return opened.subarray(1);
}
// Signed chunk descriptor envelope: [authorPk 32][sig 64][core] (§4.3, §16).
// node/sign applies the scoped prefix and returns just the signature; the stored
// envelope carries only [pk][sig][core] — the prefix is preimage-only, never sent.
async function signCore(core) {
  return concat([identity(), await call("node/sign", core), core]);
}
async function verifyEnv(env, via) {
  // The seam's argument IS the envelope — [pk 32][sig 64][msg] concatenated is
  // `env` itself, so it is passed whole, uncopied.
  const v = await via("node/verify", env, 1);
  return v[0] === 1;
}

// ── codec + reputation ──
// Both are ordinary `host.call`s (module name IS the seam's name arg, no header to
// build). A module call settles on a later turn, so encode/decode and their callers
// (encodeChunk, assembleChunk, the ranker) are async in turn.
async function rsEncode(k, m, blockSize, dataBlocks) {
  const head = new Uint8Array(7);
  head[0] = CODEC_ENCODE; head[1] = k; head[2] = m; wU32(head, 3, blockSize);
  const parity = splitBlocks(await call(CODEC_NAME, concat([head, ...dataBlocks]), m * blockSize), blockSize);
  // A trapped or over-length codec rejects at the seam (seedkernel §12.2); this catches
  // the well-formed answer of the wrong shape, where the cause is, rather than as a
  // far-away "blockIds.length must be k+m" error or a chunk silently signed wrong.
  if (parity.length !== m) {
    throw new Error("rsEncode: codec returned " + parity.length + " parity blocks, expected " + m +
      " — chunk (k=" + k + " × blockSize=" + blockSize + ") likely exceeds the codec module's scratch");
  }
  return parity;
}
async function rsDecode(k, m, blockSize, present) {
  // Callers (assembleChunk, heal) already gate on present.length >= k, but
  // guard the codec seam itself so a short set is a clean throw, never a silently
  // truncated decode request (head[7] = use.length under k → garbage out).
  if (present.length < k) throw new Error("rsDecode: need at least k blocks to reconstruct");
  const use = present.slice(0, k);
  const head = new Uint8Array(8);
  head[0] = CODEC_DECODE; head[1] = k; head[2] = m; wU32(head, 3, blockSize); head[7] = use.length;
  const idx = new Uint8Array(use.length);
  for (let i = 0; i < use.length; i++) idx[i] = use[i].index;
  const data = splitBlocks(await call(CODEC_NAME, concat([head, idx, ...use.map((p) => p.bytes)]), k * blockSize), blockSize);
  // A short answer would otherwise silently reassemble from fewer blocks than the chunk
  // has — nothing on the read path re-verifies the codec's output (§4.2 only checks
  // inputs). Must error.
  if (data.length !== k) {
    throw new Error("rsDecode: codec returned " + data.length + " blocks, expected " + k +
      " — chunk (k=" + k + " × blockSize=" + blockSize + ") likely exceeds the codec module's scratch");
  }
  return data;
}
// The codec's limits, from its OP_INFO: [version][poly lo][poly hi][max k][max m][max io u32 BE],
// max io being the most one request or answer may carry. Asked once, by the first PUT that codes,
// so a geometry the codec cannot take fails before a byte moves rather than on a short answer.
const CODEC_INFO = 0;
let codecInfo = null;
async function assertCodecFits(k, m, blockSize) {
  if (!codecInfo) codecInfo = call(CODEC_NAME, Uint8Array.of(CODEC_INFO), 16).catch((e) => { codecInfo = null; throw e; });
  const info = await codecInfo;
  const maxIo = rU32(info, 5);
  // The largest request is a decode of k blocks; the largest answer is k data or m parity blocks.
  if (k > info[3] || m > info[4] || 8 + k + k * blockSize > maxIo || Math.max(k, m) * blockSize > maxIo) {
    throw new Error("put: a chunk of RS(" + k + "," + m + ") × " + blockSize + " B blocks exceeds the codec module (k ≤ " +
      info[3] + ", m ≤ " + info[4] + ", " + maxIo + " B per call) — lower blockSize or k");
  }
}

// Reputation accumulators (module is a pure transform; callers hold state), one per
// (group, peer): goodwill a peer earns serving one group's chunks counts in that group
// only (§13). repKey → {serve, miss, last}. Entries are created only by repObserve — a real
// witnessed event (§8) — never by a bare score query, which must stay side-effect-free.
const peerReps = new Map();
function repKey(group, peerHex) { return group + "/" + peerHex; }

const ZERO_REP = { serve: 0, miss: 0, last: 0 };

async function repScore(group, peerPk, t, via = call) {
  return decodeScoreResp(await repScoreBytes(group, peerPk, t, via));
}
// Call the reputation module's SCORE op with the peer's accumulator at time t, or the
// zero accumulator for a peer never observed. Read-only: never touches peerReps.
// A score is advisory — it orders peers, it does not decide correctness — so a module
// failure (seedkernel §12.2) answers as an unscored peer rather than failing the PUT or
// GET that was only ranking. That translation is this layer's policy, not the seam's.
async function repScoreBytes(group, peerPk, t, via = call) {
  const rep = peerReps.get(repKey(group, toHex(peerPk))) ?? ZERO_REP;
  const req = encodeScoreReq(rep.serve, rep.miss, rep.last, t);
  return via(REP_NAME, req).catch(() => EMPTY);
}

// Record one batch's witnessed passes/misses for a peer, awaiting the module call so
// the Map update actually lands (this is not fire-and-forget). Counts, not one call
// per block: a fan-out's blocks are verified independently but share an observation
// time, and a call apiece would spend the realm's outstanding-call budget on scoring.
async function repObserve(group, peerPk, t, passes, misses) {
  if (passes + misses === 0) return;
  const key = repKey(group, toHex(peerPk));
  let rep = peerReps.get(key);
  if (rep === undefined) {
    pruneStalePeers(peerReps, t);
    rep = { ...ZERO_REP };
    peerReps.set(key, rep);
  }
  const req = encodeObserveReq(rep.serve, rep.miss, rep.last, t, passes, misses);
  try {
    const resp = await call(REP_NAME, req);
    // A module that rejects its input answers 0 bytes, and the seam delivers that as a
    // VALUE (seedkernel §12.2) — decoding it would zero the accumulator, so an
    // unreadable answer must leave a peer's standing alone rather than erase it.
    if (resp.length < 32) return;
    const updated = decodeObserveResp(resp);
    rep.serve = updated.serve;
    rep.miss = updated.miss;
    rep.last = updated.last;
  } catch (e) {
    // Advisory scoring must not fail a transfer when its module is unavailable.
  }
}

// Tally a fetch round's witnessed outcomes per peer, then settle each peer's standing with
// ONE call after the round. Scoring is advisory (§13) — it ranks peers, it must never pace a
// transfer — so it stays off the per-result path: awaiting a module round trip between FETCH
// results puts the reputation worker in series with the wire.
function repTally() {
  const per = new Map(); // repKey → {group, peerHex, passes, misses}
  return {
    note(group, peerHex, passes, misses) {
      if (passes + misses === 0) return;
      const key = repKey(group, peerHex);
      let e = per.get(key);
      if (!e) per.set(key, (e = { group, peerHex, passes: 0, misses: 0 }));
      e.passes += passes; e.misses += misses;
    },
    // One clock read for the round: every outcome in it shares an observation time anyway.
    // Prune once and seat the round's new peers first, so the parallel observations below
    // find their entries rather than each pruning the whole map again.
    async settle() {
      if (per.size === 0) return;
      const t = Date.now();
      const round = [...per];
      per.clear();
      if (round.some(([key]) => !peerReps.has(key))) {
        pruneStalePeers(peerReps, t);
        for (const [key] of round) if (!peerReps.has(key)) peerReps.set(key, { ...ZERO_REP });
      }
      await Promise.all(round.map(([, e]) => repObserve(e.group, fromHex(e.peerHex), t, e.passes, e.misses)));
    },
  };
}

// ── the ledger (§13) ─────────────────────────────────────────────────────────
// Kept per (group, peer), from what this node witnesses itself:
//   reliability — verified fetches passed against missed (peerReps, above);
//   availability — repair passes the peer was linked at against passes it was not;
//   holdings — bytes the peer verifiably holds for this node's own files, from auditing them.
// Reliability × availability ranks peers for placement, repair and reads; availability
// decides which copies a chunk can count on; holdings set the allowance an author earns.
const availReps = new Map(); // repKey → { serve: passes present, miss: passes absent, last }
// The share of recent passes a peer was linked at. Both counts decay from the same moment,
// so their ratio needs no decay of its own. A peer not yet observed counts as available.
function availability(group, peerHex) {
  const r = availReps.get(repKey(group, peerHex));
  return r !== undefined && r.serve + r.miss > 0 ? r.serve / (r.serve + r.miss) : 1;
}
// Online often enough that a copy on it counts towards its chunk's health (§8, §9).
const DEPENDABLE = 0.5;
function dependable(group, peerHex) { return peerHex === myPeer() || availability(group, peerHex) >= DEPENDABLE; }
// One observation per group member per repair pass: is it linked now.
async function observeAvailability() {
  const linked = new Set(decodePeers(await netOp("peers", EMPTY, call)));
  const me = myPeer(), t = Date.now(), work = [];
  for (const [group, members] of groups) for (const p of members) if (p !== me) work.push(availObserve(group, p, t, linked.has(p)));
  await Promise.all(work);
}
async function availObserve(group, peerHex, t, present) {
  const key = repKey(group, peerHex);
  let rep = availReps.get(key);
  if (rep === undefined) {
    pruneStalePeers(availReps, t);
    rep = { ...ZERO_REP };
    availReps.set(key, rep);
  }
  try {
    const resp = await call(REP_NAME, encodeObserveReq(rep.serve, rep.miss, rep.last, t, present ? 1 : 0, present ? 0 : 1));
    if (resp.length < 32) return;
    const u = decodeObserveResp(resp);
    rep.serve = u.serve; rep.miss = u.miss; rep.last = u.last;
  } catch { /* advisory, as reliability is */ }
}
// Holdings: own chunk key → { group, peers: Map(peerHex → bytes) } from that chunk's last
// audit, and their sum per (group, peer) in heldForMe.
const ownHoldings = new Map();
const heldForMe = new Map(); // repKey → bytes
function recordHoldings(key, d, live) {
  const old = ownHoldings.get(key);
  if (old) for (const [p, n] of old.peers) heldForMe.set(repKey(old.group, p), heldForMe.get(repKey(old.group, p)) - n);
  const peers = new Map(), me = myPeer();
  for (const set of live.values()) for (const p of set) if (p !== me) peers.set(p, (peers.get(p) ?? 0) + d.blockSize);
  ownHoldings.set(key, { group: d.group, peers });
  for (const [p, n] of peers) heldForMe.set(repKey(d.group, p), (heldForMe.get(repKey(d.group, p)) ?? 0) + n);
}
function heldFor(group, peerHex) { return heldForMe.get(repKey(group, peerHex)) ?? 0; }

// ── local store over fs ─────────────────────────────────────────────────────
// One <hex>.rec per block (host/store-record.ts). The index of what is held is the
// holder's, so its fs reads and writes take the holder's share of the budget.
async function fsGet(keyStr, via, answerBytes = CFG.blockSize + 1024) {
  const r = await via("fs/get", strBytes(keyStr), answerBytes);
  return r[0] === 1 ? r.subarray(1) : null;
}
async function storeHas(id) { await ensureStoreIndex(); return heldBlocks.has(toHex(id)); }
async function storeGet(id, via) { return decodeStoreRecord(await fsGet(toHex(id) + STORE_REC, via)); }
async function storeGetBytes(id, via) { const r = await storeGet(id, via); return r ? r.bytes : null; }
async function storeGetDescriptor(id, via) { const r = await storeGet(id, via); return r ? r.descriptor : null; }
async function storeKeys() {
  const r = await holderCall("fs/list", EMPTY), out = [];
  let o = 0; const n = rU32(r, o); o += 4;
  for (let i = 0; i < n; i++) {
    const klen = rU32(r, o); o += 4;
    const key = bytesToStr(r.slice(o, o + klen)); o += klen;
    out.push(key);
  }
  return out;
}
async function storeList() { await ensureStoreIndex(); return [...heldBlocks.keys()].map(fromHex); }

// ── the network: one local service name, two ops ─────────────────────────────
// The network is a bundle (the transport) claiming `_net` under its `services`
// list (seedkernel §12.10) — a co-resident guest's to reach, never a peer's —
// reached via `host.call("_net", …)`. The host prepends this app's 32-byte key
// as caller so the transport can attribute the request.
// Wire: `[opLen u8][op][args]`. This app uses two ops, `send` and `peers`; both
// answer on a later turn, so both are awaited.
const NET_ID = "_net";
// A rejected cross-realm call (no transport loaded, or torn down mid-flight) maps to
// the empty answer - same shape as an unreachable peer - so a PUT reports "no holder
// answered" instead of an uncaught rejection out of a fan-out.
function netOp(op, args, via) { return via(NET_ID, writeOp(op, args)).then((r) => r, () => EMPTY); } // seedkernel op-frame (content) - this app's own framing

// ── peers + ranking by reciprocity (§13) ──
// The `peers` answer is the raw 32-byte keys back to back — the peers the transport holds at
// least one AUTHENTICATED link to. There is no count header: the length says how many.
function decodePeers(r) {
  const out = [];
  for (let o = 0; o + 32 <= r.length; o += 32) out.push(toHex(r.slice(o, o + 32)));
  return out;
}
// ── the roster (§5.1) ──
// This node's groups: name → Set of member hex, from LOCAL at boot and replaced by
// Op.GROUPS. The cohort is every member of every group. A link alone admits nothing: a peer
// outside the roster is answered nothing, and a chunk is stored only among its own group.
let groups = new Map();
let rosterMembers = new Set();
function setRoster(map) {
  groups = map;
  rosterMembers = new Set();
  for (const members of map.values()) for (const m of members) rosterMembers.add(m);
}
setRoster(new Map(Object.entries(LOCAL.groups ?? {}).map(([name, members]) => [name, new Set(members)])));
function inGroup(group, peerHex) { const g = groups.get(group); return g !== undefined && g.has(peerHex); }
// The linked peers in the roster: everyone a broadcast (have/want) may ask.
async function cohortPeers(via) { return decodePeers(await netOp("peers", EMPTY, via)).filter((p) => rosterMembers.has(p)); }
// The linked members of one group: everyone a chunk of that group may be placed on.
async function groupPeers(group, via) { return (await cohortPeers(via)).filter((p) => inGroup(group, p)); }
// A ranker (§13): orders peers best-first by their standing in `group`, reliability times
// availability, so a steady peer comes before one often offline. `makeRanker` memoizes
// each distinct peer's score (by PROMISE, not settled value, so concurrent lookups
// share one in-flight call) for its lifetime, so ranking overlapping holder subsets
// across a round costs one bridge crossing per peer, not one per (peer, id).
// `inStanding` drops the peers that fail more checks than they pass while any peer does not,
// for a caller that spreads work over the list instead of taking its head (gatherBlocks).
async function makeRanker(group) {
  const t = Date.now();
  const cache = new Map(); // peerHex → Promise<standing>
  const standing = async (p) => { const rel = await repScore(group, fromHex(p), t); return rel < 0 ? rel : (1 + rel) * availability(group, p); };
  const scoreOf = (p) => { let s = cache.get(p); if (s === undefined) cache.set(p, s = standing(p)); return s; };
  return async (peers, inStanding = false) => {
    if (peers.length === 0) return [];
    const scored = (await Promise.all(peers.map(async (p) => ({ p, s: await scoreOf(p) })))).sort((a, b) => b.s - a.s);
    const kept = inStanding && scored[0].s >= 0 ? scored.filter((x) => x.s >= 0) : scored;
    return kept.map((x) => x.p);
  };
}
// One-shot ranker for callers that rank a single list (its own fresh cache).
async function rank(peers, group) { return (await makeRanker(group))(peers); }

// ── net (request/response over the transport; wire format here) ──
// One round trip via the transport's `send` op:
//   [noReply u8][to blob][proto blob][payload blob]
// No deadline field: the round trip runs under THIS invocation's remaining segment,
// which the host carries across every handoff (seedkernel §12.3) — a caller naming
// its own would be minting time. Answer is `[ok u8][response]`; an unreachable peer
// comes back `[0]`, mapped to null below. `proto` is the routing id (seedkernel §12.10); the
// storage message type leads the payload, opaque in between.
const NET_SEND_OP = strBytes("send");
// A frame's length for a payload of `payloadLen` bytes, addressed to a 32-byte peer key.
function netFrameBytes(payloadLen) {
  return 1 + NET_SEND_OP.length + 1 + 4 + 32 + 4 + NET_PROTO.length + 4 + 1 + payloadLen;
}
// The whole frame in ONE allocation — op envelope, blobs and payload written straight
// in, so a STORE batch is copied once before it leaves the realm. `parts` lets the
// caller pass the batch's pieces uncopied, so a block's bytes land in the frame directly
// off the codec. The result must stay a WHOLE buffer: host.call copies any view it is handed.
function netSendFrame(to, type, parts) {
  let payloadLen = 0;
  for (const p of parts) payloadLen += p.length;
  const bodyLen = 1 + payloadLen; // [type u8][payload]
  const out = new Uint8Array(netFrameBytes(payloadLen));
  let o = 0;
  out[o++] = NET_SEND_OP.length;
  out.set(NET_SEND_OP, o); o += NET_SEND_OP.length;
  out[o++] = 0; // noReply = 0 — a reply is what this call is for
  wU32(out, o, to.length); o += 4; out.set(to, o); o += to.length;
  wU32(out, o, NET_PROTO.length); o += 4; out.set(NET_PROTO, o); o += NET_PROTO.length;
  wU32(out, o, bodyLen); o += 4;
  out[o++] = type;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
// `payload` is one buffer or an array of pieces to frame in order (encodeStoreBatchParts).
// `answerBytes` is what the reply may carry, charged to the ledger with the frame
// (verdicts, unless the caller says otherwise — maskAnswerBytes). `timing.ms`, when the
// caller passes it, is the round trip alone, not the wait for the ledger to admit it.
async function netSend(peer, type, payload, answerBytes, timing) {
  const parts = Array.isArray(payload) ? payload : [payload];
  let payloadLen = 0;
  for (const p of parts) payloadLen += p.length;
  const frameBytes = netFrameBytes(payloadLen);
  statsSent[type]++;
  // The frame is built once the ledger admits the call, so a lane waiting its turn holds
  // no copy of its blocks, and in-flight counts only what the host actually holds.
  const r = await hostBudget(frameBytes + (answerBytes ?? maskAnswerBytes(frameBytes)), async () => {
    statsInFlight[type]++;
    if (statsInFlight[type] > statsPeak[type]) statsPeak[type] = statsInFlight[type];
    const t0 = Date.now();
    try { return await host.call(NET_ID, netSendFrame(fromHex(peer), type, parts)); }
    finally { statsInFlight[type]--; if (timing) timing.ms = Date.now() - t0; }
  }, type === MsgType.STORE || type === MsgType.FETCH || type === MsgType.REPAIR_FETCH ? BULK : FOREGROUND).then((r) => r, () => EMPTY);
  // A view, not a copy: the caller decodes it (and keeps only what it needs) before
  // the answer goes out of scope. null = peer unreachable within the window.
  return r[0] === 1 ? r.subarray(1) : null;
}
// Per-peer fan-out (§6/§7): a distinct request per peer, all issued concurrently via
// Promise.all. `requests` = [{ peer, type, payload }]; results align to input order,
// an unreachable peer coming back `bytes: null` rather than a throw.
function netSendMany(requests) {
  return Promise.all(requests.map(async (rq) => ({ peer: rq.peer, bytes: await netSend(rq.peer, rq.type, rq.payload, rq.answerBytes) })));
}
// have/want (§5.2): one round of fan-out to the cohort (Promise.all over the
// same HAVE request to every holder) so the guest overlaps every peer. A node is
// itself a holder of whatever its own store keeps (repair runs on holders).
async function haveWant(ids) {
  const holders = new Map();
  for (const id of ids) holders.set(toHex(id), new Set());
  const me = myPeer();
  for (const id of ids) if (await storeHas(id)) holders.get(toHex(id)).add(me);
  const peers = await cohortPeers(call);
  // Split so one HAVE request stays under the frame cap (§18) — the request side
  // (32 B/id) is what binds since the reply is a 1-byte mask. Merge per-slice masks.
  const maxIds = Math.max(1, Math.floor((maxMsgBytes() - BATCH_HEAD) / BLOCK_ID_LEN));
  for (const slice of sliceN(ids, maxIds)) {
    const haveReq = encodeHaveReq(slice); // one shared request, broadcast to every peer
    for (const res of await netSendMany(peers.map((p) => ({ peer: p, type: MsgType.HAVE, payload: haveReq })))) {
      const held = res.bytes;
      if (held === null) continue;
      for (let i = 0; i < slice.length && i < held.length; i++) {
        if (held[i] === 1) holders.get(toHex(slice[i])).add(res.peer);
      }
    }
  }
  return holders;
}
// The HAVE/OFFER/STORE/FETCH wire codecs (§18) are stitched in from host/protocol.ts.

// One placement engine (placeChunksBatched, below) drives the shared §18 codecs
// through netSendMany. Nothing places a block any other way — a small file, a
// window of coded chunks, an index level, and a repair pass all express themselves
// as (block, slot) targets handed to that one function.

// ── descriptor ───────────────────────────────────────────────────────────────
// The pure §4.3 codecs (parseSignedDescriptor, encode/decodeDescriptorList,
// descriptorContains, copyTargets, BLOCK_ID_LEN) are stitched in from
// host/descriptor-core.ts. What stays here needs a grant: the scoped sign/verify pair.
//
// verifyDescriptor checks the author signature AND structurally validates the core:
// a signed-but-malformed descriptor (bad id count) is rejected rather than parsed
// into block-ids that sidestep the §10 sibling rule. Returns the whole envelope —
// a valid signature is only half the check; the holder's roster (admitBatch) is the other half.
// `parsed` is the envelope's parse when the caller already has it (a STORE hashes with it).
async function verifyDescriptor(env, via, parsed) {
  // Length-gate before the verify seam: the envelope is [pk 32][sig 64][core ≥ MIN_CORE]
  // (parseSignedDescriptor's own bound), so anything shorter — an absent descriptor
  // included — is rejected here rather than handed to verify as a short buffer.
  if (!env || env.length < 32 + 64 + MIN_CORE) return null;
  if (!(await verifyEnv(env, via))) return null;
  if (parsed) return parsed;
  try { return parseSignedDescriptor(env); } catch (_e) { return null; }
}
function signChunk(d) { return signCore(encodeDescriptorCore(d)); }

// ── placement + fetch (coordinator §6/§7) ────────────────────────────────────
// A batched OFFER/STORE/FETCH is split to stay under CFG.maxMessageBytes — the
// per-transport cap keeping one message inside the frame cap AND request timeout.
// Operator (LOCAL) policy; default if absent.
function maxMsgBytes() { const v = CFG.maxMessageBytes; return (typeof v === "number" && v > 0) ? v : (1 << 20); }
// Ids per FETCH sub-batch, bounded by the RESPONSE frame (blockSize + FETCH_ENTRY_HEAD per
// present block) so a full reply stays under the cap. The GET gather and the repair
// audit both size their batches this way; the holder caps served bytes the same (§18).
function fetchMaxIds() { return Math.max(1, Math.floor(maxMsgBytes() / (CFG.blockSize + FETCH_ENTRY_HEAD))); }
// A conservative allowance for what the host copies ALONGSIDE a message payload
// (type, request id, peer address): payload + this is what a call really charges.
const MSG_ENVELOPE_BYTES = 128;
// What a message's answer may carry, charged to the ledger with its frame. Every type but
// FETCH answers a verdict byte per entry, and an entry is at least an id; a FETCH answers
// the blocks it asked for. No type is full-size both ways.
function maskAnswerBytes(frameBytes) { return MSG_ENVELOPE_BYTES + Math.ceil(frameBytes / BLOCK_ID_LEN); }
function fetchAnswerBytes(n) { return MSG_ENVELOPE_BYTES + BATCH_HEAD + n * (CFG.blockSize + FETCH_ENTRY_HEAD); }
// The largest charge one initiator call takes to the ledger: a full-cap message and its
// verdicts, a full FETCH answer, or a chunk through the cipher (in and out) or the codec
// (k in, m out; k in, k out).
function maxCallChargeBytes() {
  const c = CFG, frame = maxMsgBytes() + MSG_ENVELOPE_BYTES;
  return Math.max(frame + maskAnswerBytes(frame), fetchAnswerBytes(fetchMaxIds()) + MSG_ENVELOPE_BYTES,
    Math.max(2 * c.k, c.k + c.m) * c.blockSize + MSG_ENVELOPE_BYTES);
}
// The fan-out window (operator policy, like maxMessageBytes): how many per-peer
// sub-batches one Promise.all round fires at once. PUT and GET share it — it bounds
// STORE messages PER PEER and OFFER/FETCH messages TOTAL across the cohort, pipelining
// a holder's many small messages instead of one round trip apiece. core.ts homes the
// default. It asks for concurrency; the ledger (hostBudget) decides how much of it the
// host's budget admits at once, and paces the rest.
function fanoutWindow() { return CFG.fanoutWindow; }
function sliceN(arr, size) {
  if (arr.length <= size) return [arr];
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}
// Run each peer's groups down `width` lanes drawing from one cursor, so one slow ack holds
// up only its own lane (coupled-batch refill measured 22% slower). Lanes start round-robin
// across peers. A holder answers past its per-source admission empty (`send` returns false):
// that group goes back to the peer's other lanes and this lane retires, so the width
// settles at what the holder admits; a last lane's refusal stands.
async function runStoreBatches(byPeer, width, send) {
  const workers = [];
  let failed = false, failure;
  const peers = [...byPeer].map(([peer, groups]) => ({ peer, groups: groups.slice(), next: 0, running: 0, lanes: Math.min(width, groups.length) }));
  const lane = (p) => (async () => {
    p.running++;
    while (!failed && p.next < p.groups.length) {
      const group = p.groups[p.next++];
      let refused = false;
      try { refused = (await send(p.peer, group)) === false; }
      catch (err) { if (!failed) { failed = true; failure = err; } }
      if (refused && p.running > 1) { p.groups.push(group); break; }
    }
    p.running--;
  })();
  for (let l = 0; l < width; l++) {
    for (const p of peers) if (l < p.lanes) workers.push(lane(p));
  }
  // Drain started lanes even on error; none may outlive this placement phase.
  await Promise.all(workers);
  if (failed) throw failure;
}
// Group items so each group's summed sizeOf stays under `maxBytes` (a single
// over-cap item still gets its own group). Used to bound a batched STORE message.
function batchBytes(items, sizeOf, maxBytes) {
  const out = [];
  let group = [], acc = 0;
  for (const it of items) {
    const sz = sizeOf(it);
    if (group.length > 0 && acc + sz > maxBytes) { out.push(group); group = []; acc = 0; }
    group.push(it); acc += sz;
  }
  if (group.length > 0) out.push(group);
  return out;
}
// A placement JOB: the unit the one engine below consumes. A flat list of SLOTS —
// (block bytes, id) targets to land on distinct peers — plus the signed descriptor
// that admits them, a `floor` of distinct ids that must land, peers to exclude, and the
// chunk's group, whose linked members are the only candidates.
// A chunk (makeChunk) is one slot per listed id, floor = its own k; a repair pass
// (heal) is only the copies still owed, floor 0 (best-effort).
function makeJob(slotIds, slotBlocks, descriptor, floor, exclude, group) {
  return {
    floor, slotIds, slotBlocks, descriptor, exclude, group,
    placedPeer: new Array(slotIds.length).fill(null),
    placedIds: [],
  };
}
// A signed chunk ready to place, expanded into its placement slots (§6/§10). One
// slot per listed id — a k=1 chunk's m+1-times-listed block IS its m+1 replica
// slots, no special case needed. Floor is the chunk's OWN k, not config's.
function makeChunk(d, blocks, descriptor) {
  return makeJob(d.blockIds.slice(), blocks.slice(), descriptor, d.k, new Set(), d.group);
}
// Encode + sign one chunk at its OWN k = ceil(plain / blockSize), not padded to the
// deployment's k. At k=1, RS(1,m) parity ≡ data, so the codec is skipped and the
// chunk simply lists its lone block m+1 times (§4.1). Nonce = (level, GLOBAL index
// within that level) (§4.4), so a windowed encode matches a whole-level one.
// `tailBytes` is how much of the chunk a reader keeps (§4.3); `group` is where it is placed (§5.1).
async function encodeChunk(source, localCi, globalCi, K, level, group) {
  const c = CFG;
  const plain = source.subarray(localCi * c.k * c.blockSize, (localCi + 1) * c.k * c.blockSize);
  const kc = Math.max(1, Math.ceil(plain.length / c.blockSize));
  const sealed = await encrypt(K, level, globalCi, padTo(plain, kc * c.blockSize));
  const dataBlocks = splitBlocks(sealed.ciphertext, c.blockSize);
  const blocks = kc === 1 ? new Array(c.m + 1).fill(dataBlocks[0])
                          : [...dataBlocks, ...await rsEncode(kc, c.m, c.blockSize, dataBlocks)];
  const author = { authorPk: identity() };
  const ids = kc === 1 ? new Array(c.m + 1).fill(await blockHash(author, dataBlocks[0], call))
                       : await Promise.all(blocks.map((b) => blockHash(author, b, call)));
  const d = { level, k: kc, m: c.m, blockSize: c.blockSize, tailBytes: plain.length, group, authTag: sealed.authTag, blockIds: ids };
  return makeChunk(d, blocks, await signChunk(d));
}
// The decline reasons a holder's verdict can name, for the error a failed PUT throws.
const VERDICT_REASONS = {
  [VERDICT_QUOTA]: "quota", [VERDICT_SIBLING]: "sibling",
  [VERDICT_DESCRIPTOR]: "descriptor-rejected", [VERDICT_ERROR]: "holder-error",
  [VERDICT_ALLOWANCE]: "allowance", [VERDICT_GROUP]: "not-in-group", [VERDICT_NOT_AUTHOR]: "not-author",
};
// THE placement engine (§6/§10). Places every job's slots with one batched OFFER
// per peer per round, then accepted blocks STORE'd in fanoutWindow()-deep fan-outs.
// Slot i targets cands[i], cands[i+slots], … — a disjoint residue class per i, so
// one job's slots land on distinct peers (the sibling rule / replica distinctness /
// "somewhere new" for repair, all one rule). Fills each job's placedPeer[]/placedIds[].
//
// Throws if a job lands fewer than its `floor` distinct ids. `what` names the job in
// that error; floor 0 (repair) never throws and so passes no name. `ranker` lets a PUT
// stream score each peer once for all its windows (makeRanker). Every job shares one group,
// and only that group's linked members are candidates. Answers the cohort size it placed across.
async function placeChunksBatched(jobs, what, ranker) {
  const group = jobs[0].group;
  const roster = await groupPeers(group, call);
  const ranked = await (ranker ?? ((peers) => rank(peers, group)))(roster);
  // Each job draws from the ranked cohort minus peers to avoid. PUT excludes nothing;
  // repair excludes peers already holding part of the chunk, so a restored copy lands
  // somewhere new instead of a sibling-declining or silently-overwritten holder.
  const candsOf = new Map();
  for (const job of jobs) candsOf.set(job, job.exclude.size === 0 ? ranked : ranked.filter((p) => !job.exclude.has(p)));
  const maxBytes = maxMsgBytes();
  const entryBytes = OFFER_ENTRY_HEAD + (jobs.length ? jobs[0].descriptor.length : 0); // one OFFER entry
  const maxOffers = Math.max(1, Math.floor(maxBytes / entryBytes));

  // Advisory diagnostics collected from holder verdicts — a holder may lie, so the
  // reason is never policy, but the error a failed PUT throws becomes exact.
  const declined = {}; // verdict → count
  let refused = 0;
  const noteVerdict = (v) => { if (v in VERDICT_REASONS) declined[v] = (declined[v] ?? 0) + 1; };

  for (let r = 0; ; r++) {
    const byPeer = new Map(); // peer → [{ch, i}]
    for (const ch of jobs) {
      const cands = candsOf.get(ch);
      const slots = ch.slotIds.length;
      for (let i = 0; i < slots; i++) {
        if (ch.placedPeer[i]) continue;
        const peer = cands[i + r * slots];
        if (!peer) continue;
        let list = byPeer.get(peer); if (!list) byPeer.set(peer, (list = []));
        list.push({ ch, i });
      }
    }
    if (byPeer.size === 0) break;

    // Lock-step fan-out: ALL of this round's OFFERs complete before its STOREs (no
    // optimistic STORE — §6). STORE lanes then replenish independently within
    // fanoutWindow() per peer (peers concurrent → peak W·peers).

    // ── OFFER phase ── every peer's slices form ONE cohort-wide list, windowed like the
    // FETCH plan, so a wide cohort does not fan out one full-cap message per peer at once.
    // Round-robin over peers so a window spreads across holders instead of serializing on
    // the one with the most slices.
    const offerSlices = new Map(); // peer → [slice]
    for (const [peer, items] of byPeer) offerSlices.set(peer, sliceN(items, maxOffers));
    const offerTasks = [];
    for (let s = 0, more = true; more; s++) {
      more = false;
      for (const [peer, slices] of offerSlices) if (s < slices.length) { offerTasks.push({ peer, slice: slices[s] }); more = true; }
    }
    const acceptedByPeer = new Map(); // peer → [{ch, i}]
    const offerW = fanoutWindow();
    for (let base = 0; base < offerTasks.length; base += offerW) {
      const round = offerTasks.slice(base, base + offerW);
      const results = await netSendMany(round.map(({ peer, slice }) => ({
        peer, type: MsgType.OFFER,
        payload: encodeOfferBatch(slice.map(({ ch, i }) => ({ blockId: ch.slotIds[i], descriptor: ch.descriptor }))),
      })));
      for (let ri = 0; ri < results.length; ri++) {
        const slice = round[ri].slice;
        const bytes = results[ri].bytes;
        if (bytes !== null && bytes.length === 0) refused++;
        const mask = bytes !== null ? decodeMask(bytes) : [];
        const accepted = slice.filter((_, j) => mask[j] === VERDICT_ACCEPTED);
        for (let j = 0; j < slice.length; j++) noteVerdict(mask[j]);
        if (accepted.length === 0) continue;
        let list = acceptedByPeer.get(results[ri].peer); if (!list) acceptedByPeer.set(results[ri].peer, (list = []));
        for (const it of accepted) list.push(it);
      }
    }

    // ── STORE phase ── the accepted blocks, byte-bounded per peer, then one request
    // per lane across fanoutWindow() lanes per peer, each lane refilling on its own
    // ack. Peak is W per peer, as far as the ledger admits.
    const storeGroups = new Map(); // peer → [group]
    const storeEntryBytes = ({ ch, i }) => STORE_ENTRY_HEAD + ch.descriptor.length + ch.slotBlocks[i].length;
    for (const [peer, accepted] of acceptedByPeer) storeGroups.set(peer, batchBytes(accepted, storeEntryBytes, maxBytes));
    await runStoreBatches(storeGroups, fanoutWindow(), async (peer, group) => {
      // Parts, not a concatenated batch: netSend writes the blocks into the outgoing
      // frame itself, so the ciphertext is never copied to a second buffer.
      const bytes = await netSend(peer, MsgType.STORE, encodeStoreBatchParts(group.map(({ ch, i }) => ({ blockId: ch.slotIds[i], descriptor: ch.descriptor, bytes: ch.slotBlocks[i] }))));
      // Empty is the holder turning the request away unread, not a verdict (runStoreBatches).
      if (bytes !== null && bytes.length === 0) { refused++; return false; }
      const stored = bytes !== null ? decodeMask(bytes) : [];
      for (let j = 0; j < group.length; j++) {
        if (stored[j] === VERDICT_ACCEPTED) group[j].ch.placedPeer[group[j].i] = peer;
        else noteVerdict(stored[j]);
      }
    });
  }

  for (const ch of jobs) {
    const distinct = new Set();
    for (let i = 0; i < ch.slotIds.length; i++) if (ch.placedPeer[i]) distinct.add(toHex(ch.slotIds[i]));
    if (distinct.size < ch.floor) {
      // Integer keys iterate in ascending verdict order, so the reasons list is stable.
      const verdicts = Object.keys(declined);
      const total = verdicts.reduce((sum, v) => sum + declined[v], 0);
      // No verdicts at all is itself the diagnosis — "holders declined" would point at the
      // wrong place. An empty answer is a holder turning requests away unread; no answer at
      // all is a deadline or an unreachable peer.
      const why = verdicts.length
        ? "holders declined (" + total + " holders: " + verdicts.map((v) => VERDICT_REASONS[v]).join(", ") + "). Check quota and newcomerShare (--local-config), signing scope (§16), or connect more holders"
        : refused
          ? "no holder returned a verdict — " + refused + " request(s) were answered empty: the holder was over its per-source delivery window, or serves no seedstore app"
          : "no holder returned a verdict — the requests timed out or the peers were unreachable rather than refusing. Raise the request deadline if a large PUT is queueing past it (p2p-cli --timeout, seedkernel --guest-timeout)";
      throw new Error("put: " + what + " landed " + distinct.size + "/" + ch.floor + " distinct blocks — " + why);
    }
    ch.placedIds = [...distinct].map(fromHex);  // the distinct ids that landed, for the PUT result
  }
  return roster.length;
}
// Run a windowed batched FETCH over a peer→[idHex] plan: self reads the local store,
// other holders fan out fanoutWindow() FETCH messages at a time. Every block is
// hash-verified against `descriptorOf(idHex)` (§4.2) and scores its holder (§8, never
// self); `onResult(peer, idHex, bytes)` then sees each asked id once, with the verified
// bytes or null. Shared by GET gather and repair audit.
//
// A holder bounds its reply by its own cap, so a block it has but couldn't fit comes back
// FETCH_UNANSWERED (§18) and is re-asked. Each round must resolve ≥1 id — checked below,
// not trusted, so a peer that never progresses is ruled a miss instead of looping forever.
//
// Up to fanoutWindow() requests are in flight, each verified as its own answer lands and its
// lane refilled at once, as the STORE lanes are (runStoreBatches): one slow holder then holds
// up only its own lane, not the verification of every answer that came back beside it.
// With `repairKey` each request is a REPAIR_FETCH, [chunk key 64][FETCH request]: serving it
// tells the holder that chunk is being repaired, deferring its own request (§9).
async function runFetchTasks(byPeer, maxIds, descriptorOf, onResult, repairKey = null) {
  const me = myPeer();
  const tally = repTally();
  // `blocks` aligns to `ids` (bytes|null each), or is null for an unreachable peer — not a §8 miss.
  const apply = async (peer, slice, ids, blocks) => {
    const hashes = blocks === null ? [] : await Promise.all(blocks.map((b, i) => b ? blockHash(descriptorOf(slice[i]), b, call) : null));
    for (let i = 0; i < slice.length; i++) {
      const b = blocks === null ? null : blocks[i];
      const good = b !== null && bytesEqual(hashes[i], ids[i]);
      // Standing is per group: each outcome counts in the group of the chunk it read.
      if (peer !== me && blocks !== null) tally.note(descriptorOf(slice[i]).group, peer, good ? 1 : 0, good ? 0 : 1);
      onResult(peer, slice[i], good ? b : null);
    }
  };
  if (byPeer.has(me)) {
    for (const slice of sliceN(byPeer.get(me), maxIds)) {
      const ids = slice.map(fromHex);
      await apply(me, slice, ids, await Promise.all(ids.map((id) => storeGetBytes(id, call))));
    }
  }
  // { peer, slice, ids } — re-requested unanswered blocks are appended, and the next free lane
  // takes them. Round-robin over peers, as the STORE lanes start (runStoreBatches): the ledger
  // admits in order, so one peer's slices first would idle every other holder.
  const tasks = [];
  const slicesOf = [...byPeer.keys()].filter((peer) => peer !== me).map((peer) => ({ peer, slices: sliceN(byPeer.get(peer), maxIds) }));
  for (let s = 0, more = true; more; s++) {
    more = false;
    for (const { peer, slices } of slicesOf) if (s < slices.length) { tasks.push({ peer, slice: slices[s], ids: slices[s].map(fromHex) }); more = true; }
  }
  const fetchOne = async ({ peer, slice, ids }) => {
    const req = encodeFetchBatchReq(ids);
    const bytes = repairKey === null
      ? await netSend(peer, MsgType.FETCH, req, fetchAnswerBytes(ids.length))
      : await netSend(peer, MsgType.REPAIR_FETCH, [fromHex(repairKey), req], fetchAnswerBytes(ids.length));
    if (bytes === null) return apply(peer, slice, ids, null); // unreachable
    let decoded;
    try { decoded = decodeFetchBatchRes(bytes, ids.length); }
    catch {
      // A bad response is this holder's miss, not a failure of the whole read
      // or repair pass. Mark it tried and let the caller use healthy holders.
      return apply(peer, slice, ids, new Array(ids.length).fill(null));
    }
    // Split the holder's answers over the ids we asked: FETCH_UNANSWERED blocks (no room
    // under the holder's cap) re-queue as a fresh task; present/absent are final verdicts
    // for `apply`. Malformed responses were rejected as a whole above.
    const reSlice = [], reIds = [], aSlice = [], aIds = [], aBlocks = [];
    for (let i = 0; i < slice.length; i++) {
      if (decoded[i] === FETCH_UNANSWERED) { reSlice.push(slice[i]); reIds.push(ids[i]); }
      else { aSlice.push(slice[i]); aIds.push(ids[i]); aBlocks.push(decoded[i] || null); }
    }
    // Re-queue only if this round decided something (checked, not assumed): a peer
    // answering UNANSWERED for every id has resolved nothing, and re-queueing would
    // loop forever. No progress rules those ids absent — a §8 miss for this peer.
    if (reSlice.length && aSlice.length === 0) {
      for (let i = 0; i < reSlice.length; i++) { aSlice.push(reSlice[i]); aIds.push(reIds[i]); aBlocks.push(null); }
      reSlice.length = 0;
    }
    // Re-ask in slices this holder has SHOWN it can fill, not the width we asked at:
    // fetchMaxIds sizes a request by OUR cap, so against a smaller-capped holder the
    // original width re-asks the whole tail every round — n ids costing n round trips.
    // Nothing served is no capacity signal (the tail was unread, not capped): keep the width.
    if (reSlice.length) {
      let served = 0;
      for (const b of aBlocks) if (b) served++;
      const w = served > 0 ? served : reSlice.length;
      for (let i = 0; i < reSlice.length; i += w) tasks.push({ peer, slice: reSlice.slice(i, i + w), ids: reIds.slice(i, i + w) });
    }
    if (aSlice.length) await apply(peer, aSlice, aIds, aBlocks);
  };
  // A pump rather than fixed lanes: re-asks are appended while requests are in flight, so
  // every completion refills up to the width, and the run ends when nothing is left or running.
  const width = fanoutWindow();
  let next = 0, running = 0, failure = null;
  await new Promise((resolve, reject) => {
    const pump = () => {
      while (failure === null && running < width && next < tasks.length) {
        running++;
        fetchOne(tasks[next++])
          .catch((err) => { if (failure === null) failure = err; })
          .finally(() => { running--; pump(); });
      }
      if (running === 0) failure === null ? resolve() : reject(failure);
    };
    pump();
  });
  await tally.settle();
}
// Fetch every block the file's chunks need, batched per holder. Each still-missing
// block is requested from one untried holder; a coded chunk stops at k. Every
// returned block is hash-verified (§4.2) and scores its holder (§8).
//
// A block several peers hold (a k = 1 replica, §4.1) goes to whichever of them has the
// fewest blocks queued this round, the better-scored on a tie. Always taking the
// best-scored would read a whole replicated file from one holder and leave the others'
// links idle. A holder scored below zero is still passed over while another has the block (§7).
// `got` may arrive holding blocks already in hand, and is filled in place. `repairKey`, when
// set, marks every fetch as that chunk's repair (runFetchTasks).
async function gatherBlocks(descriptors, holders, got = new Map(), repairKey = null) {
  const descriptorOf = new Map();
  for (const d of descriptors) for (const id of d.blockIds) descriptorOf.set(toHex(id), d);
  const tried = new Map();
  const triedOf = (h) => { let s = tried.get(h); if (!s) tried.set(h, (s = new Set())); return s; };
  // Bound a FETCH sub-batch by the RESPONSE size: each present block is blockSize +
  // FETCH_ENTRY_HEAD on the wire, so dividing by blockSize alone would let a full response
  // slip just past the cap (the request side, 32 B/id, is smaller and never binds).
  const maxIds = fetchMaxIds();

  // k distinct ids read a chunk, whatever its k (§4.1): any k of a coded chunk's k+m
  // blocks reconstruct it, and a k = 1 chunk needs the one id it lists m+1 times.
  const stillNeeds = (d) => {
    const distinct = new Set();
    for (const id of d.blockIds) if (got.has(toHex(id))) distinct.add(toHex(id));
    return Math.max(0, d.k - distinct.size);
  };

  for (;;) {
    // One ranker for the whole round: scoring a holder crosses the bridge once, then
    // every id that shares that holder reuses the cached score (§13).
    const rankRound = await makeRanker(descriptors[0].group);
    const byPeer = new Map(); // peer → [idHex]
    const queuedOn = (p) => { const l = byPeer.get(p); return l ? l.length : 0; };
    const queued = new Set();
    const me = myPeer();
    for (const d of descriptors) {
      let need = stillNeeds(d);
      if (need === 0) continue;
      for (const id of d.blockIds) {
        if (need === 0) break;
        const h = toHex(id);
        if (got.has(h) || queued.has(h)) continue;
        const cands = await rankRound([...(holders.get(h) || new Set())].filter((p) => !triedOf(h).has(p)), true);
        if (cands.length === 0) continue;
        // Our own copy costs no round trip, so it is read before any peer's.
        let peer = cands[0];
        if (cands.includes(me)) peer = me;
        else for (const p of cands) if (queuedOn(p) < queuedOn(peer)) peer = p;
        let list = byPeer.get(peer); if (!list) byPeer.set(peer, (list = []));
        list.push(h);
        queued.add(h);
        need--;
      }
    }
    if (byPeer.size === 0) break;

    // Keep the first verified copy; a holder asked once is not asked for that id again.
    await runFetchTasks(byPeer, maxIds, (h) => descriptorOf.get(h), (peer, h, b) => {
      triedOf(h).add(peer);
      if (b && !got.has(h)) got.set(h, b);
    }, repairKey);
  }
  return got;
}
// Assemble one chunk's ciphertext from the gathered blocks (§4.1/§7), as its k data blocks
// in order for decrypt to frame: take the first k DISTINCT listed blocks, and if they're
// the k data blocks in order they are it (systematic RS). Distinct matters: a k=1
// descriptor lists its block m+1 times, so the same bytes must not fill two rows.
async function assembleChunk(d, got) {
  const k = d.k;
  const present = [], seen = new Set();
  for (let i = 0; i < d.blockIds.length && present.length < k; i++) {
    const h = toHex(d.blockIds[i]);
    if (seen.has(h)) continue;
    const b = got.get(h);
    if (b) { seen.add(h); present.push({ index: i, bytes: b }); }
  }
  if (present.length < k) throw new Error("get: fewer than k blocks retrievable — chunk unavailable");
  // `present` is k distinct rows in ascending order, so the last being row k−1 means rows 0..k−1.
  if (present[k - 1].index === k - 1) return present.map((p) => p.bytes);
  return rsDecode(k, d.m, d.blockSize, present);
}

// ── PUT (§6) ─────────────────────────────────────────────────────────────────
// A large file is never wholly resident in the confined guest heap: encoded and
// placed in chunk-aligned WINDOWS, dropping ciphertext blocks once placed (§3). The
// driver streams plaintext a window at a time (putStart → putWindow* → putFinish);
// the whole-file `put` entry drives the same loop over its own in-memory argument.

// Target footprint for one window's plaintext slice, derived by the host driver
// from realmMemoryBytes (~/6: two windows in flight, core.ts) as CFG.windowTargetBytes,
// and signed into every bundle the same way, so it is always set.
// A too-small window idles the wire between OFFER→STORE→ack rounds on a fat link.
function windowTarget() {
  const v = CFG.windowTargetBytes;
  if (!(v > 0)) throw new Error("config: no windowTargetBytes — the host derives it (core.ts normaliseConfig)");
  return v;
}
// A chunk-aligned window size: as many whole chunks (k·blockSize) as fit under the
// target, at least one, so window boundaries never split a chunk.
function putWindowBytes() { const chunkData = CFG.k * CFG.blockSize; return Math.max(1, Math.floor(windowTarget() / chunkData)) * chunkData; }
// Chunks per GET window. `chunkData` (k·blockSize) is the DESCRIPTOR's geometry
// (§4.3), passed in by the reader, never config's.
function getWindowChunks(chunkData) { return Math.max(1, Math.floor(windowTarget() / chunkData)); }

// Chunks one window encodes (PUT) or decodes and opens (GET) at once, overlapping the codec
// worker with neighboring chunks' cipher/hash/sign work.
const CHUNK_DEPTH = 4;
// Encode the chunks wholly contained in `slice` — a chunk-aligned slice of a LEVEL's
// byte stream at offset `baseByteOffset`. Each chunk codes at its own k (§4.1).
// Level 0 (the file) and level ℓ > 0 (an index) are the same call.
async function encodeWindow(slice, baseByteOffset, K, level, group) {
  const c = CFG;
  const chunkData = c.k * c.blockSize;
  const baseCi = Math.floor(baseByteOffset / chunkData);
  const numChunks = Math.max(1, Math.ceil(slice.length / chunkData));
  const chunks = [];
  for (let base = 0; base < numChunks; base += CHUNK_DEPTH) {
    const work = [];
    for (let lc = base; lc < Math.min(base + CHUNK_DEPTH, numChunks); lc++) work.push(encodeChunk(slice, lc, baseCi + lc, K, level, group));
    chunks.push(...await Promise.all(work));
  }
  return chunks;
}

// Place a whole byte stream as a run of chunks, answering with signed descriptors.
// The only thing that turns bytes into placed chunks — a file's descriptor list is
// bytes too, so it goes through here at a different `level`. One path, called twice.
//
// Placement is pipelined: a window's descriptors exist once it is encoded, so it is
// handed to placement and the stream moves on, keeping one window placing behind the
// one just started. The next window's encode and OFFER round trip then run while the
// last one's STOREs drain, instead of the wire idling through each boundary — and an
// index level, whose input is only the descriptors, places beside the file's last window.
// The two share the realm's host-call budget through the ledger (hostBudget).
async function placeStream(s, bytes, level, base) {
  const out = [];
  const wb = putWindowBytes();
  for (let off = 0; off === 0 || off < bytes.length; off += wb) {   // an empty file is still one chunk
    const chunks = await encodeWindow(bytes.subarray(off, Math.min(off + wb, bytes.length)), base + off, s.K, level, s.group);
    for (const ch of chunks) { out.push(ch.descriptor); s.own.push(ch.descriptor); }
    await pipePlacement(s, placeChunksBatched(chunks, "chunk", s.rank).then((peerCount) => recordPlacements(s, chunks, peerCount)));
  }
  return out;
}
// Start one window placing and wait for the one behind it, so at most two are in flight.
// A failure is thrown only once the other has settled: no placement outlives its stream.
async function pipePlacement(s, placing) {
  placing.catch(() => {}); // observed here, by the next window, or by settlePlacements
  const behind = s.placing;
  s.placing = placing;
  if (!behind) return;
  try { await behind; }
  catch (err) { await placing.catch(() => {}); throw err; }
}
async function settlePlacements(s) {
  const last = s.placing;
  s.placing = null;
  if (last) await last;
}
// Run one stream step; on failure, let the placement still in flight settle first.
async function streamStep(s, step) {
  try { return await step(); }
  catch (err) {
    const pending = s.placing;
    s.placing = null;
    if (pending) await pending.catch(() => {});
    throw err;
  }
}

// ── the streamed PUT session ─────────────────────────────────────────────────
// Protocol state a PUT carries between windows (K, offset, descriptors, replica
// accounting) lives here in realm state rather than round-tripped through the
// driver. Safe by construction: every driver runs one initiator op to completion
// before the next (StorageNode's runExclusive), so streams never overlap.
let putStream = null;
function requirePut() {
  if (!putStream) throw new Error("put: no stream open — call putStart first");
  return putStream;
}
// The largest a signed descriptor in `group` gets, framed for the descriptor list: the
// deployment's own (k, m), since a partial chunk lists fewer ids (§4.3).
function descriptorBytes(group) { return 4 + 32 + 64 + MIN_CORE - 1 + group.length + (CFG.k + CFG.m) * BLOCK_ID_LEN; }
// Open a stream: mint K and answer with the plaintext window the driver should feed.
// It takes no file size: each chunk signs its own `tailBytes` (§4.3).
//
// A chunk must hold at least two descriptors, or a descriptor list could never
// shrink to a single root — checked here, once, before a byte moves, as is a coded
// chunk against the codec's limits. Realistic geometries clear the first by orders of magnitude.
//
// The stream keeps one ranker: each peer is scored once for every window, not per window.
// Every chunk, index levels included, is placed in `group` and signs its name (§5.1).
async function putStart(group) {
  if (!groups.has(group)) throw new Error("put: no group \"" + group + "\" in this node's roster");
  const chunkData = CFG.k * CFG.blockSize;
  if (chunkData < 2 * descriptorBytes(group)) {
    throw new Error("put: k·blockSize (" + chunkData + " B) must hold two chunk descriptors ("
      + descriptorBytes(group) + " B each) so a file's descriptor list can reach a single root — raise blockSize or k");
  }
  if (CFG.k > 1) await assertCodecFits(CFG.k, CFG.m, CFG.blockSize);
  putStream = { K: await randomKey(), group, rank: await makeRanker(group), offset: 0, descriptors: [], own: [], placedIds: [], placed: 0, intended: 0, placing: null };
  return putWindowBytes();
}
// Fold placed chunks into the stream's durability accounting (§8). Counts REPLICA
// PLACEMENTS (one filled slot), not distinct ids — a k=1 chunk is one id on m+1
// peers, so counting ids would under-report. `intended` caps at the reachable
// cohort the chunks were placed across (the §6/§10 sibling rule caps one block per
// peer), so a small cohort isn't flagged while a declining (full) holder makes
// placed < intended.
function recordPlacements(s, chunks, peerCount) {
  for (const ch of chunks) {
    for (const id of ch.placedIds) s.placedIds.push(id);
    for (const p of ch.placedPeer) if (p) s.placed++;
    s.intended += Math.min(ch.slotIds.length, peerCount);
  }
}
// Feed the next plaintext window, in file order — a chunk-aligned slice of the file. It
// returns once the window BEFORE it is placed, leaving this one placing behind the next
// feed (placeStream); the driver never learns the window's byte offset, because the
// stream knows it.
async function putFeed(slice) {
  const s = requirePut();
  await streamStep(s, async () => {
    for (const env of await placeStream(s, slice, LEVEL_BODY, s.offset)) s.descriptors.push(env);
  });
  s.offset += slice.length;
}
// Seal the stream and report the whole PUT. Closes the stream first, so a failed or
// abandoned PUT leaves nothing behind.
//
// The descriptors this PUT placed are bytes too, so they go through placeStream at
// increasing `level` until one chunk is left — its descriptor is the file's root
// (§4.3). A file that fits one chunk has no index: its own descriptor IS the root.
async function putFinish() {
  const s = requirePut();
  putStream = null;
  if (!s.descriptors.length) throw new Error("put: stream sealed with no data — call putWindow at least once before putFinish");
  return streamStep(s, async () => {
    let envs = s.descriptors;
    for (let level = 1; envs.length > 1; level++) envs = await placeStream(s, encodeDescriptorList(envs), level, 0);
    await settlePlacements(s);
    await saveOwnFile(envs[0], s.own);
    // The ONE PUT result format, shared with every driver (host/protocol.ts).
    return encodePutResult({
      key: s.K, root: envs[0], chunkCount: s.descriptors.length,
      replicasLanded: s.placed, replicasIntended: s.intended, blockIds: s.placedIds,
    });
  });
}

// The group a PUT names, or the node's only one when it names none.
function putGroup(nameBytes) {
  if (nameBytes.length > 0) return groupName(nameBytes);
  if (groups.size !== 1) throw new Error("put: name a group — this node has " + (groups.size === 0 ? "none" : [...groups.keys()].join(", ")));
  return [...groups.keys()][0];
}
// [group ..] → [windowBytes u32]: open the stream, report the feed size. An empty argument
// is the node's only group.
async function doPutStart(arg) { const out = new Uint8Array(4); wU32(out, 0, await putStart(putGroup(arg))); return out; }
// The window's plaintext, raw — no framing, since the stream holds everything else.
async function doPutWindow(arg) { await putFeed(arg); return EMPTY; }
// Whole-file PUT: one call, bytes in, result out — for drivers with no protocol
// structure of their own, such as the CLI's `--op put < file`. It stores into the node's
// only group; a node with several streams instead (PUT_START names the group). Runs the
// same session as the streamed path; only the 1× plaintext is resident.
async function doPut(plaintext) {
  const wb = await putStart(putGroup(EMPTY));
  for (let off = 0; ; off += wb) {
    await putFeed(plaintext.subarray(off, Math.min(off + wb, plaintext.length)));
    if (off + wb >= plaintext.length) break;
  }
  return putFinish();
}

// ── GET (§7) ─────────────────────────────────────────────────────────────────
// Fetch, reconstruct (§4.1) and decrypt (§4.4) the plaintext for a run of parsed chunk
// descriptors `ds` starting at level-relative index `chunkStart`. Shared by the
// whole-file `get`, streamed getNext, and the index walk, since an index level
// reads exactly like a run of file chunks. Geometry is always the DESCRIPTOR's,
// never config's (§4.1/§4.3).
async function reconstructChunks(ds, K, chunkStart) {
  const allIds = [];
  for (const d of ds) for (const id of d.blockIds) allIds.push(id);
  const holders = await haveWant(allIds);
  const got = await gatherBlocks(ds, holders);
  const parts = new Array(ds.length);
  for (let base = 0; base < ds.length; base += CHUNK_DEPTH) {
    await Promise.all(ds.slice(base, base + CHUNK_DEPTH).map(async (d, j) => {
      // Nonce = (this chunk's own level, its index within that level) (§4.4), matching
      // encodeChunk; tailBytes trims this chunk's zero padding, whether it is the file's
      // last chunk or an index level's.
      const plain = await decrypt(K, d.level, chunkStart + base + j, await assembleChunk(d, got), d.authTag);
      parts[base + j] = plain.length === d.tailBytes ? plain : plain.subarray(0, d.tailBytes);
    }));
  }
  return concat(parts);
}
// ── the streamed GET session ─────────────────────────────────────────────────
// The mirror of the PUT stream: getStart walks the index to the leaf descriptors,
// kept in realm state; getNext then reconstructs one window's chunks at a time.
let getStream = null;
// Open a stream from the ROOT DESCRIPTOR the reader was handed. Signed `level` says
// what it describes: 0 is the file's ciphertext, ℓ > 0 an index over level ℓ−1.
// Walk to the leaves, then sum their signed tailBytes for the file size.
//
// The root has no authenticated parent. Verify its signature before trusting its
// size, geometry or block ids; AEAD authenticates ciphertext, not tailBytes.
async function getStart(rootEnv, K) {
  const root = await verifyDescriptor(rootEnv, call);
  if (!root) throw new Error("get: invalid root descriptor signature or format");
  let ds = [root.descriptor];
  while (ds[0].level > 0) {
    const above = ds[0].level;
    ds = decodeDescriptorList(await reconstructChunks(ds, K, 0)).map((env) => parseSignedDescriptor(env).descriptor);
    // Descent MUST strictly decrease (§7). A hostile sharer holds K, so it can hand
    // out an index chunk that authenticates and decrypts to a list naming its own
    // level, which content addressing wouldn't catch. Unchecked, the walk never ends.
    if (!ds.length || ds[0].level >= above) throw new Error("get: index does not descend at level " + above + " — malformed or hostile root");
  }
  let fileSize = 0, maxChunkBytes = 0;
  for (const d of ds) {
    fileSize += d.tailBytes;
    if (d.k * d.blockSize > maxChunkBytes) maxChunkBytes = d.k * d.blockSize;
  }
  getStream = { K, ds, next: 0, windowChunks: getWindowChunks(maxChunkBytes), ahead: null };
  return fileSize;
}
// Start reconstructing the stream's next window, or null once every window is started.
function startWindow(s) {
  if (s.next >= s.ds.length) return null;
  const start = s.next;
  const ds = s.ds.slice(start, start + s.windowChunks);
  s.next = start + ds.length;
  const window = reconstructChunks(ds, s.K, start);
  window.catch(() => {}); // observed by the getNext that returns it
  return window;
}
// The next window's plaintext, in file order. Empty once the file is exhausted, which
// also closes the stream — so a driver reading to the end leaves nothing behind.
//
// Prefetched: the window after this one is started before this one is awaited, so its
// HAVE and FETCH round trips run while this one lands and the driver drains it, instead
// of the wire idling through every boundary. At most two windows are in flight; they
// share the realm's host-call budget through the ledger (hostBudget).
async function getNext() {
  const s = getStream;
  if (!s) throw new Error("get: no stream open — call getStart first");
  const window = s.ahead ?? startWindow(s);
  if (!window) { getStream = null; return EMPTY; }
  s.ahead = startWindow(s);
  try { return await window; }
  catch (err) {
    // A failed read ends the stream, once the window behind it has settled.
    getStream = null;
    if (s.ahead) await s.ahead.catch(() => {});
    throw err;
  }
}

// [K 32][root ...] → [fileSize u64]: open the stream, report how much to drain. K leads so
// the variable-length root can be the tail.
async function doGetStart(arg) {
  const out = new Uint8Array(8);
  writeU64BE(out, 0, await getStart(arg.slice(32), arg.slice(0, 32)));
  return out;
}

// Whole-file GET: the counterpart of the whole-file `put`, draining the same stream in
// one call for the byte-in/byte-out drivers.
async function doGet(arg) {
  await getStart(arg.slice(32), arg.slice(0, 32));
  const parts = [];
  while (getStream) parts.push(await getNext());
  return concat(parts);
}

// ── repair (§9) ────────────────────────────────────────────────────────────--
// The verification ledger (§8): peerHex → { pass, miss }, when this node last saw the peer
// serve a sampled block whole and within verifyDeadlineMs, and when one last failed. It is
// per peer: a peer verified on any block counts as holding the others it advertises until
// its pass is verifyFreshMs old.
const verifiedAt = new Map();
// Fresh holders a chunk audit re-checks besides the stale ones, least recently verified first.
const AUDIT_SAMPLE = 2;
// Set by normaliseConfig (core.ts) on every path that signs or boots a config.
function cfgMs(key) {
  const v = CFG[key];
  if (!(v > 0)) throw new Error("config: no " + key + " — the host derives it (core.ts normaliseConfig)");
  return v;
}
function verifiedLive(peer, t) {
  const v = verifiedAt.get(peer);
  return v !== undefined && v.pass > v.miss && t - v.pass < cfgMs("verifyFreshMs");
}
function noteVerified(peer, t, ok) {
  let v = verifiedAt.get(peer);
  if (v === undefined) {
    // An entry past the fresh window says no more than a missing one.
    for (const [p, e] of verifiedAt) if (t - Math.max(e.pass, e.miss) >= cfgMs("verifyFreshMs")) verifiedAt.delete(p);
    verifiedAt.set(peer, (v = { pass: 0, miss: 0 }));
  }
  if (ok) v.pass = t; else v.miss = t;
}
// Verify one block per picked peer, each a single-block FETCH so the deadline bounds one
// disk read and one block on the wire. Unreachable or UNANSWERED is no verdict; wrong,
// malformed or late is a miss.
async function verifySample(d, picks) {
  const tally = repTally();
  await Promise.all(picks.map(async ({ peer, h }) => {
    const id = fromHex(h), timing = {};
    const r = await netSend(peer, MsgType.FETCH, encodeFetchBatchReq([id]), fetchAnswerBytes(1), timing);
    if (r === null) return;
    let b;
    try { b = decodeFetchBatchRes(r, 1)[0]; } catch { b = null; }
    if (b === FETCH_UNANSWERED) return;
    const good = b !== null && bytesEqual(await blockHash(d, b, call), id);
    const ok = good && !(timing.ms > cfgMs("verifyDeadlineMs"));
    noteVerified(peer, Date.now(), ok);
    tally.note(d.group, peer, ok ? 1 : 0, ok ? 0 : 1);
  }));
  await tally.settle();
}
// Audit a chunk's blocks (§9 step 1): have/want for the advertised holders, then a
// verification-fetch of one block from every advertiser the ledger holds no fresh pass for,
// plus AUDIT_SAMPLE of the rest. Live = advertised and freshly verified; this node's own
// copies count as live without a fetch. Returns Map hex → Set(peer).
async function liveHolders(d) {
  const advertised = await haveWant(d.blockIds);
  const me = myPeer(), t = Date.now();
  const sampleOf = new Map(); // peer → one id it advertised
  for (const [h, peers] of advertised) for (const p of peers) if (p !== me && !sampleOf.has(p)) sampleOf.set(p, h);
  const picks = [], fresh = [];
  for (const [peer, h] of sampleOf) (verifiedLive(peer, t) ? fresh : picks).push({ peer, h });
  fresh.sort((a, b) => verifiedAt.get(a.peer).pass - verifiedAt.get(b.peer).pass);
  picks.push(...fresh.slice(0, AUDIT_SAMPLE));
  await verifySample(d, picks);
  const now = Date.now(), live = new Map();
  for (const [h, peers] of advertised) live.set(h, new Set([...peers].filter((p) => p === me || verifiedLive(p, now))));
  return live;
}
// ── repair by request (§9) ──
// A missing copy is rebuilt by the device that will keep it. A holder whose audit finds a
// chunk short sends a group member holding none of it a REPAIR request: the signed
// descriptor, the block wanted, and who holds which blocks. The member decides under its
// own admission and, if it agrees, fetches what it needs, rebuilds the block, checks it
// against its signed id and stores it. Agreeing is a promise, not a guarantee: if nothing
// lands, the chunk's repair note expires and a later audit asks someone else.
const REPAIR_NOTE_MS = 2 * 60 * 1000;
// Chunk key → until when this node treats it as being repaired because it asked a member to
// repair it. That is this node's own request, so it holds for the whole window.
const repairing = new Map();
// Chunk key → until when another member's REPAIR_FETCH defers this node's own request. A
// hint, not a promise, and any member can send one, so it holds one window from the FIRST
// hint and later hints do not extend it. The spent entry stays until an audit finds the chunk
// healthy, so a member that keeps claiming a repair it never finishes delays healing by one
// window, never suppresses it (§10). Entries spent for over REPAIR_HINT_MEMORY_MS are pruned.
const repairHints = new Map();
const REPAIR_HINT_MEMORY_MS = 60 * 60 * 1000;
function chunkKey(env) { return toHex(env.subarray(32, 96)); }
function noteRepairing(key, t) {
  for (const [k, until] of repairing) if (until <= t) repairing.delete(k);
  repairing.set(key, t + REPAIR_NOTE_MS);
}
function noteRepairHint(key, t) {
  if (repairHints.has(key)) return;
  for (const [k, until] of repairHints) if (until + REPAIR_HINT_MEMORY_MS <= t) repairHints.delete(k);
  repairHints.set(key, t + REPAIR_NOTE_MS);
}
function isRepairing(key, t) {
  const until = repairing.get(key), hint = repairHints.get(key);
  return (until !== undefined && until > t) || (hint !== undefined && hint > t);
}
// Take a REPAIR_FETCH as a hint only from a member of the chunk's group, about a chunk this
// node holds a block of, whose block the request names. Anything else is served and ignored.
// A repairer fetches only the chunk's own blocks, so the first one held decides.
async function hintFromRepairFetch(caller, key, ids) {
  await ensureStoreIndex();
  for (const id of ids) {
    const e = heldBlocks.get(toHex(id));
    if (!e) continue;
    if (!inGroup(e.group, toHex(caller))) return;
    const env = await storeGetDescriptor(id, holderCall);
    if (env && chunkKey(env) === key) noteRepairHint(key, Date.now());
    return;
  }
}
// ── this node's own files (§13.1) ──
// Every chunk this node authored, as its signed descriptors, so its own audit sees who holds
// its data: the ledger's holdings, and a repair request when one of them is short. A PUT
// adds `own.<root key>.<n>` records, each an encoded descriptor list of up to
// OWN_PART_BYTES. No content key is kept. A pass audits OWN_AUDIT_PER_PASS of them in turn.
const OWN_PREFIX = "own.";
const OWN_PART_BYTES = 128 * 1024;
const OWN_AUDIT_PER_PASS = 32;
let ownChunks = null, ownCursor = 0;
async function loadOwnChunks() {
  if (ownChunks !== null) return ownChunks;
  const out = [];
  for (const key of await storeKeys()) {
    if (!key.startsWith(OWN_PREFIX)) continue;
    const part = await fsGet(key, call, OWN_PART_BYTES + 1024);
    try { if (part) for (const env of decodeDescriptorList(part)) out.push(env); } catch { /* a torn part */ }
  }
  ownChunks = out;
  return out;
}
// Record a PUT's chunks, index levels included. A failure leaves the file unaudited by its
// owner, not unstored, so it does not fail the PUT.
async function saveOwnFile(rootEnv, envs) {
  try {
    const own = await loadOwnChunks();
    const parts = [];
    let part = [], bytes = 0;
    for (const env of envs) {
      if (part.length > 0 && bytes + 4 + env.length > OWN_PART_BYTES) { parts.push(part); part = []; bytes = 0; }
      part.push(env); bytes += 4 + env.length;
    }
    if (part.length > 0) parts.push(part);
    const rootKey = chunkKey(rootEnv);
    for (let i = 0; i < parts.length; i++) await fsPut(OWN_PREFIX + rootKey + "." + i, [encodeDescriptorList(parts[i])], call);
    for (const env of envs) own.push(env);
  } catch { /* unaudited, see above */ }
}
async function nextOwnChunks() {
  const own = await loadOwnChunks();
  const out = [];
  for (let i = 0; i < Math.min(OWN_AUDIT_PER_PASS, own.length); i++) out.push(own[(ownCursor + i) % own.length]);
  if (own.length > 0) ownCursor = (ownCursor + out.length) % own.length;
  return out;
}
// Ask group members to repair what an audited chunk lacks, one member per missing
// dependable copy, telling each how urgent it is (`margin`). `leaving` is a holder to count
// as gone (this node, releasing its copy), though it still serves until then. Answers how
// many members agreed.
async function requestRepairs(d, env, live, margin, leaving = null) {
  const key = chunkKey(env);
  if (isRepairing(key, Date.now())) return 0;
  const counts = dependableCopies(d, live, leaving), have = new Map();
  for (let i = 0; i < d.blockIds.length; i++) have.set(toHex(d.blockIds[i]), counts[i]);
  const missing = [];
  for (const [h, target] of copyTargets(d)) for (let c = have.get(h); c < target; c++) missing.push(h);
  // Rebuildable at all: a k = 1 block from one live copy, a coded block from any k blocks.
  let liveDistinct = 0;
  for (const h of copyTargets(d).keys()) if ((live.get(h) || new Set()).size > 0) liveDistinct++;
  if (missing.length === 0 || liveDistinct < d.k) return 0;
  const occupied = new Set();
  for (const set of live.values()) for (const p of set) occupied.add(p);
  const hints = [];
  for (const [h, peers] of live) for (const peer of peers) hints.push({ peer, blockId: fromHex(h) });
  const cands = await rank((await groupPeers(d.group, call)).filter((p) => !occupied.has(p)), d.group);
  // A member that declines is passed over for the next. One that does not answer may still
  // have agreed, so its copy counts as promised and nobody else is asked for it this time.
  let next = 0, accepted = 0, unknown = 0;
  for (const h of missing) {
    while (next < cands.length) {
      const r = await netSend(cands[next++], MsgType.REPAIR, encodeRepairReq({ descriptor: env, target: fromHex(h), margin, hints }));
      if (r === null) { unknown++; break; }
      if (r.length === 1 && r[0] === VERDICT_ACCEPTED) { accepted++; break; }
    }
  }
  if (accepted + unknown > 0) noteRepairing(key, Date.now());
  return accepted;
}
// The copies of each listed block a chunk can count on: its live, dependable holders,
// less `leaving` (a holder about to drop its copy).
function dependableCopies(d, live, leaving = null) {
  return d.blockIds.map((id) => {
    let n = 0;
    for (const p of live.get(toHex(id)) || []) if (p !== leaving && dependable(d.group, p)) n++;
    return n;
  });
}
// Audit one chunk from its signed descriptor: { d, env, live, margin } if it is short, else
// null. Health is the loss margin over dependable copies only (§8, §9), so a chunk whose
// copies sit on peers that are often offline is repaired onto steadier ones before it loses
// anything. Margin and low-water mark ⌈m/2⌉ both come from the SIGNED descriptor — a
// mixed-geometry cohort (§4.1) repairs each chunk to the count its own author signed. For a
// chunk this node authored, the audit also records who holds it (the ledger's holdings).
async function auditChunk(env) {
  const sd = await verifyDescriptor(env, call);             // forged/unsigned/malformed → null (§4.3)
  if (!sd) return null;
  const d = sd.descriptor;
  const live = await liveHolders(d);
  if (toHex(sd.authorPk) === myPeer()) recordHoldings(chunkKey(env), d, live);
  await retier(d, live);
  const margin = lossMargin(d, dependableCopies(d, live));
  if (margin < lowWaterMargin(d)) return { d, env, live, margin };
  repairHints.delete(chunkKey(env)); // healthy: the next shortfall may be deferred again
  return null;
}
// Audit one chunk and, if it is short, ask for its repair.
async function repairChunk(env) {
  const short = await auditChunk(env);
  return short ? requestRepairs(short.d, short.env, short.live, short.margin) : 0;
}
// Move this node's copies of an audited chunk between the §14 tiers. A copy past its block's
// target is surplus and drops to cache; a cached copy the chunk needs again is committed.
// Every holder sorts a block's live holders the same way, dependable ones first and then by
// key, and keeps the first `target`: only the copies past the target step down, the least
// dependable first, and a view that missed a holder keeps more.
async function retier(d, live) {
  const me = myPeer();
  for (const [h, target] of copyTargets(d)) {
    if (!live.get(h)?.has(me)) continue;
    await ensureStoreIndex();
    const e = heldBlocks.get(h);
    if (!e || pendingDeletes.has(h)) continue;
    const order = [...(live.get(h) || [])].sort((a, b) =>
      (Number(dependable(d.group, b)) - Number(dependable(d.group, a))) || (a < b ? -1 : a > b ? 1 : 0));
    const keep = order.indexOf(me) < target;
    if (keep === e.cache) await setTier(h, !keep, call);
  }
}

// ── repairs this node agreed to ──
// block hex → { size, author, group }: the room a promised repair holds until its block
// lands or the attempt ends. It counts against quota and the author's allowance, and as a
// sibling, but HAVE does not report it held.
const pendingRepairs = new Map();
let pendingRepairBytes = 0;
const pendingFor = new Map(); // allowanceKey → bytes promised for that author in that group
function reserveRepair(h, size, author, group) {
  pendingRepairs.set(h, { size, author, group });
  pendingRepairBytes += size;
  const key = allowanceKey(group, author);
  pendingFor.set(key, (pendingFor.get(key) ?? 0) + size);
}
function dropRepair(h) {
  const p = pendingRepairs.get(h);
  if (!p) return null;
  pendingRepairs.delete(h);
  pendingRepairBytes -= p.size;
  const key = allowanceKey(p.group, p.author);
  pendingFor.set(key, pendingFor.get(key) - p.size);
  return p;
}
// { target, descriptor, hints, attempt, due, until }: agreed repairs, each run once `due`.
const repairJobs = [];
// A fetch that fails is tried again, backing off, until the promise's window closes. Two
// nodes each mid-pass can wait on each other until their requests time out, so a first
// failure is ordinary.
const REPAIR_RETRY_MS = 500, REPAIR_RETRY_MAX_MS = 30 * 1000;
let wakeDue = Infinity; // when the armed wake fires, Infinity for none
// Jobs run on a wake, after the request that asked for them has been answered, so no
// request handler waits on the network. The wake is armed for the earliest job due.
async function armRepairWake(via) {
  if (repairJobs.length === 0) return;
  const t = Date.now();
  const due = Math.max(t, Math.min(...repairJobs.map((j) => j.due)));
  if (due >= wakeDue) return;
  wakeDue = due;
  const ms = new Uint8Array(4);
  wU32(ms, 0, due - t);
  try { await via("timer/arm", ms); } catch { wakeDue = Infinity; }
}
// The most urgent due job: the lowest margin its asker reported, the earliest agreed on a tie.
function takeDueJob(t) {
  let best = -1;
  for (let i = 0; i < repairJobs.length; i++) {
    const j = repairJobs[i];
    if (j.due <= t && (best < 0 || j.margin < repairJobs[best].margin)) best = i;
  }
  return best < 0 ? null : repairJobs.splice(best, 1)[0];
}
// One job per wake, so a wake is one bounded invocation; the next is armed while any remain.
async function onWake() {
  wakeDue = Infinity;
  const job = takeDueJob(Date.now());
  if (job) await runRepairJob(job);
  await armRepairWake(call);
  return EMPTY;
}
async function drainRepairJobs() {
  for (let job; (job = takeDueJob(Date.now())) !== null;) await runRepairJob(job);
  await armRepairWake(call);
}
// Fetch, rebuild, check and store one agreed block. A k = 1 block, or any block a live
// holder still has, is copied; a lost coded block is decoded from any k blocks and
// re-encoded. The fetches are marked as this chunk's repair, which tells each holder that
// serves one to leave the chunk be (§9).
async function runRepairJob(job) {
  const h = toHex(job.target);
  try {
    const d = parseSignedDescriptor(job.descriptor).descriptor;
    const key = chunkKey(job.descriptor), me = myPeer();
    const holders = new Map();
    for (const { peer, blockId } of job.hints) {
      if (peer === me) continue;
      const bh = toHex(blockId);
      let s = holders.get(bh); if (!s) holders.set(bh, (s = new Set()));
      s.add(peer);
    }
    const got = new Map();
    let bytes = null;
    if (holders.has(h)) {
      await gatherBlocks([{ ...d, k: 1, blockIds: [job.target] }], holders, got, key);
      bytes = got.get(h) ?? null;
    }
    if (bytes === null && d.k > 1) {
      await gatherBlocks([d], holders, got, key);
      const present = [];
      for (let i = 0; i < d.blockIds.length && present.length < d.k; i++) {
        const b = got.get(toHex(d.blockIds[i]));
        if (b) present.push({ index: i, bytes: b });
      }
      if (present.length >= d.k) {
        const data = await rsDecode(d.k, d.m, d.blockSize, present);
        const all = [...data, ...await rsEncode(d.k, d.m, d.blockSize, data)];
        const i = d.blockIds.findIndex((id) => bytesEqual(id, job.target));
        // Re-certify against the signed id (§9): a bad input or decode is dropped, never stored.
        if (i >= 0 && bytesEqual(await blockHash(d, all[i], call), job.target)) bytes = all[i];
      }
    }
    if (bytes !== null) return commitRepair(h, bytes, job.descriptor, d.group);
    const delay = Math.min(REPAIR_RETRY_MAX_MS, REPAIR_RETRY_MS * 2 ** job.attempt);
    if (Date.now() + delay < job.until) {
      job.attempt++;
      job.due = Date.now() + delay;
      repairJobs.push(job);
      return;
    }
  } catch {
    // A malformed job cannot get better by waiting.
  }
  // The promise lapses: the room goes, and the chunk's repair note expires on its own.
  dropRepair(h);
}
// Turn a promised repair into a held block, evicting cache for room as a STORE does.
async function commitRepair(h, bytes, env, group) {
  await ensureStoreIndex();
  const p = dropRepair(h);
  if (!p || heldBlocks.has(h) || pendingDeletes.has(h)) return;
  const short = p.size - (quota() - bytesUsed);
  const evicted = short > 0 ? pickCacheVictims(short) : [];
  indexSet(h, p.size, p.author, p.group, false);
  liveStoreReservations.set(h, { size: p.size, author: p.author, group: p.group });
  storeReservationVersion++;
  await deleteBlocks(evicted, call);
  try { await storeWrite(fromHex(h), bytes, env, group); } catch { /* storeWrite marked the index for a rebuild */ }
}
// Accept or decline one REPAIR request (§9), under the same admission a STORE meets.
async function acceptRepair(payload, caller) {
  let req;
  try { req = decodeRepairReq(payload); } catch { return VERDICT_DESCRIPTOR; }
  const [verdict] = await admitBatch([{ blockId: req.target, descriptor: req.descriptor }], caller, ADMIT_REPAIR);
  if (verdict !== VERDICT_ACCEPTED) return verdict;
  // Copies: the request is a view of a frame that is gone once this answer is.
  const t = Date.now();
  repairJobs.push({
    target: req.target.slice(), descriptor: req.descriptor.slice(),
    hints: req.hints.map((x) => ({ peer: x.peer, blockId: x.blockId.slice() })),
    margin: req.margin, attempt: 0, due: t, until: t + REPAIR_NOTE_MS,
  });
  await armRepairWake(holderCall);
  return VERDICT_ACCEPTED;
}

// A repair pass (§9): run the repairs this node agreed to that are due, audit every chunk it
// holds a block of, then ask for the repair of those that are short, all at the end of the
// pass and together, so the members asked are answered before they start fetching from this
// node. Then bring the store back under quota if it is over. A chunk is told apart by its
// descriptor's signature, with no hash call: every stored descriptor was verified on
// admission, and two verified envelopes sharing a signature is a forgery. Answers how many
// repairs members agreed to.
async function doRepair() {
  await drainRepairJobs();
  await observeAvailability();
  const seen = new Set(), short = [];
  const audit = async (env) => {
    const key = chunkKey(env);
    if (seen.has(key)) return;
    seen.add(key);
    const s = await auditChunk(env);
    if (s) short.push(s);
  };
  for (const id of await storeList()) {
    const descriptor = await storeGetDescriptor(id, call);
    if (descriptor) await audit(descriptor);
  }
  for (const env of await nextOwnChunks()) await audit(env);
  short.sort((a, b) => a.margin - b.margin); // the most urgent asked first
  const counts = await Promise.all(short.map((s) => requestRepairs(s.d, s.env, s.live, s.margin)));
  const requested = counts.reduce((a, b) => a + b, 0);
  await relieveQuota();
  const out = new Uint8Array(4);
  wU32(out, 0, requested);
  return out;
}
// Over quota (§14 eviction, steps 1 and 3), as when the operator lowers it: drop cache,
// coldest first, then release commitments, those for the lowest-standing authors first.
async function relieveQuota() {
  await ensureStoreIndex();
  if (bytesUsed <= quota()) return;
  await deleteBlocks(pickCacheVictims(bytesUsed - quota()), call);
  if (bytesUsed <= quota()) return;
  const t = Date.now(), standing = new Map(); // allowanceKey → the author's standing in that group
  const committed = [...heldBlocks].filter(([h, e]) => !e.cache && !pendingDeletes.has(h));
  for (const [, e] of committed) {
    const key = allowanceKey(e.group, e.author);
    if (!standing.has(key)) standing.set(key, await repScore(e.group, fromHex(e.author), t));
  }
  const standingOf = (e) => standing.get(allowanceKey(e.group, e.author));
  committed.sort(([ha, a], [hb, b]) => (standingOf(a) - standingOf(b)) || (touchedAt(ha) - touchedAt(hb)));
  for (const [h] of committed) {
    if (bytesUsed <= quota()) break;
    await releaseCommitment(h);
  }
}
// Graceful release (§14): drop this copy once the chunk stays at or above low water
// without it. Until then, ask members to repair the copies it would leave missing, and try
// again on a later pass, so shedding never itself leaves the chunk short.
async function releaseCommitment(h) {
  const rec = await storeGet(fromHex(h), call);
  const sd = rec && await verifyDescriptor(rec.descriptor, call);
  if (sd) {
    const d = sd.descriptor, me = myPeer();
    const live = await liveHolders(d);
    const margin = lossMargin(d, dependableCopies(d, live, me));
    if (margin < lowWaterMargin(d)) {
      await requestRepairs(d, rec.descriptor, live, margin, me);
      return false;
    }
  }
  await ensureStoreIndex();
  if (!heldBlocks.has(h) || pendingDeletes.has(h)) return false;
  await deleteBlocks([claimForDelete(h)], call);
  return true;
}

// ── holder side (§5/§6/§7) ───────────────────────────────────────────────────
// The request side a node serves to its cohort: admission control (§6 sibling rule,
// §14 quota and tiers, §13.2 allowance), content-addressing (§4.2), and durable record writes — confined
// here; the host keeps only a read view (host/store-view.ts), no write path. Async,
// since every seam name answers a Promise (seedkernel §12.2), fs included.
// The index of what is held, rebuilt from fs on first use: heldBlocks maps block hex →
// { size, author (hex), group, cache }. bytesUsed counts both §14 tiers and cacheBytes the
// cache alone; committedFor charges each author's committed bytes in a group to its
// allowance there (§13.2), keyed by allowanceKey.
let bytesUsed = -1, cacheBytes = 0, heldBlocks = null, storeIndexPromise = null, storeIndexDirty = false;
let committedFor = new Map();
const touched = new Map();        // block hex → when a peer last fetched or stored it (coldness, §14)
const pendingDeletes = new Set(); // claimed for deletion: out of the index, still on disk and a sibling
let activeStoreWrites = 0, resolveStoreWritesIdle = null, storeWritesIdle = Promise.resolve();
const liveStoreReservations = new Map(); // block hex → { size, author, group }
let storeReservationVersion = 0;
// The §14 byte budget is OPERATOR policy: read from LOCAL alone, never CFG (an
// author-signed `quota` in CFG would let a bundle grant itself disk). No generous
// default either — an under-injecting driver falls to 0 and FAILS CLOSED.
function quota() { return LOCAL.quota != null ? LOCAL.quota : 0; }
// How much of the quota an author's blocks may fill in one group (§13.2): newcomerShare of
// it to start, plus what the author verifiably holds for this node there, up to the whole
// quota, so the group holds for a peer about as much as it holds for the group. Nothing
// while it fails more checks than it passes.
function allowanceFor(reliability, heldForThisNode) {
  const share = CFG.newcomerShare;
  if (!(share >= 0 && share <= 1)) throw new Error("config: no newcomerShare — the host derives it (core.ts normaliseConfig)");
  return reliability < 0 ? 0 : Math.min(quota(), quota() * share + heldForThisNode);
}
function allowanceKey(group, authorHex) { return group + "/" + authorHex; }
function touchedAt(h) { return touched.get(h) ?? 0; }
function charge(e, sign) {
  const key = allowanceKey(e.group, e.author);
  committedFor.set(key, (committedFor.get(key) ?? 0) + sign * e.size);
}
function indexSet(h, size, author, group, cache) {
  const e = { size, author, group, cache };
  heldBlocks.set(h, e);
  bytesUsed += size;
  if (cache) cacheBytes += size; else charge(e, 1);
}
function indexDrop(h) {
  const e = heldBlocks.get(h);
  if (!e) return;
  heldBlocks.delete(h);
  touched.delete(h);
  bytesUsed -= e.size;
  if (e.cache) cacheBytes -= e.size; else charge(e, -1);
}
// Every write or delete runs between these, so a rebuild waits for the store to settle.
function beginStoreWrite() {
  if (activeStoreWrites++ === 0) storeWritesIdle = new Promise((resolve) => { resolveStoreWritesIdle = resolve; });
}
function endStoreWrite() {
  if (--activeStoreWrites === 0 && resolveStoreWritesIdle) {
    const resolve = resolveStoreWritesIdle; resolveStoreWritesIdle = null; resolve();
  }
}
async function fsSize(keyStr) { const v = rU32(await holderCall("fs/size", strBytes(keyStr), 4), 0); return v === 0xffffffff ? 0 : v; }
// A cold holder's index can take thousands of fs/size calls; the holder's share of the
// host-call budget (hostBudget) paces them under the host's per-realm cap.
async function ensureStoreIndex() {
  if (!storeIndexDirty && heldBlocks !== null && bytesUsed >= 0) return;
  if (storeIndexPromise === null) storeIndexPromise = (async () => {
    // Rebuild only from a stable durable snapshot. Admission may have resumed from an
    // earlier clean ensureStoreIndex() while the fs calls are in flight, so merge its
    // still-live reservations and retry if any reservation landed or settled across
    // the seam calls. This keeps both quota charges and sibling exclusions.
    for (;;) {
      if (activeStoreWrites > 0) await storeWritesIdle;
      const reservationVersion = storeReservationVersion;
      // A block is held when both files are: storeWrite writes the tag first, so a
      // record without one never committed.
      const recs = new Set(), tagged = [];
      for (const key of await storeKeys()) {
        if (key.length !== 68) continue;
        if (key.endsWith(STORE_REC)) recs.add(key.slice(0, 64));
        else if (key.endsWith(STORE_TAG)) tagged.push(key.slice(0, 64));
      }
      const entries = (await Promise.all(tagged.filter((hex) => recs.has(hex)).map(async (hex) => {
        const tag = decodeStoreTag(await fsGet(hex + STORE_TAG, holderCall, STORE_TAG_MAX + 1));
        return tag && { hex, size: await fsSize(hex + STORE_REC), author: toHex(tag.author), group: tag.group, cache: tag.tier === TIER_CACHE };
      }))).filter((e) => e);
      if (reservationVersion !== storeReservationVersion || activeStoreWrites > 0) continue;
      heldBlocks = new Map();
      bytesUsed = 0; cacheBytes = 0; committedFor = new Map();
      for (const e of entries) indexSet(e.hex, e.size, e.author, e.group, e.cache);
      for (const [hex, r] of liveStoreReservations) if (!heldBlocks.has(hex)) indexSet(hex, r.size, r.author, r.group, false);
      storeIndexDirty = false;
      return;
    }
  })();
  try { await storeIndexPromise; } finally { storeIndexPromise = null; }
}
async function fsPut(keyStr, parts, via) {
  const kb = strBytes(keyStr);
  const head = new Uint8Array(4); wU32(head, 0, kb.length);
  // Frame the fs call and durable record in one pass. Building a record first and
  // framing it again would copy every block-sized payload twice in the guest.
  await via("fs/put", concat([head, kb, ...parts]));
}
async function writeTag(h, cache, via) {
  const e = heldBlocks.get(h);
  if (!e) return;
  beginStoreWrite();
  try { await fsPut(h + STORE_TAG, [encodeStoreTag(cache ? TIER_CACHE : TIER_COMMITTED, fromHex(e.author), e.group)], via); }
  finally { endStoreWrite(); }
}
// Move a held block between the tiers: the index at once, its tag after.
async function setTier(h, cache, via) {
  const e = heldBlocks.get(h);
  if (!e || e.cache === cache) return;
  indexDrop(h);
  indexSet(h, e.size, e.author, e.group, cache);
  try { await writeTag(h, cache, via); } catch { storeIndexDirty = true; }
}
// The one write path into the store: the tag, then one framed record, under the quota budget.
//
// Backend failures (full disk, backend error, realm OOM) surface as holder errors:
// a holder has no console, so the verdict byte is its only way to report them.
async function storeWrite(id, bytes, descriptor, group) {
  const hex = toHex(id);
  beginStoreWrite();
  try {
    await fsPut(hex + STORE_TAG, [encodeStoreTag(TIER_COMMITTED, descriptor.subarray(0, 32), group)], holderCall);
    await fsPut(hex + STORE_REC, [storeRecordHead(descriptor.length), descriptor, bytes], holderCall);
    touched.set(hex, Date.now());
  } catch (e) {
    // A failed write may still have left a partial file. The next admission rebuilds
    // after all concurrent commits settle instead of guessing which bytes landed.
    storeIndexDirty = true;
    throw e;
  } finally {
    if (liveStoreReservations.delete(hex)) storeReservationVersion++;
    endStoreWrite();
  }
}
// Claim a held block for deletion, synchronously: it leaves the index and frees its quota
// now, and stays a sibling until deleteBlocks has removed its files.
function claimForDelete(h) {
  beginStoreWrite();
  pendingDeletes.add(h);
  indexDrop(h);
  return h;
}
// Claim cache blocks, coldest first, until `need` bytes are free or the cache is empty.
function pickCacheVictims(need) {
  const cold = [...heldBlocks].filter(([h, e]) => e.cache && !pendingDeletes.has(h)).sort(([a], [b]) => touchedAt(a) - touchedAt(b));
  const out = [];
  for (let i = 0, freed = 0; i < cold.length && freed < need; i++) { freed += cold[i][1].size; out.push(claimForDelete(cold[i][0])); }
  return out;
}
async function deleteBlocks(hexes, via) {
  await Promise.all(hexes.map(async (h) => {
    try {
      await via("fs/delete", strBytes(h + STORE_REC));
      await via("fs/delete", strBytes(h + STORE_TAG));
    } catch {
      storeIndexDirty = true; // a record may survive: rebuild from what is on disk
    } finally {
      pendingDeletes.delete(h);
      endStoreWrite();
    }
  }));
}
// What an admission is for: OFFER checks only; STORE reserves the block in the index for the
// write that follows; REPAIR reserves room for a block this node will rebuild itself.
const ADMIT_OFFER = 0, ADMIT_STORE = 1, ADMIT_REPAIR = 2;
// Admission (§4.3 descriptor, §5.1 group, §6 sibling rule, §14 quota, §13.2 allowance),
// enforced by the holder itself so the §10 invariant survives a malicious placer. A batch is
// checked cumulatively: room, allowance and siblings count as blocks are provisionally
// accepted. Bytes are pushed (OFFER, STORE) only by the chunk's author; anyone else's copy is
// one this node pulls, after a REPAIR request (§9). Every block, pushed or pulled, counts
// against its author's allowance in the chunk's group. A STORE passes `size`, the block in
// hand, and `parsed`, the descriptor it already parsed to hash it, and collects the cache
// blocks evicted to make room in `evicted`. The signed descriptor is required on every path —
// no descriptor-less branch past the sibling rule. `caller` sent the batch.
async function admitBatch(offers, caller, mode = ADMIT_OFFER, evicted = null) {
  // A batch is one immutable admission snapshot. Issue its independent seam work
  // together (the holder's budget share paces it), then apply quota +
  // provisional-sibling decisions in wire order.
  const signed = await Promise.all(offers.map((o) => verifyDescriptor(o.descriptor, holderCall, o.parsed)));
  const callerHex = toHex(caller), me = myPeer();
  const allowance = new Map(); // allowanceKey → the author's allowance in that group
  const t = Date.now();
  for (const sd of signed) {
    if (!sd) continue;
    const key = allowanceKey(sd.descriptor.group, toHex(sd.authorPk));
    if (!allowance.has(key)) {
      const rel = await repScore(sd.descriptor.group, sd.authorPk, t, holderCall);
      allowance.set(key, allowanceFor(rel, heldFor(sd.descriptor.group, toHex(sd.authorPk))));
    }
  }
  // Do this after crypto/score awaits: once it returns, the quota/sibling decision
  // and the reservations below run without yielding, making the snapshot atomic
  // with respect to other inbound calls while disk writes remain concurrent.
  await ensureStoreIndex();
  // Cache gives way to commitments, so a commitment needs room only beside the committed
  // tier and the repairs this node has promised.
  let room = Math.max(0, quota() - (bytesUsed - cacheBytes) - pendingRepairBytes);
  const used = new Map(); // allowanceKey → bytes counted for that author so far, this batch included
  const usedBy = (key) => used.get(key) ?? (committedFor.get(key) ?? 0) + (pendingFor.get(key) ?? 0);
  const held = (h) => heldBlocks.has(h) || pendingDeletes.has(h) || pendingRepairs.has(h);
  const provisional = new Set();
  const verdicts = [];
  for (let oi = 0; oi < offers.length; oi++) {
    const o = offers[oi], sd = signed[oi];
    if (!sd) { verdicts.push(VERDICT_DESCRIPTOR); continue; }          // absent, forged, unsigned, or malformed
    const d = sd.descriptor, authorHex = toHex(sd.authorPk);
    // ANCHOR the signature (§4.3) in the roster (§5.1): the author must be a member of the
    // group the chunk names, or this node itself, and so must the caller. A key that merely
    // signed proves nothing, since the envelope carries its own pubkey.
    if (!inGroup(d.group, callerHex) || (authorHex !== me && !inGroup(d.group, authorHex))) { verdicts.push(VERDICT_GROUP); continue; }
    if (mode !== ADMIT_REPAIR && authorHex !== callerHex) { verdicts.push(VERDICT_NOT_AUTHOR); continue; }
    if (!descriptorContains(d, o.blockId)) { verdicts.push(VERDICT_DESCRIPTOR); continue; } // not a block of this chunk
    // Geometry is the SIGNED descriptor's, never a field the sender picks: every block
    // is exactly blockSize bytes, so bytes in hand that disagree are not the block that
    // was offered, whatever they hash to.
    if (o.size != null && o.size !== d.blockSize) { verdicts.push(VERDICT_DESCRIPTOR); continue; }
    // Charge exactly what storeWrite commits: frame + descriptor + ciphertext.
    const cost = STORE_REC_HEAD + d.blockSize + o.descriptor.length;
    if (cost > room) { verdicts.push(VERDICT_QUOTA); continue; }
    const key = allowanceKey(d.group, authorHex);
    if (usedBy(key) + cost > allowance.get(key)) { verdicts.push(VERDICT_ALLOWANCE); continue; }
    // The sibling rule, over the whole id list. A block this holder ALREADY has counts:
    // a k=1 chunk lists its one block m+1 times, so those m+1 slots are m+1 distinct
    // peers — accepting a second copy here would silently burn one of them and leave the
    // chunk short of replicas while looking placed.
    if (provisional.has(toHex(o.blockId)) || held(toHex(o.blockId))) { verdicts.push(VERDICT_SIBLING); continue; }
    let sibling = false;
    for (const sib of d.blockIds) {
      if (bytesEqual(sib, o.blockId)) continue;
      if (provisional.has(toHex(sib)) || held(toHex(sib))) { sibling = true; break; }
    }
    if (sibling) { verdicts.push(VERDICT_SIBLING); continue; }
    room -= cost;
    used.set(key, usedBy(key) + cost);
    const blockHex = toHex(o.blockId);
    provisional.add(blockHex);
    if (mode === ADMIT_STORE) {
      // Evict cache (§14 step 1) for whatever the free space falls short of.
      const short = cost - (quota() - bytesUsed);
      if (short > 0) for (const h of pickCacheVictims(short)) evicted.push(h);
      indexSet(blockHex, cost, authorHex, d.group, false);
      liveStoreReservations.set(blockHex, { size: cost, author: authorHex, group: d.group });
      storeReservationVersion++;
    } else if (mode === ADMIT_REPAIR) {
      reserveRepair(blockHex, cost, authorHex, d.group);
    }
    verdicts.push(VERDICT_ACCEPTED);
  }
  return verdicts;
}
async function acceptStoreBatch(stores, caller) {
  // Hashes are independent. Binding admission atomically reserves quota + ids in the
  // holder index, then the independent single-record writes can overlap safely. Each
  // descriptor is parsed once, here, and admission verifies its signature over that parse.
  const parsed = stores.map((s) => {
    try { return parseSignedDescriptor(s.descriptor); } catch { return null; }
  });
  const hashes = await Promise.all(stores.map((s, i) => parsed[i] ? blockHash(parsed[i].descriptor, s.bytes, holderCall) : null));
  const verdicts = parsed.map((sd) => sd ? VERDICT_DECLINED : VERDICT_DESCRIPTOR);
  const valid = [];
  for (let i = 0; i < stores.length; i++) {
    if (hashes[i] && bytesEqual(hashes[i], stores[i].blockId)) valid.push({ index: i, store: stores[i] });
  }
  const evicted = [];
  const admitted = await admitBatch(valid.map(({ index, store: s }) => ({
    blockId: s.blockId, descriptor: s.descriptor, size: s.bytes.length, parsed: parsed[index],
  })), caller, ADMIT_STORE, evicted);
  await Promise.all([deleteBlocks(evicted, holderCall), ...valid.map(async ({ index, store: s }, i) => {
    if (admitted[i] !== VERDICT_ACCEPTED) { verdicts[index] = admitted[i]; return; }
    try { await storeWrite(s.blockId, s.bytes, s.descriptor, parsed[index].descriptor.group); verdicts[index] = VERDICT_ACCEPTED; }
    catch { verdicts[index] = VERDICT_ERROR; }
  })]);
  return verdicts;
}
// Serve a batched FETCH, capped at maxMsgBytes. A held block that won't fit, or an id never
// read, answers FETCH_UNANSWERED (re-asked); the first present block is always served, so
// every request makes progress. Reads stop at the cap too: an id costs 32 bytes to ask for
// and a whole block to look up, so reading the whole request let one message pull far more
// off the store than any reply carries.
const FETCH_MISS_ALLOWANCE = 256;   // reads past one full reply's worth, since a miss costs no reply bytes
async function serveFetch(ids) {
  const cap = maxMsgBytes();
  // Unread ids answer UNANSWERED: "ask again" is the only honest verdict for one we
  // never looked up. A genuine miss (read, not held) overwrites it with null → ABSENT.
  const out = new Array(ids.length).fill(FETCH_UNANSWERED);
  const order = [], queued = new Set(); // distinct ids in ask order, so a repeat is one read
  for (const id of ids) { const h = toHex(id); if (!queued.has(h)) { queued.add(h); order.push([h, id]); } }
  const maxReads = Math.min(order.length, fetchMaxIds() + FETCH_MISS_ALLOWANCE);
  const seen = new Map();  // idHex → bytes | null, for the ids read so far
  let used = BATCH_HEAD;   // the [count u32] response header
  let servedAny = false, read = 0;
  for (let i = 0; i < ids.length; i++) {
    const h = toHex(ids[i]);
    if (!seen.has(h)) {
      if (read >= maxReads) break;  // read enough to fill a reply; the tail re-asks
      // Read ahead by what the REMAINING budget could still hold, at OUR blockSize — a
      // foreign author's may differ, so this sizes the read, never the cap check below.
      const room = Math.max(1, Math.floor((cap - used) / (CFG.blockSize + FETCH_ENTRY_HEAD)));
      const upto = Math.min(maxReads, read + room);
      const batch = order.slice(read, upto);
      const bytes = await Promise.all(batch.map(([, id]) => storeGetBytes(id, holderCall)));
      for (let j = 0; j < batch.length; j++) seen.set(batch[j][0], bytes[j]);
      read = upto;
    }
    const bytes = seen.get(h);
    if (!bytes) { out[i] = null; continue; } // genuine miss — ABSENT
    const framed = bytes.length + FETCH_ENTRY_HEAD;
    // Full: stop here rather than scanning on for a smaller block that still fits —
    // reading the rest is the amplification, and this id re-asks either way.
    if (servedAny && used + framed > cap) break;
    out[i] = bytes;
    touched.set(h, Date.now());
    used += framed;
    servedAny = true;
  }
  return out;
}
// The wire codecs a holder decodes/encodes (HAVE/OFFER/STORE/FETCH, encodeMask) come
// from the shared host/protocol.ts — the holder admits over the same §18 format the
// initiator speaks, by construction.

// The one entrypoint, declared top-level: the host invokes `handle` with
// `[caller 32][body …]` and nothing else (seedkernel §12.2). A peer's control message
// is `[type u8][payload]`; a STORE batch's writes overlap, its quota and sibling
// reservations already taken atomically in admitBatch.
async function handle(arg) {
  // The host's part of the argument is exactly the 32-byte caller; everything
  // after it is THIS app's own shape (util.ts `callerOf`/`readOp`) - the same shape
  // the host-side `invoke` uses.
  const { fromHost, caller, body } = callerOf(arg);
  // The host's loopback (caller = 32 zero bytes) drives the initiator ops; a peer's
  // frame carries a MsgType byte instead of an op name, and the caller id tells them apart.
  if (fromHost) {
    const { op, args: payload } = readOp(body);
    switch (op) {
      case Op.PUT: return doPut(payload);
      case Op.PUT_START: return doPutStart(payload);
      case Op.PUT_WINDOW: return doPutWindow(payload);
      case Op.PUT_FINISH: return putFinish();
      case Op.GET: return doGet(payload);
      case Op.GET_START: return doGetStart(payload);
      case Op.GET_NEXT: return getNext();
      case Op.REPAIR: return doRepair();
      case Op.REQUEST: return doRequest(payload);
      case Op.WARM: return doWarm();
      case Op.SCORE: return repScoreBytes(groupName(payload.subarray(32)), payload.subarray(0, 32), Date.now());
      case Op.GROUPS: setRoster(decodeGroups(payload)); return EMPTY;
      case Op.STATS: return encodeStats();
      case "wake": return onWake();
      default: return EMPTY;
    }
  }
  // A peer's wire frame: answer it, timing + counting it as holder work (the
  // `recv*` half of the STATS op, since the host has no inbound seam of its own).
  const type = body[0], payload = body.subarray(1); // a view — the decoders below own no bytes
  // A link is not membership (§5.1): a peer in none of this node's groups learns nothing,
  // not even what it holds, and an empty answer is what a turned-away request gets.
  if (!rosterMembers.has(toHex(caller))) return EMPTY;
  const t0 = Date.now();
  let out;
  if (type === MsgType.HAVE) out = encodeMask(await Promise.all(decodeHaveReq(payload).map((id) => storeHas(id))));
  else if (type === MsgType.OFFER) out = encodeMask(await admitBatch(decodeOfferBatch(payload), caller));
  else if (type === MsgType.STORE) out = encodeMask(await acceptStoreBatch(decodeStoreBatch(payload), caller));
  else if (type === MsgType.FETCH) out = encodeFetchBatchRes(await serveFetch(decodeFetchBatchReq(payload)));
  else if (type === MsgType.REPAIR) out = encodeMask([await acceptRepair(payload, caller)]);
  else if (type === MsgType.REPAIR_FETCH && payload.length >= 64) {
    const ids = decodeFetchBatchReq(payload.subarray(64));
    await hintFromRepairFetch(caller, toHex(payload.subarray(0, 64)), ids);
    out = encodeFetchBatchRes(await serveFetch(ids));
  }
  else out = EMPTY;
  statsRecv[type]++;
  statsRecvBytes[type] += payload.length;
  statsRecvMs[type] += Date.now() - t0;
  return out;
}

// ── one control message, on the host's behalf ────────────────────────────────
// arg = [to 32][type u8][payload] — the mirror image of `handle`, and the only way
// a host-side caller reaches a peer (seedkernel §12.10). Grants nothing new: the same netSend
// the placement engine drives, exposed as a local op (Op.REQUEST) rather than a
// second entrypoint. Answers `[ok u8][response]`; unreachable is `[0]`.
async function doRequest(arg) {
  const resp = await netSend(toHex(arg.subarray(0, 32)), arg[32], arg.subarray(33), MSG_ENVELOPE_BYTES + maxMsgBytes());
  return resp === null ? Uint8Array.from([0]) : concat([Uint8Array.from([1]), resp]);
}

// ── warm (boot-time JIT warmup) ──────────────────────────────────────────────
// One throwaway RS encode + decode + verify under a random key, no network/store,
// run once at boot. Pays the engine's cold-JIT tax on codec + crypto up front, since a cold
// realm's first real PUT would otherwise pay it (~0.25s for 10 MB) in front of the
// transfer. Self-contained and idempotent; the result is discarded.
async function doWarm() {
  const c = CFG;
  const K = await randomKey();
  const perRound = Math.max(1, c.k) * c.blockSize;
  const buf = new Uint8Array(perRound);
  // Push ~4 MB through (what a real PUT's first chunks take to JIT-tier up),
  // capped at 64 rounds so a tiny test-scale blockSize can't spin forever.
  const rounds = Math.min(64, Math.max(1, Math.ceil((4 * 1024 * 1024) / perRound)));
  for (let r = 0; r < rounds; r++) {
    // `r` is both the chunk index and the nonce counter — must advance each round
    // or this becomes a two-time pad (nothing here leaves the realm, but don't copy
    // this loop as an example with a fixed counter).
    const chunk = await encodeChunk(buf, 0, r, K, LEVEL_BODY, "warm");                       // encrypt + RS-encode + hash + sign
    const sd = await verifyDescriptor(chunk.descriptor, call);                   // Ed25519 verify (+ §16 scope preimage)
    // Warm the decode seam too, at k ≥ 2 only — a k=1 deployment never reaches the
    // codec on PUT/GET/repair, so there's no cold-JIT tax there to pay down.
    if (sd && sd.descriptor.k > 1) {
      await rsDecode(c.k, c.m, c.blockSize, chunk.slotBlocks.slice(0, c.k).map((bytes, index) => ({ index, bytes })));
    }
  }
  return EMPTY;
}

// The Tier-2 guest: the whole storage protocol (README §6/§7/§9) as zero-authority
// JS running inside the QuickJS realm (§2.1) — placement, k-of-n, admission, wire
// format, and repair. Reached only through `host.call(name, bytes)` (seedkernel §12.2);
// net/fs/module calls resolve async, crypto/clock resolve sync.
//
// Both roles (initiator and holder) share this one realm/entrypoint (`handle`,
// split by `callerOf`/`readOp`); the realm's per-realm FIFO (seedkernel
// realm-queue.ts) keeps them from interleaving.
//
// A plain script (no imports/exports/ambient authority), prepended with `APP`/`LOCAL`
// config and the safe-js preamble by the host before running. Hosted by JSC (Bun)
// today, WAMR later — one artifact, both runtimes.

"use strict";

// ── byte helpers ────────────────────────────────────────────────────────────
// toHex/fromHex/bytesEqual/concatBytes/writeU32BE/readU32BE/callerOf/readOp/writeOp are stitched in from
// host/util.ts by scripts/build-guest.mjs. Short local aliases for this body.
const concat = concatBytes, wU32 = writeU32BE, rU32 = readU32BE;
function splitBlocks(buf, blockSize) {
  const out = [];
  for (let o = 0; o < buf.length; o += blockSize) out.push(buf.slice(o, o + blockSize));
  return out;
}
function padTo(buf, len) {
  if (buf.length === len) return buf;
  const out = new Uint8Array(len);
  out.set(buf.subarray(0, Math.min(buf.length, len)));
  return out;
}

// The nonce's domain byte is the chunk's index-tree LEVEL (§4.3/§4.4): 0 is the file's
// own ciphertext, ℓ > 0 an index chunk over level ℓ−1. There is no manifest domain.
const LEVEL_BODY = 0;
const EMPTY = new Uint8Array(0);

function wU64(out, off, ms) {
  const hi = Math.floor(ms / 0x100000000);
  wU32(out, off, hi); wU32(out, off + 4, ms >>> 0);
}
function rU64(b, off) { return rU32(b, off) * 0x100000000 + rU32(b, off + 4); }
function readF64LE(b) { return new DataView(b.buffer, b.byteOffset, 8).getFloat64(0, true); }
// fs keys are ASCII (hex + a short suffix); QuickJS has no TextEncoder, so map
// chars to bytes by hand, the same way toHex/fromHex avoid Buffer.
function strBytes(s) { const o = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i) & 255; return o; }
function bytesToStr(b) { let s = ""; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return s; }

// ── the guest seam: storage policy over GENERIC kernel names ────────────────
// Thin wrappers over the seam's application-neutral names (crypto/fs/module/
// clock/node, seedkernel host/guest-seam.ts). All storage STRUCTURE — nonce
// convention, signed-descriptor envelope, wire format, store layout — lives here,
// never in the kernel. Crypto calls resolve sync; fs/net/module calls are async.

// The op bytes of the codec module (the guest owns its ABI). The reputation module's
// op bytes + request framing (REP_OBSERVE/REP_SCORE, encodeScoreReq/encodeObserveReq)
// come from the SHARED host/reputation-core.ts, stitched in ahead of this body — the same
// framing StorageNode.score uses host-side, so the two agree by construction.
const CODEC_ENCODE = 1, CODEC_DECODE = 2;     // assembly/codec/index.ts
// Control-plane message types carried over netSend (host/protocol.ts §18).
const MSG_HAVE = 1, MSG_OFFER = 2, MSG_FETCH = 3, MSG_STORE = 4;
// This app's wire protocol id (§12.10) — must match the bundle manifest's `protocols`
// entry (scripts/storage-bundle.mjs) so the receiving host routes frames here.
const NET_PROTO = strBytes("seedstore");
const HAVE_ID_LEN = 32;      // a HAVE/FETCH request names 32-byte block_ids (§18)
const FETCH_FRAME = 5;       // a present block costs [found u8][len u32] in a FETCH response (§18)
// New writes use one record per block: [descriptor length u32][descriptor][ciphertext].
// The legacy two-file layout remains readable so existing holders upgrade in place.
const STORE_REC = ".rec", STORE_BLK = ".blk", STORE_DSC = ".dsc", STORE_REC_HEAD = 4;
// The logical names this app's own modules are installed under. The guest calls them
// by the logical name from its manifest, straight through `host.call` — a name this
// realm did not declare as a local service, and that is not a host method (`service/call`),
// is this app's module (seedkernel §12.2). The seam resolves it against this app's map,
// so app keys never leave the host.
const CODEC_NAME = "codec";
const REP_NAME = "reputation";

// ── request statistics (§18, for the latency/bench harnesses) ────────────────
// The kernel has no host-side inbound seam, so these counters live here: `netSend`
// counts+peaks outbound requests, `doHandle` counts+times inbound holder work.
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
// quota() reads LOCAL alone so an author can't sign one. Mirrored by node.config
// in host/storage-node.ts — keep the two in sync.
const CFG = { ...APP, ...LOCAL };

// ── crypto primitives + storage framing ──
// Pure transforms reach the host under the `crypto/` prefix (seedkernel §12.2):
// BLAKE2b-256 for block-ids and ChaCha20-Poly1305 for at-rest encryption.
// node/sign and node/verify apply the scoped `DOMAIN_guest ‖ scope` prefix on the
// host side — the guest never holds or reconstructs it. Every seam name answers a
// Promise now, so every helper here is awaited by its callers.
function hash(bytes) { return host.call("crypto/blake2b-256", bytes); }
const P_SEAL = "crypto/chacha20poly1305-ietf/seal";
const P_OPEN = "crypto/chacha20poly1305-ietf/open";
function randomKey() { const n = new Uint8Array(4); wU32(n, 0, 32); return host.call("node/random", n); }
function identity() { return host.call("node/identity", EMPTY); }
let myPeerCache = null;
async function myPeer() {
  // Cache the in-flight Promise too: concurrent callers share one seam crossing.
  if (myPeerCache === null) myPeerCache = identity().then((pk) => toHex(pk));
  return myPeerCache;
}
// 12-byte nonce = [level u8][chunk index u32 BE][0…] (§4.4). A fresh random K per
// file makes this deterministic per-file namespace unique; level separates index data.
function nonce(level, index) { const n = new Uint8Array(12); n[0] = level & 255; wU32(n, 1, index >>> 0); return n; }
// The kernel's seal result is [ciphertext][tag 16]. Keep the tag in the signed
// descriptor so the ciphertext remains exactly k·blockSize for systematic RS.
async function encrypt(K, level, index, msg) {
  const sealed = await host.call(P_SEAL, concat([nonce(level, index), K, msg]));
  if (sealed.length !== msg.length + AUTH_TAG_LEN) throw new Error("encrypt: unexpected ChaCha20-Poly1305 output length");
  return { ciphertext: sealed.slice(0, msg.length), authTag: sealed.slice(msg.length) };
}
async function decrypt(K, level, index, ct, authTag) {
  if (!authTag || authTag.length !== AUTH_TAG_LEN) throw new Error("get: malformed ciphertext authentication tag");
  const opened = await host.call(P_OPEN, concat([nonce(level, index), K, ct, authTag]));
  if (opened.length !== ct.length + 1 || opened[0] !== 1) throw new Error("get: ciphertext authentication failed");
  return opened.slice(1);
}
// Signed chunk descriptor envelope: [authorPk 32][sig 64][core] (§4.3, §16).
// node/sign applies the scoped prefix and returns just the signature; the stored
// envelope carries only [pk][sig][core] — the prefix is preimage-only, never sent.
async function signCore(core) {
  const [pk, sig] = await Promise.all([identity(), host.call("node/sign", core)]);
  return concat([pk, sig, core]);
}
async function verifyEnv(env) {
  const v = await host.call("node/verify", concat([env.slice(0, 32), env.slice(32, 96), env.slice(96)]));
  return v[0] === 1;
}

// ── codec + reputation ──
// Both are ordinary `host.call`s (module name IS the seam's name arg, no header to
// build). Module calls are async (the module runs in its own worker), so encode/decode
// and their callers (encodeChunk, assembleChunk, the ranker) are async in turn.
async function rsEncode(k, m, blockSize, dataBlocks) {
  const head = new Uint8Array(7);
  head[0] = CODEC_ENCODE; head[1] = k; head[2] = m; wU32(head, 3, blockSize);
  const parity = splitBlocks(await host.call(CODEC_NAME, concat([head, ...dataBlocks])), blockSize);
  // Fail here, where the cause is, rather than as a far-away "blockIds.length must be
  // k or k+m" error or a chunk silently signed with the wrong shape.
  if (parity.length !== m) {
    throw new Error("rsEncode: codec returned " + parity.length + " parity blocks, expected " + m +
      " — chunk (k=" + k + " × blockSize=" + blockSize + ") likely exceeds the codec module's scratch");
  }
  return parity;
}
async function rsDecode(k, m, blockSize, present) {
  // Callers (assembleChunk, healCoded) already gate on present.length >= k, but
  // guard the codec seam itself so a short set is a clean throw, never a silently
  // truncated decode request (head[7] = use.length under k → garbage out).
  if (present.length < k) throw new Error("rsDecode: need at least k blocks to reconstruct");
  const use = present.slice(0, k);
  const head = new Uint8Array(8);
  head[0] = CODEC_DECODE; head[1] = k; head[2] = m; wU32(head, 3, blockSize); head[7] = use.length;
  const idx = new Uint8Array(use.length);
  for (let i = 0; i < use.length; i++) idx[i] = use[i].index;
  const data = splitBlocks(await host.call(CODEC_NAME, concat([head, idx, ...use.map((p) => p.bytes)])), blockSize);
  // A short/empty answer here (scratch too small for this descriptor's k·blockSize)
  // would otherwise silently reassemble from fewer blocks than the chunk has — nothing
  // on the read path re-verifies the codec's output (§4.2 only checks inputs). Must error.
  if (data.length !== k) {
    throw new Error("rsDecode: codec returned " + data.length + " blocks, expected " + k +
      " — chunk (k=" + k + " × blockSize=" + blockSize + ") likely exceeds the codec module's scratch");
  }
  return data;
}
async function clockNow() { const b = await host.call("clock/now", EMPTY); return rU32(b, 0) * 0x100000000 + rU32(b, 4); }

// Per-peer reputation accumulators (module is a pure transform; callers hold state).
// hex pubkey → {serve, miss, last}. Entries are created only by repObserve — a real
// witnessed event (§8) — never by a bare score query, which must stay side-effect-free.
const peerReps = new Map();

const ZERO_REP = { serve: 0, miss: 0, last: 0 };

async function repScore(peerPk, t) {
  return decodeScoreResp(await repScoreBytes(peerPk, t));
}
// Call the reputation module's SCORE op with the peer's accumulator at time t, or the
// zero accumulator for a peer never observed. Read-only: never touches peerReps.
async function repScoreBytes(peerPk, t) {
  const rep = peerReps.get(toHex(peerPk)) ?? ZERO_REP;
  const req = encodeScoreReq(rep.serve, rep.miss, rep.last, t);
  return host.call(REP_NAME, req);
}

// Record a witnessed pass/fail for a peer, awaiting the module call so the Map
// update actually lands (this is not fire-and-forget).
async function repObserve(peerPk, t, pass) {
  const peerHex = toHex(peerPk);
  let rep = peerReps.get(peerHex);
  if (rep === undefined) {
    pruneStalePeers(peerReps, t);
    rep = { serve: 0, miss: 0, last: 0 };
    peerReps.set(peerHex, rep);
  }
  const req = encodeObserveReq(rep.serve, rep.miss, rep.last, t, pass);
  try {
    const resp = await host.call(REP_NAME, req);
    const updated = decodeObserveResp(resp);
    rep.serve = updated.serve;
    rep.miss = updated.miss;
    rep.last = updated.last;
  } catch (e) {
    // Call sites treat reputation updates as fire-and-forget; swallow so a failure
    // here never surfaces as an unhandled rejection.
  }
}

// ── local store over fs ─────────────────────────────────────────────────────
// New blocks are one <hex>.rec; legacy <hex>.blk/.dsc pairs remain readable.
function decodeStoreRecord(rec) {
  if (!rec || rec.length < STORE_REC_HEAD) return null;
  const dlen = rU32(rec, 0);
  if (dlen === 0 || dlen > rec.length - STORE_REC_HEAD) return null;
  return { descriptor: rec.subarray(STORE_REC_HEAD, STORE_REC_HEAD + dlen), bytes: rec.subarray(STORE_REC_HEAD + dlen) };
}
async function fsGet(keyStr) {
  const r = await host.call("fs/get", strBytes(keyStr));
  return r[0] === 1 ? r.subarray(1) : null;
}
async function storeHas(id) { await ensureStoreIndex(); return heldBlocks.has(toHex(id)); }
async function storeGet(id) {
  const hex = toHex(id);
  const rec = await fsGet(hex + STORE_REC);
  if (rec) return decodeStoreRecord(rec);
  const blk = await fsGet(hex + STORE_BLK);
  if (!blk) return null;
  return { bytes: blk, descriptor: await fsGet(hex + STORE_DSC) };
}
async function storeGetBytes(id) {
  const hex = toHex(id);
  const rec = await fsGet(hex + STORE_REC);
  if (rec) { const decoded = decodeStoreRecord(rec); return decoded ? decoded.bytes : null; }
  return fsGet(hex + STORE_BLK);
}
async function storeGetDescriptor(id) {
  const hex = toHex(id);
  const rec = await fsGet(hex + STORE_REC);
  if (rec) { const decoded = decodeStoreRecord(rec); return decoded ? decoded.descriptor : null; }
  return fsGet(hex + STORE_DSC);
}
async function storeKeys() {
  const r = await host.call("fs/list", EMPTY), out = [];
  let o = 0; const n = rU32(r, o); o += 4;
  for (let i = 0; i < n; i++) {
    const klen = rU32(r, o); o += 4;
    const key = bytesToStr(r.slice(o, o + klen)); o += klen;
    out.push(key);
  }
  return out;
}
async function storeList() { await ensureStoreIndex(); return [...heldBlocks].map(fromHex); }

// ── the network: one local service name, two ops ─────────────────────────────
// The network is a bundle (the transport) claiming `_net` under its `services`
// list (seedkernel §12.10) — a co-resident guest's to reach, never a peer's —
// reached via `host.call("_net", …)`. The host prepends this app's 32-byte key
// as caller so the transport can attribute the request.
// Wire: `[opLen u8][op][args]`. This app uses two ops, `send` and `peers`; both
// answer on a later turn, so both are awaited.
const NET_ID = "_net";
function netBlob(b) { const h = new Uint8Array(4); wU32(h, 0, b.length); return concat([h, b]); }
function netOp(op, args) {
  const out = writeOp(op, args); // kernel op-frame (content) - this app's own framing
  // A rejected cross-realm call (no transport loaded, or torn down mid-flight) maps to
  // the empty answer - same shape as an unreachable peer - so a PUT reports "no holder
  // answered" instead of an uncaught rejection out of a fan-out.
  return host.call(NET_ID, out).then((r) => r, () => EMPTY);
}

// ── peers + ranking by reciprocity (§13) ──
// The `peers` answer is the raw 32-byte keys back to back — the peers the transport holds at
// least one AUTHENTICATED link to. There is no count header: the length says how many.
function decodePeers(r) {
  const out = [];
  for (let o = 0; o + 32 <= r.length; o += 32) out.push(toHex(r.slice(o, o + 32)));
  return out;
}
async function cohortPeers() { return decodePeers(await netOp("peers", EMPTY)); }
// A reciprocity ranker (§13): orders peers best-score-first. `makeRanker` memoizes
// each distinct peer's score (by PROMISE, not settled value, so concurrent lookups
// share one in-flight call) for its lifetime, so ranking overlapping holder subsets
// across a round costs one bridge crossing per peer, not one per (peer, id).
async function makeRanker() {
  const t = await clockNow();
  const cache = new Map(); // peerHex → Promise<decayed score>
  const scoreOf = (p) => { let s = cache.get(p); if (s === undefined) cache.set(p, s = repScore(fromHex(p), t)); return s; };
  return async (peers) => {
    if (peers.length === 0) return [];
    const scored = await Promise.all(peers.map(async (p) => ({ p, s: await scoreOf(p) })));
    return scored.sort((a, b) => b.s - a.s).map((x) => x.p);
  };
}
// One-shot ranker for callers that rank a single list (its own fresh cache).
async function rank(peers) { return (await makeRanker())(peers); }

// ── net (request/response over the transport; wire format here) ──
// One round trip via the transport's `send` op:
//   [noReply u8][deadlineMs u32][to blob][proto blob][payload blob]
// Zero deadline = the host's own default. Answer is `[ok u8][response]`; an
// unreachable peer comes back `[0]`, mapped to null below. `proto` is the routing
// id (§12.10); the storage message type leads the payload, opaque in between.
async function netSend(peer, type, payload) {
  statsSent[type]++;
  statsInFlight[type]++;
  if (statsInFlight[type] > statsPeak[type]) statsPeak[type] = statsInFlight[type];
  try {
    const head = new Uint8Array(5); // noReply=0, deadline=0 (the node's default)
    const body = new Uint8Array(1 + payload.length);
    body[0] = type;
    body.set(payload, 1);
    const r = await netOp("send", concat([head, netBlob(fromHex(peer)), netBlob(NET_PROTO), netBlob(body)]));
    return r[0] === 1 ? r.slice(1) : null; // null = peer unreachable within the window
  } finally {
    statsInFlight[type]--;
  }
}
// Per-peer fan-out (§6/§7): a distinct request per peer, all issued concurrently via
// Promise.all. `requests` = [{ peer, type, payload }]; results align to input order,
// an unreachable peer coming back `ok:false`/`bytes:null` rather than a throw.
function netSendMany(requests) {
  return Promise.all(requests.map(async (rq) => {
    const bytes = await netSend(rq.peer, rq.type, rq.payload);
    return { peer: rq.peer, ok: bytes !== null, bytes };
  }));
}
// disc.have/want (§5.2): one round of fan-out to the cohort (Promise.all over the
// same HAVE request to every holder) so the guest overlaps every peer. A node is
// itself a holder of whatever its own store keeps (repair runs on holders).
async function haveWant(ids) {
  const holders = new Map();
  for (const id of ids) holders.set(toHex(id), new Set());
  const me = await myPeer();
  for (const id of ids) if (await storeHas(id)) holders.get(toHex(id)).add(me);
  const peers = await cohortPeers();
  // Split so one HAVE request stays under the frame cap (§18) — the request side
  // (32 B/id) is what binds since the reply is a 1-byte mask. Merge per-slice masks.
  const maxIds = Math.max(1, Math.floor((maxMsgBytes() - 4) / HAVE_ID_LEN));
  for (const slice of sliceN(ids, maxIds)) {
    const haveReq = encodeHaveReq(slice); // one shared request, broadcast to every peer
    for (const res of await netSendMany(peers.map((p) => ({ peer: p, type: MSG_HAVE, payload: haveReq })))) {
      if (!res.ok) continue;
      const held = res.bytes;
      for (let i = 0; i < slice.length && i < held.length; i++) {
        if (held[i] === 1) holders.get(toHex(slice[i])).add(res.peer);
      }
    }
  }
  return holders;
}
// The HAVE/OFFER/STORE/FETCH wire codecs (§18) are stitched in from host/protocol.ts.

// Batched fetch from one peer (the GET hot path): one round trip for many blocks.
// Self reads the local store. Returns an array aligned to `ids` (bytes|null), or
// null for the whole batch if the peer was unreachable — so the caller can score a
// reachable-but-didn't-serve as a §8 miss but never an unreachable peer.
async function fetchBatch(peer, ids) {
  if (peer === await myPeer()) return Promise.all(ids.map((id) => storeGetBytes(id)));
  const resp = await netSend(peer, MSG_FETCH, encodeFetchBatchReq(ids));
  if (resp === null) return null;
  const blocks = decodeFetchBatchRes(resp);
  return ids.map((_, i) => blocks[i] || null);
}
// One placement engine (placeChunksBatched, below) drives the shared §18 codecs
// through netSendMany. Nothing places a block any other way — a small file, a
// window of coded chunks, an index level, and a repair pass all express themselves
// as (block, slot) targets handed to that one function.

// ── descriptor ───────────────────────────────────────────────────────────────
// The pure §4.3 codecs (parseSignedDescriptor, encode/decodeDescriptorList,
// descriptorContains, copyTargets, BLOCK_ID_LEN) are stitched in from
// host/manifest-core.ts. What stays here needs a grant: the scoped sign/verify pair.
//
// verifyDescriptor checks the author signature AND structurally validates the core:
// a signed-but-malformed descriptor (bad id count) is rejected rather than parsed
// into block-ids that sidestep the §10 sibling rule. Returns the whole envelope —
// a valid signature is only half the check; knownAuthors below is the other half.
async function verifyDescriptor(env) {
  // Length-gate before the verify seam: the envelope is [pk 32][sig 64][core ≥13]
  // (parseSignedDescriptor's own bound), so anything shorter — an absent descriptor
  // included — is rejected here rather than handed to verify as a short buffer.
  if (!env || env.length < 32 + 64 + 13) return null;
  if (!(await verifyEnv(env))) return null;
  try { return parseSignedDescriptor(env); } catch (_e) { return null; }
}
// The §4.3 ANCHOR: a signature checked against a pubkey carried inside the signed
// object only proves someone held a private key — any peer could self-sign a fresh
// keypair. The author must also be an identity the cohort knows (§5.1), so forgery
// costs a known peer its standing (§13) instead of nothing.
async function knownAuthors() {
  const [peers, me] = await Promise.all([cohortPeers(), myPeer()]);
  const s = new Set(peers); s.add(me); return s;
}
function signChunk(d) { return signCore(encodeDescriptorCore(d)); }

// ── placement + fetch (coordinator §6/§7) ────────────────────────────────────
// A batched OFFER/STORE/FETCH is split to stay under CFG.maxMessageBytes — the
// per-transport cap keeping one message inside the frame cap AND request timeout.
// Operator (LOCAL) policy; default if absent.
function maxMsgBytes() { const v = CFG.maxMessageBytes; return (typeof v === "number" && v > 0) ? v : (1 << 20); }
// Ids per FETCH sub-batch, bounded by the RESPONSE frame (blockSize + FETCH_FRAME per
// present block) so a full reply stays under the cap. The GET gather and the repair
// audit both size their batches this way; the holder caps served bytes the same (§18).
function fetchMaxIds() { return Math.max(1, Math.floor(maxMsgBytes() / (CFG.blockSize + FETCH_FRAME))); }
// The fan-out window (operator policy, like maxMessageBytes): how many per-peer
// sub-batches one Promise.all round fires at once. PUT and GET share it — it bounds
// STORE messages PER PEER and FETCH messages TOTAL across the cohort, pipelining a
// holder's many small messages instead of one round trip apiece. core.ts homes the default.
function fanoutWindow() { return CFG.fanoutWindow; }
function sliceN(arr, size) {
  if (arr.length <= size) return [arr];
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
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
// that admits them, a `floor` of distinct ids that must land, and peers to exclude.
// A chunk (makeChunk) is one slot per listed id, floor = its own k; a repair pass
// (heal) is only the copies still owed, floor 0 (best-effort).
function makeJob(slotIds, slotBlocks, descriptor, floor, exclude) {
  return {
    floor, slotIds, slotBlocks, descriptor, exclude,
    placedPeer: new Array(slotIds.length).fill(null),
    placedIds: [],
  };
}
// A signed chunk ready to place, expanded into its placement slots (§6/§10). One
// slot per listed id — a k=1 chunk's m+1-times-listed block IS its m+1 replica
// slots, no special case needed. Floor is the chunk's OWN k, not config's.
function makeChunk(d, blocks, descriptor) {
  return makeJob(d.blockIds.slice(), blocks.slice(), descriptor, d.k, new Set());
}
// Encode + sign one chunk at its OWN k = ceil(plain / blockSize), not padded to the
// deployment's k. At k=1, RS(1,m) parity ≡ data, so the codec is skipped and the
// chunk simply lists its lone block m+1 times (§4.1). Nonce = (level, GLOBAL index
// within that level) (§4.4), so a windowed encode matches a whole-level one.
// `tailBytes` is what a reader trims by, instead of a manifest-wide file_size.
async function encodeChunk(source, localCi, globalCi, K, level) {
  const c = CFG;
  const plain = source.slice(localCi * c.k * c.blockSize, (localCi + 1) * c.k * c.blockSize);
  const kc = Math.max(1, Math.ceil(plain.length / c.blockSize));
  const sealed = await encrypt(K, level, globalCi, padTo(plain, kc * c.blockSize));
  const ct = sealed.ciphertext;
  const dataBlocks = splitBlocks(ct, c.blockSize);
  const blocks = kc === 1 ? new Array(c.m + 1).fill(dataBlocks[0])
                          : [...dataBlocks, ...await rsEncode(kc, c.m, c.blockSize, dataBlocks)];
  const ids = kc === 1 ? new Array(c.m + 1).fill(await hash(dataBlocks[0]))
                       : await Promise.all(blocks.map((b) => hash(b)));
  const d = { level, k: kc, m: c.m, blockSize: c.blockSize, tailBytes: plain.length, authTag: sealed.authTag, blockIds: ids };
  return makeChunk(d, blocks, await signChunk(d));
}
// THE placement engine (§6/§10). Places every job's slots with one batched OFFER
// per peer per round, then accepted blocks STORE'd in fanoutWindow()-deep fan-outs.
// Slot i targets cands[i], cands[i+slots], … — a disjoint residue class per i, so
// one job's slots land on distinct peers (the sibling rule / replica distinctness /
// "somewhere new" for repair, all one rule). Fills each job's placedPeer[]/placedIds[].
//
// Throws if a job lands fewer than its `floor` distinct ids. `what` names the job in
// that error; floor 0 (repair) never throws and so passes no name.
async function placeChunksBatched(jobs, what) {
  const ranked = await rank(await cohortPeers());
  // Each job draws from the ranked cohort minus peers to avoid. PUT excludes nothing;
  // repair excludes peers already holding part of the chunk, so a restored copy lands
  // somewhere new instead of a sibling-declining or silently-overwritten holder.
  const candsOf = new Map();
  for (const job of jobs) candsOf.set(job, job.exclude.size === 0 ? ranked : ranked.filter((p) => !job.exclude.has(p)));
  const maxBytes = maxMsgBytes();
  const entryBytes = 36 + (jobs.length ? jobs[0].descriptor.length : 0); // one OFFER entry: [blockId 32][dlen u32][descriptor]
  const maxOffers = Math.max(1, Math.floor(maxBytes / entryBytes));

  // Advisory diagnostics collected from holder verdicts — a holder may lie, so the
  // reason is never policy, but the error a failed PUT throws becomes exact.
  const diag = { quota: 0, sibling: 0, descriptor: 0, error: 0 };

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
    // optimistic STORE — §6). STORE phase windows fanoutWindow() sub-batches per peer
    // (peers concurrent → peak W·peers) so a holder's many capped messages pipeline.

    // ── OFFER phase ──
    const offerSlices = new Map(); // peer → [slice]
    for (const [peer, items] of byPeer) offerSlices.set(peer, sliceN(items, maxOffers));
    const acceptedByPeer = new Map(); // peer → [{ch, i}]
    for (let s = 0; ; s++) {
      const reqs = [], sliceOf = [];
      for (const [peer, slices] of offerSlices) {
        if (s >= slices.length) continue;
        const slice = slices[s];
        const offers = slice.map(({ ch, i }) => ({ blockId: ch.slotIds[i], descriptor: ch.descriptor }));
        reqs.push({ peer, type: MSG_OFFER, payload: encodeOfferBatch(offers) });
        sliceOf.push(slice);
      }
      if (reqs.length === 0) break;
      const results = await netSendMany(reqs);
      for (let ri = 0; ri < results.length; ri++) {
        const slice = sliceOf[ri];
        const mask = results[ri].ok ? decodeMask(results[ri].bytes) : [];
        const accepted = slice.filter((_, j) => mask[j] === VERDICT_ACCEPTED);
        for (let j = 0; j < slice.length; j++) {
          if (mask[j] === VERDICT_QUOTA) diag.quota++;
          else if (mask[j] === VERDICT_SIBLING) diag.sibling++;
          else if (mask[j] === VERDICT_DESCRIPTOR) diag.descriptor++;
          else if (mask[j] === VERDICT_ERROR) diag.error++;
        }
        if (accepted.length === 0) continue;
        let list = acceptedByPeer.get(results[ri].peer); if (!list) acceptedByPeer.set(results[ri].peer, (list = []));
        for (const it of accepted) list.push(it);
      }
    }

    // ── STORE phase ── the accepted blocks, byte-bounded per peer, fanned out in
    // windows of fanoutWindow() per peer: each round packs up to W of a peer's STORE
    // sub-batches into one netSendMany (all peers concurrent → peak W·peers).
    const storeGroups = new Map(); // peer → [group]
    for (const [peer, accepted] of acceptedByPeer) {
      storeGroups.set(peer, batchBytes(accepted, ({ ch, i }) => 40 + ch.descriptor.length + ch.slotBlocks[i].length, maxBytes));
    }
    const putW = fanoutWindow();
    for (let base = 0; ; base += putW) {
      const reqs = [], groupOf = [];
      for (const [peer, groups] of storeGroups) {
        for (let s = base; s < base + putW && s < groups.length; s++) {
          const group = groups[s];
          reqs.push({ peer, type: MSG_STORE, payload: encodeStoreBatch(group.map(({ ch, i }) => ({ blockId: ch.slotIds[i], descriptor: ch.descriptor, bytes: ch.slotBlocks[i] }))) });
          groupOf.push(group);
        }
      }
      if (reqs.length === 0) break;
      const results = await netSendMany(reqs);
      for (let ri = 0; ri < results.length; ri++) {
        const group = groupOf[ri];
        const stored = results[ri].ok ? decodeMask(results[ri].bytes) : [];
        for (let j = 0; j < group.length; j++) {
          if (stored[j] === VERDICT_ACCEPTED) { group[j].ch.placedPeer[group[j].i] = results[ri].peer; }
          else if (stored[j] === VERDICT_QUOTA) diag.quota++;
          else if (stored[j] === VERDICT_SIBLING) diag.sibling++;
          else if (stored[j] === VERDICT_DESCRIPTOR) diag.descriptor++;
          else if (stored[j] === VERDICT_ERROR) diag.error++;
        }
      }
    }
  }

  for (const ch of jobs) {
    const distinct = new Set();
    for (let i = 0; i < ch.slotIds.length; i++) if (ch.placedPeer[i]) distinct.add(toHex(ch.slotIds[i]));
    if (distinct.size < ch.floor) {
      const parts = []; let total = 0;
      if (diag.quota) { parts.push("quota"); total += diag.quota; }
      if (diag.sibling) { parts.push("sibling"); total += diag.sibling; }
      if (diag.descriptor) { parts.push("descriptor-rejected"); total += diag.descriptor; }
      if (diag.error) { parts.push("holder-error"); total += diag.error; }
      // No verdicts at all is itself the diagnosis: every response failed (deadline
      // expiry or unreachable peers), so no holder ever judged anything — saying
      // "holders declined" here would point at the wrong place.
      const why = parts.length
        ? "holders declined (" + total + " holders: " + parts.join(", ") + "). Check quota (--app-config), signing scope (§16), or connect more holders"
        : "no holder returned a verdict — the requests timed out or the peers were unreachable rather than refusing. Raise the request deadline if a large PUT is queueing past it (p2p-cli --timeout, loader --request-deadline)";
      throw new Error("put: " + what + " landed " + distinct.size + "/" + ch.floor + " distinct blocks — " + why);
    }
    ch.placedIds = [...distinct].map(fromHex);  // the distinct ids that landed, for the PUT result
  }
}
// Run a windowed batched FETCH over a peer→[idHex] plan. Self reads the local store
// directly; other holders' sub-batches fan out fanoutWindow() FETCH messages at a
// time. `apply(peer, sliceHex, ids, blocks)` sees each result — null blocks for the
// whole slice means unreachable (not a §8 miss). Shared by GET gather and repair audit.
//
// Truncation vs miss is a wire bit: a holder bounds its FETCH response by its own
// maxMessageBytes (serveFetch), which can differ from ours. A block it has but
// couldn't fit comes back FETCH_UNANSWERED, distinct from an ABSENT genuine miss
// (§18); it's re-requested as a fresh task. An honest holder always serves the first
// present block, so each round resolves ≥1 — the loop CHECKS that (below) rather than
// trusting the peer, ruling no-progress a miss instead of looping forever.
async function runFetchTasks(byPeer, maxIds, apply) {
  const me = await myPeer();
  if (byPeer.has(me)) {
    for (const slice of sliceN(byPeer.get(me), maxIds)) {
      const ids = slice.map(fromHex);
      await apply(me, slice, ids, await fetchBatch(me, ids));
    }
  }
  const tasks = []; // { peer, slice, ids } — re-requested unanswered blocks are appended and picked up by later windows
  for (const peer of byPeer.keys()) {
    if (peer === me) continue;
    for (const slice of sliceN(byPeer.get(peer), maxIds)) tasks.push({ peer, slice, ids: slice.map(fromHex) });
  }
  const getW = fanoutWindow();
  for (let base = 0; base < tasks.length; base += getW) {
    const window = tasks.slice(base, base + getW);
    const results = await netSendMany(window.map(({ peer, ids }) => ({ peer, type: MSG_FETCH, payload: encodeFetchBatchReq(ids) })));
    for (let ri = 0; ri < results.length; ri++) {
      const { peer, slice, ids } = window[ri];
      if (!results[ri].ok) { await apply(results[ri].peer, slice, ids, null); continue; } // unreachable
      const decoded = decodeFetchBatchRes(results[ri].bytes);
      // Split the holder's answers over the ids we asked: FETCH_UNANSWERED blocks (no room
      // under the holder's cap) re-queue as a fresh task; present/absent are final verdicts
      // for `apply`. A short/malformed response leaves an id undefined, ruled absent.
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
      if (reSlice.length) tasks.push({ peer, slice: reSlice, ids: reIds });
      if (aSlice.length) await apply(results[ri].peer, aSlice, aIds, aBlocks);
    }
  }
}
// Fetch every block the file's chunks need, batched per holder. Each still-missing
// block is requested from its best untried holder; a coded chunk stops at k. Every
// returned block is hash-verified (§4.2) and scores its holder (§8).
async function gatherBlocks(descriptors, holders) {
  const c = CFG;
  const got = new Map();
  const tried = new Map();
  const triedOf = (h) => { let s = tried.get(h); if (!s) tried.set(h, (s = new Set())); return s; };
  // Bound a FETCH sub-batch by the RESPONSE size: each present block is blockSize +
  // FETCH_FRAME on the wire, so dividing by blockSize alone would let a full response
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
    const rankRound = await makeRanker();
    const byPeer = new Map(); // peer → [idHex]
    const queued = new Set();
    for (const d of descriptors) {
      let need = stillNeeds(d);
      if (need === 0) continue;
      for (const id of d.blockIds) {
        if (need === 0) break;
        const h = toHex(id);
        if (got.has(h) || queued.has(h)) continue;
        const cands = await rankRound([...(holders.get(h) || new Set())].filter((p) => !triedOf(h).has(p)));
        if (cands.length === 0) continue;
        let list = byPeer.get(cands[0]); if (!list) byPeer.set(cands[0], (list = []));
        list.push(h);
        queued.add(h);
        need--;
      }
    }
    if (byPeer.size === 0) break;

    const me = await myPeer();
    // Apply one peer-slice's fetched blocks: verify each by hash (§4.2), record the
    // first good copy, and score the holder (§8) — self is never scored. `blocks` is
    // aligned to `ids` (bytes|null per id), or null for the whole slice if the peer
    // was unreachable (not a §8 miss).
    const applyFetch = async (peer, slice, ids, blocks) => {
      const isSelf = peer === me;
      const [t, hashes] = await Promise.all([
        clockNow(),
        blocks === null ? [] : Promise.all(blocks.map((b) => b ? hash(b) : null)),
      ]);
      for (let i = 0; i < slice.length; i++) {
        triedOf(slice[i]).add(peer);
        if (blocks === null) continue;            // unreachable — not a §8 miss
        const b = blocks[i];
        if (b && bytesEqual(hashes[i], ids[i])) {
          if (!got.has(slice[i])) got.set(slice[i], b);
          if (!isSelf) repObserve(fromHex(peer), t, true);
        } else if (!isSelf) {
          repObserve(fromHex(peer), t, false);
        }
      }
    };

    // Self reads local; every other holder's sub-batches window by fanoutWindow() (§8/§13).
    await runFetchTasks(byPeer, maxIds, applyFetch);
  }
  return got;
}
// Assemble one chunk's ciphertext from the gathered blocks (§4.1/§7): take the first
// k DISTINCT listed blocks, and if they're the k data blocks in order just concatenate
// (systematic RS). Distinct matters: a k=1 descriptor lists its block m+1 times, so
// the same bytes must not fill two rows.
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
  const allData = present.slice(0, k).every((p) => p.index < k);
  if (allData) {
    const ordered = present.filter((p) => p.index < k).sort((a, b) => a.index - b.index).slice(0, k);
    if (ordered.length === k && ordered.every((p, i) => p.index === i)) return concat(ordered.map((p) => p.bytes));
  }
  return concat(await rsDecode(k, d.m, d.blockSize, present));
}

// ── PUT (§6) ─────────────────────────────────────────────────────────────────
// A large file is never wholly resident in the confined guest heap: encoded and
// placed in chunk-aligned WINDOWS, dropping ciphertext blocks once placed (§3). The
// driver streams plaintext a window at a time (putStart → putWindow* → putFinish);
// the whole-file `put` entry drives the same loop over its own in-memory argument.

// Target footprint for one window's plaintext slice, derived by the host driver
// from realmMemoryBytes (~/3, peak guest footprint ratio) as CFG.windowTargetBytes.
// A too-small window idles the wire between OFFER→STORE→ack rounds on a fat link.
function windowTarget() { return CFG.windowTargetBytes ?? 4 * 1024 * 1024; }
// A chunk-aligned window size: as many whole chunks (k·blockSize) as fit under the
// target, at least one, so window boundaries never split a chunk.
function putWindowBytes() { const chunkData = CFG.k * CFG.blockSize; return Math.max(1, Math.floor(windowTarget() / chunkData)) * chunkData; }
// Chunks per GET window. `chunkData` (k·blockSize) is the DESCRIPTOR's geometry
// (§4.3), passed in by the reader, never config's.
function getWindowChunks(chunkData) { return Math.max(1, Math.floor(windowTarget() / chunkData)); }

// Encode + place the chunks wholly contained in `slice` — a chunk-aligned slice of a
// LEVEL's byte stream at offset `baseByteOffset`. Each chunk codes at its own k
// (§4.1). Level 0 (the file) and level ℓ > 0 (an index) are the same call.
async function placeWindow(slice, baseByteOffset, K, level) {
  const c = CFG;
  const chunkData = c.k * c.blockSize;
  const baseCi = Math.floor(baseByteOffset / chunkData);
  const numChunks = Math.max(1, Math.ceil(slice.length / chunkData));
  const chunks = [];
  // The codec module has one worker and serializes calls; keeping chunk calls in
  // order avoids a large parked-Promise cohort without reducing codec wall time.
  for (let lc = 0; lc < numChunks; lc++) chunks.push(await encodeChunk(slice, lc, baseCi + lc, K, level));
  await placeChunksBatched(chunks, "chunk");
  return chunks;
}

// Place a whole byte stream as a run of chunks, answering with signed descriptors.
// The only thing that turns bytes into placed chunks — a file's descriptor list is
// bytes too, so it goes through here at a different `level`. One path, called twice.
async function placeStream(s, bytes, level, base) {
  const out = [];
  const wb = putWindowBytes();
  for (let off = 0; off === 0 || off < bytes.length; off += wb) {   // an empty file is still one chunk
    const chunks = await placeWindow(bytes.subarray(off, Math.min(off + wb, bytes.length)), base + off, s.K, level);
    await recordPlacements(s, chunks);
    for (const ch of chunks) out.push(ch.descriptor);
  }
  return out;
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
// The largest a signed descriptor gets, framed for the descriptor list: the deployment's
// own (k, m), since a partial chunk lists fewer ids (§4.3).
function descriptorBytes() { return 4 + 32 + 64 + 13 + AUTH_TAG_LEN + (CFG.k + CFG.m) * BLOCK_ID_LEN; }
// Open a stream: mint K and answer with the plaintext window the driver should feed.
// File size is no longer an argument — each chunk signs its own `tailBytes` (§4.3).
//
// A chunk must hold at least two descriptors, or a descriptor list could never
// shrink to a single root — checked here, once, before a byte moves. Production
// geometry clears it ~2000×.
async function putStart() {
  const chunkData = CFG.k * CFG.blockSize;
  if (chunkData < 2 * descriptorBytes()) {
    throw new Error("put: k·blockSize (" + chunkData + " B) must hold two chunk descriptors ("
      + descriptorBytes() + " B each) so a file's descriptor list can reach a single root — raise blockSize or k");
  }
  putStream = { K: await randomKey(), offset: 0, descriptors: [], placedIds: [], placed: 0, intended: 0 };
  return putWindowBytes();
}
// Fold placed chunks into the stream's durability accounting (§8). Counts REPLICA
// PLACEMENTS (one filled slot), not distinct ids — a k=1 chunk is one id on m+1
// peers, so counting ids would under-report. `intended` caps at the reachable
// cohort (the §6/§10 sibling rule caps one block per peer), so a small cohort isn't
// flagged while a declining (full) holder makes placed < intended.
async function recordPlacements(s, chunks) {
  const peerCount = (await cohortPeers()).length;
  for (const ch of chunks) {
    for (const id of ch.placedIds) s.placedIds.push(id);
    for (const p of ch.placedPeer) if (p) s.placed++;
    s.intended += Math.min(ch.slotIds.length, peerCount);
  }
}
// Feed the next plaintext window, in file order — a chunk-aligned slice of the file. Its
// ciphertext is placed and dropped before this returns; the driver never learns the
// window's byte offset, because the stream knows it.
async function putFeed(slice) {
  const s = requirePut();
  for (const env of await placeStream(s, slice, LEVEL_BODY, s.offset)) s.descriptors.push(env);
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
  let envs = s.descriptors;
  for (let level = 1; envs.length > 1; level++) envs = await placeStream(s, encodeDescriptorList(envs), level, 0);
  return encodePutResult(envs[0], s);
}
// The ONE PUT result format, read by every driver:
//   [K 32][chunkCount u32][placed u32][intended u32][rootLen u32][root ...]
//   [idCount u32]{id 32}
// root is the signed ROOT DESCRIPTOR (§4.3), variable-length (there's no manifest
// object), hence the length prefix. Offsets 0-47 are fixed. (placed, intended) is
// the §8 replica accounting, so a driver can warn on a silently under-replicated PUT.
function encodePutResult(root, s) {
  const out = new Uint8Array(48 + root.length + 4 + s.placedIds.length * 32);
  out.set(s.K, 0);
  wU32(out, 32, s.descriptors.length);
  wU32(out, 36, s.placed);
  wU32(out, 40, s.intended);
  wU32(out, 44, root.length);
  out.set(root, 48);
  const tail = 48 + root.length;
  wU32(out, tail, s.placedIds.length);
  for (let i = 0; i < s.placedIds.length; i++) out.set(s.placedIds[i], tail + 4 + i * 32);
  return out;
}

// No argument → [windowBytes u32]: open the stream, report the feed size.
async function doPutStart() { const out = new Uint8Array(4); wU32(out, 0, await putStart()); return out; }
// The window's plaintext, raw — no framing, since the stream holds everything else.
async function doPutWindow(arg) { await putFeed(arg); return EMPTY; }
// No argument — the stream is the argument.
function doPutFinish() { return putFinish(); }

// Whole-file PUT: one call, bytes in, result out — for drivers with no protocol
// structure of their own. Runs the same session as the streamed path; only the 1×
// plaintext is resident.
async function doPut(plaintext) {
  const wb = await putStart();
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
  const parts = [];
  for (let i = 0; i < ds.length; i++) {
    const d = ds[i];
    // Nonce = (this chunk's own level, its index within that level) (§4.4), matching
    // encodeChunk; tailBytes trims this chunk's zero padding, whether it is the file's
    // last chunk or an index level's.
    const plain = await decrypt(K, d.level, chunkStart + i, await assembleChunk(d, got), d.authTag);
    parts.push(plain.length === d.tailBytes ? plain : plain.subarray(0, d.tailBytes));
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
// No signature check here — content-addressed block ids (§4.2) already guarantee a
// tampered index fails its hash before being parsed. The author signature is what a
// HOLDER checks at admission (§4.3).
async function getStart(rootEnv, K) {
  let ds;
  try { ds = [parseSignedDescriptor(rootEnv).descriptor]; }
  catch (_e) { throw new Error("get: malformed root descriptor"); }
  while (ds[0].level > 0) {
    const above = ds[0].level;
    ds = decodeDescriptorList(await reconstructChunks(ds, K, 0)).map((env) => parseSignedDescriptor(env).descriptor);
    // Descent MUST strictly decrease — a hostile sharer (unauthenticated stream
    // cipher, §4.4) could hand out an index whose chunk decrypts to a list naming
    // itself, which content-addressing wouldn't catch. Unchecked, the walk hangs.
    if (!ds.length || ds[0].level >= above) throw new Error("get: index does not descend at level " + above + " — malformed or hostile root");
  }
  let fileSize = 0, maxChunkBytes = 0;
  for (const d of ds) {
    fileSize += d.tailBytes;
    if (d.k * d.blockSize > maxChunkBytes) maxChunkBytes = d.k * d.blockSize;
  }
  getStream = { K, ds, next: 0, windowChunks: getWindowChunks(maxChunkBytes) };
  return fileSize;
}
// The next window's plaintext, in file order. Empty once the file is exhausted, which
// also closes the stream — so a driver reading to the end leaves nothing behind.
async function getNext() {
  const s = getStream;
  if (!s) throw new Error("get: no stream open — call getStart first");
  if (s.next >= s.ds.length) { getStream = null; return EMPTY; }
  const start = s.next;
  const ds = s.ds.slice(start, start + s.windowChunks);
  s.next = start + ds.length;
  return reconstructChunks(ds, s.K, start);
}

// [K 32][root ...] → [fileSize u64]: open the stream, report how much to drain. K leads so
// the variable-length root can be the tail — the root replaced the fixed 32-byte id.
async function doGetStart(arg) {
  const out = new Uint8Array(8);
  wU64(out, 0, await getStart(arg.slice(32), arg.slice(0, 32)));
  return out;
}
// No argument — the stream is the argument.
function doGetNext() { return getNext(); }

// Whole-file GET: the counterpart of the whole-file `put`, draining the same stream in
// one call for the byte-in/byte-out drivers.
async function doGet(arg) {
  await getStart(arg.slice(32), arg.slice(0, 32));
  const parts = [];
  while (getStream) parts.push(await getNext());
  return concat(parts);
}

// ── repair (§9) ────────────────────────────────────────────────────────────--
// Audit a chunk's blocks: for each block_id, the live holders — advertised via
// have/want, confirmed retrievable by a verification-fetch (§8). Returns
// { live: Map hex → Set(peer), bytes: Map hex → one verified copy }; healing
// re-places from `bytes` instead of re-fetching. Batched one FETCH per holder,
// windowed by fanoutWindow(), not one round trip per (id, holder).
async function liveHolders(ids) {
  const advertised = await haveWant(ids);
  const me = await myPeer();
  const live = new Map();
  const bytes = new Map(); // hex → first hash-verifying copy seen this audit
  for (const id of ids) live.set(toHex(id), new Set());

  // Invert to holder → the ids it advertised, so one batched FETCH audits all of them.
  const byPeer = new Map();
  for (const id of ids) {
    const h = toHex(id);
    for (const peer of advertised.get(h) || new Set()) {
      let list = byPeer.get(peer); if (!list) byPeer.set(peer, (list = []));
      list.push(h);
    }
  }
  const applyAudit = async (peer, slice, idBytes, blocks) => { // async: the hash + clock cross the seam
    const isSelf = peer === me;
    const [t, hashes] = await Promise.all([
      clockNow(),
      blocks === null ? [] : Promise.all(blocks.map((b) => b ? hash(b) : null)),
    ]);
    for (let i = 0; i < slice.length; i++) {
      if (blocks === null) continue;              // unreachable — not a §8 miss
      const b = blocks[i];
      if (b && bytesEqual(hashes[i], idBytes[i])) {
        live.get(slice[i]).add(peer);
        if (!bytes.has(slice[i])) bytes.set(slice[i], b);
        if (!isSelf) repObserve(fromHex(peer), t, true);
      } else if (!isSelf) {
        repObserve(fromHex(peer), t, false);
      }
    }
  };
  await runFetchTasks(byPeer, fetchMaxIds(), applyAudit);
  return { live, bytes };
}
// Heal one chunk back toward full redundancy (§9). Wanted copies per block = its
// multiplicity in the id list (copyTargets); a short block is topped up from the
// audit's verified copy, or reconstructed from any k present blocks if coded (k≥2)
// with no live holder — a k=1 block can only be copied while one copy survives.
async function heal(d, descEnv, holders, verified) {
  const copiesOf = (h) => (holders.get(h) || new Set()).size;
  const want = copyTargets(d);

  const regenerated = new Map();
  if (d.k > 1 && d.blockIds.some((id) => copiesOf(toHex(id)) === 0)) {
    const present = [];
    for (let idx = 0; idx < d.blockIds.length && present.length < d.k; idx++) {
      const b = verified.get(toHex(d.blockIds[idx])); // present iff that id has a live holder
      if (b) present.push({ index: idx, bytes: b });
    }
    if (present.length >= d.k) {
      const data = await rsDecode(d.k, d.m, d.blockSize, present);
      const all = [...data, ...await rsEncode(d.k, d.m, d.blockSize, data)];
      for (let i = 0; i < all.length; i++) {
        // Re-certify against the already-signed id (§9): a mismatch means a bad
        // input/decode — drop it, never propagate (a poisoned descriptor can't mint).
        if (bytesEqual(await hash(all[i]), d.blockIds[i])) regenerated.set(toHex(d.blockIds[i]), all[i]);
      }
    }
  }

  // Every peer already holding part of this chunk. Restored copies go somewhere else
  // (§6, §10 — the sibling rule, which is also what keeps r replicas distinct).
  const occupied = new Set();
  for (const set of holders.values()) for (const p of set) occupied.add(p);

  // Copies still owed, expressed as PLACEMENT SLOTS — same shape a PUT window hands
  // the engine. A block already at full redundancy, or with no reconstructable copy,
  // contributes no slots.
  const slotIds = [], slotBlocks = [];
  for (const [h, target] of want) {
    const bytes = verified.get(h) || regenerated.get(h);
    if (!bytes) continue;
    const id = fromHex(h);
    for (let have = copiesOf(h); have < target; have++) { slotIds.push(id); slotBlocks.push(bytes); }
  }
  if (slotIds.length === 0) return 0;

  // Floor 0 — repair is best-effort: a pass places what the cohort will take and the next
  // pass retries the rest, where a PUT would rather fail than under-place a new file.
  const job = makeJob(slotIds, slotBlocks, descEnv, 0, occupied);
  await placeChunksBatched([job]);
  let replaced = 0;
  for (const p of job.placedPeer) if (p) replaced++;
  return replaced;
}
// Audit and, if under-replicated, heal one chunk from its signed descriptor.
async function repairChunk(descEnv) {
  const sd = await verifyDescriptor(descEnv);               // forged/unsigned/malformed → null (§4.3)
  if (!sd) return 0;
  const d = sd.descriptor;
  const { live: holders, bytes: verified } = await liveHolders(d.blockIds);
  // Chunk health is one number (§8, §9): loss margin against low-water mark ⌈m/2⌉,
  // both derived from the SIGNED descriptor — a mixed-geometry cohort (§4.1) repairs
  // each chunk to the count its own author signed.
  const copies = d.blockIds.map((id) => (holders.get(toHex(id)) || new Set()).size);
  if (lossMargin(d, copies) >= lowWaterMargin(d)) return 0;          // healthy
  return heal(d, descEnv, holders, verified);
}
// Run the repair loop over every chunk this node holds a block of (§9).
async function doRepair() {
  const seen = new Set();
  let replaced = 0;
  for (const id of await storeList()) {
    const descriptor = await storeGetDescriptor(id);
    if (!descriptor) continue;
    const key = toHex(await hash(descriptor));
    if (seen.has(key)) continue;
    seen.add(key);
    replaced += await repairChunk(descriptor);
  }
  const out = new Uint8Array(4);
  wU32(out, 0, replaced);
  return out;
}

// ── holder side (§5/§6/§7) ───────────────────────────────────────────────────
// The request side a node serves to its cohort: admission control (§6 sibling rule
// + §14 quota), content-addressing (§4.2), and durable record writes — confined
// here; the host keeps only a read view (host/store-view.ts), no write path. Async,
// since the fs seam is async on every backend (seedkernel core/fs.ts).
let bytesUsed = -1, heldBlocks = null, storeIndexPromise = null, storeIndexDirty = false;
let activeStoreWrites = 0, resolveStoreWritesIdle = null, storeWritesIdle = Promise.resolve();
const liveStoreReservations = new Map();
let storeReservationVersion = 0;
// The §14 byte budget is OPERATOR policy: read from LOCAL alone, never CFG (an
// author-signed `quota` in CFG would let a bundle grant itself disk). No generous
// default either — an under-injecting driver falls to 0 and FAILS CLOSED.
function quota() { return LOCAL.quota != null ? LOCAL.quota : 0; }
async function fsSizeRaw(keyStr) { return rU32(await host.call("fs/size", strBytes(keyStr)), 0); }
async function fsSize(keyStr) { const v = await fsSizeRaw(keyStr); return v === 0xffffffff ? 0 : v; }
async function ensureStoreIndex() {
  if (!storeIndexDirty && heldBlocks !== null && bytesUsed >= 0) return;
  if (storeIndexPromise === null) storeIndexPromise = (async () => {
    // Rebuild only from a stable durable snapshot. Admission may have resumed from an
    // earlier clean ensureStoreIndex() while storeKeys()/fsSize() are in flight, so
    // merge its still-live reservations and retry if any reservation landed or settled
    // across the seam calls. This keeps both quota charges and sibling exclusions.
    for (;;) {
      if (activeStoreWrites > 0) await storeWritesIdle;
      const reservationVersion = storeReservationVersion;
      const keys = await storeKeys();
      const records = new Set(), legacy = new Set();
      for (const key of keys) {
        if (key.length !== 68) continue;
        const hex = key.slice(0, 64), ext = key.slice(64);
        if (ext === STORE_REC) records.add(hex);
        else if (ext === STORE_BLK) legacy.add(hex);
      }
      const sizeKeys = [];
      for (const hex of records) sizeKeys.push(hex + STORE_REC);
      for (const hex of legacy) sizeKeys.push(hex + STORE_BLK, hex + STORE_DSC);
      const sizes = await Promise.all(sizeKeys.map(fsSize));
      if (reservationVersion !== storeReservationVersion || activeStoreWrites > 0) continue;
      const rebuilt = new Set([...records, ...legacy]);
      let rebuiltBytes = sizes.reduce((sum, size) => sum + size, 0);
      for (const [hex, cost] of liveStoreReservations) {
        if (!rebuilt.has(hex)) rebuiltBytes += cost;
        rebuilt.add(hex);
      }
      heldBlocks = rebuilt;
      bytesUsed = rebuiltBytes;
      storeIndexDirty = false;
      return;
    }
  })();
  try { await storeIndexPromise; } finally { storeIndexPromise = null; }
}
async function fsPut(keyStr, bytes) {
  const kb = strBytes(keyStr);
  const head = new Uint8Array(4); wU32(head, 0, kb.length);
  await host.call("fs/put", concat([head, kb, bytes]));
}
async function fsPutStoreRecord(keyStr, descriptor, bytes) {
  const kb = strBytes(keyStr);
  const head = new Uint8Array(4); wU32(head, 0, kb.length);
  const recordHead = new Uint8Array(STORE_REC_HEAD); wU32(recordHead, 0, descriptor.length);
  // Frame the fs call and durable record in one pass. Building a record first and
  // passing it through fsPut would copy every block-sized payload twice in the guest.
  await host.call("fs/put", concat([head, kb, recordHead, descriptor, bytes]));
}
// The one write path into store.local: one framed record, under the quota budget.
// Legacy two-file records are read but all new commits avoid the second metadata op.
//
// Backend failures (full disk, backend error, realm OOM) surface as holder errors:
// a holder has no console, so the verdict byte is its only way to report them.
async function storeWrite(id, bytes, descriptor) {
  const hex = toHex(id);
  if (activeStoreWrites++ === 0) {
    storeWritesIdle = new Promise((resolve) => { resolveStoreWritesIdle = resolve; });
  }
  try {
    await fsPutStoreRecord(hex + STORE_REC, descriptor, bytes);
  } catch (e) {
    // A failed write may still have left a partial file. The next admission rebuilds
    // after all concurrent commits settle instead of guessing which bytes landed.
    storeIndexDirty = true;
    throw e;
  } finally {
    activeStoreWrites--;
    if (liveStoreReservations.delete(hex)) storeReservationVersion++;
    if (activeStoreWrites === 0 && resolveStoreWritesIdle) {
      const resolve = resolveStoreWritesIdle; resolveStoreWritesIdle = null; resolve();
    }
  }
}
// Admission (§4.3 descriptor check, §6 sibling rule, §14 quota): a holder verifies
// the signed descriptor and enforces no-two-blocks-of-a-chunk itself, so the §10
// invariant survives a careless or malicious placer, not just an honest coordinator.
// `size` is the length of the block actually in hand (STORE only); OFFER carries
// none on the wire and passes null.
// Batched admission: one OFFER's worth of blocks checked cumulatively — the §14 quota
// budget shrinks as blocks are provisionally accepted, and a block whose sibling (§6)
// is already held OR provisionally accepted in this same batch is declined, so two
// blocks of one chunk never both pass. STORE re-checks each block with `reserve=true`,
// so this is the advisory pre-check, never the enforcement.
//
// The signed descriptor is REQUIRED on every path (§4.3). Deliberately no
// descriptor-less branch — that would let any peer push arbitrary bytes past the
// sibling rule under quota alone.
async function admitBatch(offers, reserve = false) {
  // A batch is one immutable admission snapshot. Issue its independent seam work
  // together, then apply quota + provisional-sibling decisions in wire order.
  const [known, signed] = await Promise.all([
    knownAuthors(), Promise.all(offers.map((o) => verifyDescriptor(o.descriptor))),
  ]);
  // Do this after crypto/roster awaits: once it returns, the quota/sibling decision
  // and optional STORE reservations below run without yielding, making the snapshot
  // atomic with respect to other inbound calls while disk writes remain concurrent.
  await ensureStoreIndex();
  let free = Math.max(0, quota() - bytesUsed);
  const provisional = new Set();
  const verdicts = [];
  for (let oi = 0; oi < offers.length; oi++) {
    const o = offers[oi], sd = signed[oi];
    if (!sd) { verdicts.push(VERDICT_DESCRIPTOR); continue; }          // absent, forged, unsigned, or malformed
    // ANCHOR the signature (§4.3): the key that signed it must be one this cohort knows,
    // or the check proves nothing — the envelope carries its own pubkey, so any peer could
    // self-sign with a fresh keypair.
    if (!known.has(toHex(sd.authorPk))) { verdicts.push(VERDICT_DESCRIPTOR); continue; }
    const d = sd.descriptor;
    if (!descriptorContains(d, o.blockId)) { verdicts.push(VERDICT_DESCRIPTOR); continue; } // not a block of this chunk
    // Geometry is the SIGNED descriptor's, never a field the sender picks: every block
    // is exactly blockSize bytes, so bytes in hand that disagree are not the block that
    // was offered, whatever they hash to.
    if (o.size != null && o.size !== d.blockSize) { verdicts.push(VERDICT_DESCRIPTOR); continue; }
    // Charge exactly what storeWrite commits: frame + descriptor + ciphertext.
    const cost = STORE_REC_HEAD + d.blockSize + o.descriptor.length;
    if (cost > free) { verdicts.push(VERDICT_QUOTA); continue; }
    // The sibling rule, over the whole id list. A block this holder ALREADY has counts:
    // a k=1 chunk lists its one block m+1 times, so those m+1 slots are m+1 distinct
    // peers — accepting a second copy here would silently burn one of them and leave the
    // chunk short of replicas while looking placed.
    if (provisional.has(toHex(o.blockId)) || heldBlocks.has(toHex(o.blockId))) { verdicts.push(VERDICT_SIBLING); continue; }
    let sibling = false;
    for (const sib of d.blockIds) {
      if (bytesEqual(sib, o.blockId)) continue;
      if (provisional.has(toHex(sib)) || heldBlocks.has(toHex(sib))) { sibling = true; break; }
    }
    if (sibling) { verdicts.push(VERDICT_SIBLING); continue; }
    free -= cost;
    const blockHex = toHex(o.blockId);
    provisional.add(blockHex);
    if (reserve) {
      bytesUsed += cost;
      heldBlocks.add(blockHex);
      liveStoreReservations.set(blockHex, cost);
      storeReservationVersion++;
    }
    verdicts.push(VERDICT_ACCEPTED);
  }
  return verdicts;
}
async function acceptStoreBatch(stores) {
  // Hashes are independent. Binding admission atomically reserves quota + ids in the
  // holder index, then the independent single-record writes can overlap safely.
  const hashes = await Promise.all(stores.map((s) => hash(s.bytes)));
  const verdicts = new Array(stores.length).fill(VERDICT_DECLINED);
  const valid = [];
  for (let i = 0; i < stores.length; i++) {
    if (bytesEqual(hashes[i], stores[i].blockId)) valid.push({ index: i, store: stores[i] });
  }
  const admitted = await admitBatch(valid.map(({ store: s }) => ({
    blockId: s.blockId, descriptor: s.descriptor, size: s.bytes.length,
  })), true);
  await Promise.all(valid.map(async ({ index, store: s }, i) => {
    if (admitted[i] !== VERDICT_ACCEPTED) { verdicts[index] = admitted[i]; return; }
    try { await storeWrite(s.blockId, s.bytes, s.descriptor); verdicts[index] = VERDICT_ACCEPTED; }
    catch { verdicts[index] = VERDICT_ERROR; }
  }));
  return verdicts;
}
// Serve a batched FETCH, capped at maxMsgBytes so a hostile cohort member can't name
// one id thousands of times and force an oversized reply. A held block that won't
// fit is tagged FETCH_UNANSWERED (re-requested by runFetchTasks); the FIRST present
// block is always served even alone over cap, so every request makes progress.
async function serveFetch(ids) {
  // Misbehaving-peer simulator (StorageConfig.lieOnFetch): answer UNANSWERED for
  // everything, exercising the reader's §18 no-progress invariant in tests.
  if (CFG.lieOnFetch) return ids.map(() => FETCH_UNANSWERED);
  const cap = maxMsgBytes();
  const out = new Array(ids.length).fill(null);
  const unique = new Map(); // idHex → id bytes, so a repeated id is one store read
  for (const id of ids) { const h = toHex(id); if (!unique.has(h)) unique.set(h, id); }
  const seen = new Map(await Promise.all([...unique].map(async ([h, id]) => [h, await storeGetBytes(id)])));
  let used = 4;           // the [count u32] response header
  let servedAny = false;
  for (let i = 0; i < ids.length; i++) {
    const h = toHex(ids[i]);
    const bytes = seen.get(h);
    if (!bytes) continue; // genuine miss — leave it ABSENT (null)
    const framed = bytes.length + FETCH_FRAME;
    if (servedAny && used + framed > cap) { out[i] = FETCH_UNANSWERED; continue; } // held but over the byte cap → mark for re-ask
    out[i] = bytes;
    used += framed;
    servedAny = true;
  }
  return out;
}
// The wire codecs a holder decodes/encodes (HAVE/OFFER/STORE/FETCH, encodeMask) come
// from the shared host/protocol.ts — the holder admits over the same §18 format the
// initiator speaks, by construction.

// Dispatch one incoming control message: arg = [type u8][payload]. Async since the
// fs seam is async. A STORE batch is processed SEQUENTIALLY, not in parallel: a
// parallel fan-out would race `bytesUsed` (two blocks both seeing the pre-batch
// budget). A HAVE batch is independent reads and may fan out.
async function doHandle(arg) {
  // The kernel's part of the argument is exactly the 32-byte caller; everything
  // after it is THIS app's own shape (util.ts `callerOf`/`readOp`) - same shape
  // `handle` and the host-side `invoke` share.
  const { fromHost, body } = callerOf(arg);
  // The host's loopback (caller = 32 zero bytes) drives the initiator ops; a peer's
  // frame carries a MsgType byte instead of an op name, and the caller id tells them apart.
  if (fromHost) {
    const { op, args: payload } = readOp(body);
    switch (op) {
      case Op.PUT: return doPut(payload);
      case Op.PUT_START: return doPutStart();
      case Op.PUT_WINDOW: return doPutWindow(payload);
      case Op.PUT_FINISH: return doPutFinish();
      case Op.GET: return doGet(payload);
      case Op.GET_START: return doGetStart(payload);
      case Op.GET_NEXT: return doGetNext();
      case Op.REPAIR: return doRepair();
      case Op.REQUEST: return doRequest(payload);
      case Op.WARM: return doWarm();
      case Op.SCORE: return repScoreBytes(payload, await clockNow());
      case Op.STATS: return encodeStats();
      default: return EMPTY;
    }
  }
  // A peer's wire frame: answer it, timing + counting it as holder work (the
  // `recv*` half of the STATS op, since the host has no inbound seam of its own).
  const type = body[0], payload = body.slice(1);
  const t0 = await clockNow();
  let out;
  if (type === MSG_HAVE) out = await encodeMask(await Promise.all(decodeHaveReq(payload).map((id) => storeHas(id))));
  else if (type === MSG_OFFER) out = await encodeMask(await admitBatch(decodeOfferBatch(payload)));
  else if (type === MSG_STORE) {
    const stores = decodeStoreBatch(payload);
    out = await encodeMask(await acceptStoreBatch(stores));
  }
  else if (type === MSG_FETCH) out = await encodeFetchBatchRes(await serveFetch(decodeFetchBatchReq(payload)));
  else out = EMPTY;
  statsRecv[type]++;
  statsRecvBytes[type] += payload.length;
  statsRecvMs[type] += await clockNow() - t0;
  return out;
}

// ── one control message, on the host's behalf ────────────────────────────────
// arg = [to 32][type u8][payload] — the mirror image of `handle`, and the only way
// a host-side caller reaches a peer (§12.10). Grants nothing new: the same netSend
// the placement engine drives, exposed as a local op (Op.REQUEST) rather than a
// second entrypoint. Answers `[ok u8][response]`; unreachable is `[0]`.
async function doRequest(arg) {
  const resp = await netSend(toHex(arg.slice(0, 32)), arg[32], arg.slice(33));
  return resp === null ? Uint8Array.from([0]) : concat([Uint8Array.from([1]), resp]);
}

// ── warm (boot-time JIT warmup) ──────────────────────────────────────────────
// One throwaway RS encode + decode + verify under a random key, no network/store,
// run once at boot. Pays V8's cold-JIT tax on codec + crypto up front, since a cold
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
    const chunk = await encodeChunk(buf, 0, r, K, LEVEL_BODY);                       // encrypt + RS-encode + hash + sign
    const sd = await verifyDescriptor(chunk.descriptor);                         // Ed25519 verify (+ §16 scope preimage)
    // Warm the decode seam too, at k ≥ 2 only — a k=1 deployment never reaches the
    // codec on PUT/GET/repair, so there's no cold-JIT tax there to pay down.
    if (sd && sd.descriptor.k > 1) {
      await rsDecode(c.k, c.m, c.blockSize, chunk.slotBlocks.slice(0, c.k).map((bytes, index) => ({ index, bytes })));
    }
  }
  return EMPTY;
}

// The one entrypoint, declared top-level: the kernel invokes `handle` -
// `[caller 32][body …]` - and nothing else (seedkernel §12.2). The call is
// asynchronous precisely because the async host names round-trip.
function handle(arg) {
  return doHandle(arg);
}

// The Tier-2 guest — the WHOLE storage protocol (README §6/§7/§9) as zero-authority
// JS that runs *inside* the QuickJS realm (§2.1). This is the single
// implementation of placement, k-of-n, admission, the wire format, and repair: the
// host (host/storage-node.ts) only boots the kernel and runs this guest in two
// realms. Every capability is reached through the one `host.call(op, bytes)` seam,
// and the code is de-async'd to straight-line synchronous form over the blocking
// Asyncify bridge (the load-bearing finding — a host call from a deferred promise
// job aborts the VM, so there is no async/await in here at all).
//
// Two roles share this one program. The *initiator* entrypoints (`put`/`get`/
// `repair`) are async — they fan out over net and run in the Asyncify realm. The
// *holder* entrypoint (`handle`: HAVE/OFFER/STORE/FETCH, admission, content-
// addressing, quota, fs writes) is purely synchronous (local fs + crypto, no net)
// and runs in a SYNC realm, so a node can answer requests while its own initiator
// realm is parked mid-await (the runtime split). Whichever entrypoint a realm
// calls, the other role's code is simply dormant there.
//
// This is a plain script, not a module: it has no imports/exports and no ambient
// authority. It is loaded as source by the host (host/storage-node.ts, or the
// seedkernel shell) which prepends two constant blocks — the generic
// `const CAP_* = n;` op catalog (seedkernel's host/cap-bridge.ts) and an `APP`
// object carrying the storage config + the codec/reputation kernel names — and
// runs it after the safe-js PREAMBLE that defines `host.call` and `register`.
// Every capability the guest reaches is an application-neutral primitive; all
// storage *structure* is right here. The same file is hosted by JSC on Bun today
// and by WAMR in the native node later — one artifact, both runtimes.

"use strict";

// ── byte helpers ────────────────────────────────────────────────────────────
// toHex / fromHex / bytesEqual / concatBytes / writeU32BE / readU32BE come from the
// SHARED pure core (host/util.ts), stitched in ahead of this body by
// scripts/build-guest.mjs — one definition, not a hand-copied mirror. Bridge the
// short names this body is written against to the shared ones.
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

const DOMAIN_MANIFEST = 0, DOMAIN_BODY = 1; // ENC_XCHACHA20 comes from the shared manifest-core
const EMPTY = new Uint8Array(0);

function wU64(out, off, ms) {
  const hi = Math.floor(ms / 0x100000000);
  wU32(out, off, hi); wU32(out, off + 4, ms >>> 0);
}
function readF64LE(b) { return new DataView(b.buffer, b.byteOffset, 8).getFloat64(0, true); }
// fs keys are ASCII (hex + a short suffix); QuickJS has no TextEncoder, so map
// chars to bytes by hand, the same way toHex/fromHex avoid Buffer.
function strBytes(s) { const o = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i) & 255; return o; }
function bytesToStr(b) { let s = ""; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return s; }

// ── the capability seam: storage policy over GENERIC kernel caps ─────────────
// Every wrapper is built from the application-neutral CAP_* ops — crypto
// primitives, net, fs, module-call, clock, identity (host/cap-bridge.ts in
// seedkernel). All *structure* lives here in the guest, never in the kernel:
// the nonce convention, the signed-descriptor envelope, the HAVE/OFFER/FETCH/
// STORE wire format (host/protocol.ts), the codec & reputation module ABIs, and
// the <hex>.blk/.dsc store layout (host/store-fs.ts). Config + the codec and
// reputation kernel names arrive as the injected `APP` constant (prepended by
// the driver), not as kernel ops. host.call blocks via Asyncify, so these read
// as ordinary synchronous functions.

// The op bytes of the two installed handlers (the guest owns their ABIs).
const CODEC_ENCODE = 1, CODEC_DECODE = 2;     // assembly/codec/index.ts
const REP_OBSERVE = 1, REP_SCORE = 2;         // assembly/reputation/index.ts
// Control-plane message types carried over net.send (host/protocol.ts §18).
const MSG_HAVE = 1, MSG_OFFER = 2, MSG_FETCH = 3, MSG_STORE = 4;
const HAVE_ID_LEN = 32;      // a HAVE/FETCH request names 32-byte block_ids (§18)
const FETCH_FRAME = 5;       // a present block costs [found u8][len u32] in a FETCH response (§18)
const STORE_BLK = ".blk", STORE_DSC = ".dsc";
const CODEC_NAME = fromHex(APP.codecName);
const REP_NAME = fromHex(APP.repName);
// The scoped-signature prefix `DOMAIN_guest ‖ scope` (README §16): the CAP_SIGN op signs
// `prefix ‖ msg`, never the raw msg, so a descriptor signature verifies only in this app's
// scope. CAP_VERIFY stays raw, so verifyEnv rebuilds `prefix ‖ core` before checking. The
// driver derives the bytes host-side (storage-node.ts from its scope, the shell from the
// admitted bundle's (author, app)) and injects them alongside APP — the guest treats them
// as an opaque prefix, never reconstructing the kernel's domain string itself.
const SIGN_PREFIX = fromHex(APP.signPrefix);

function config() { return APP; }

// ── crypto primitives + storage framing ──
function hash(bytes) { return host.call(CAP_HASH, bytes); }
function randomKey() { const n = new Uint8Array(4); wU32(n, 0, 32); return host.call(CAP_RANDOM, n); }
function identity() { return host.call(CAP_IDENTITY, EMPTY); }
let myPeerCache = null;
function myPeer() { if (myPeerCache === null) myPeerCache = toHex(identity()); return myPeerCache; }
// 24-byte nonce = [domain u8][index u32 BE][0…] (§4.4) — the guest's convention.
function nonce(domain, index) { const n = new Uint8Array(24); n[0] = domain & 255; wU32(n, 1, index >>> 0); return n; }
function streamXor(K, non, msg) { return host.call(CAP_STREAM_XOR, concat([non, K, msg])); }
function encrypt(K, domain, index, msg) { return streamXor(K, nonce(domain, index), msg); }
function decrypt(K, domain, index, ct) { return streamXor(K, nonce(domain, index), ct); }
// Signed chunk descriptor envelope: [authorPk 32][sig 64][core] (§4.3, §16). The
// prefix rides both paths: CAP_SIGN prepends `DOMAIN_guest ‖ scope` for us (so signCore
// passes the bare core and gets back a scoped signature), and verifyEnv rebuilds the same
// preimage for the raw CAP_VERIFY. The stored envelope still holds only [pk][sig][core] —
// the prefix is preimage-only, never transmitted.
function signCore(core) { return concat([identity(), host.call(CAP_SIGN, core), core]); }
function verifyEnv(env) {
  return host.call(CAP_VERIFY, concat([env.slice(0, 32), env.slice(32, 96), SIGN_PREFIX, env.slice(96)]))[0] === 1;
}

// ── codec + reputation via the generic module-call ──
function moduleCall(name, req) {
  const head = new Uint8Array(1 + name.length); head[0] = name.length; head.set(name, 1);
  return host.call(CAP_MODULE_CALL, concat([head, req]));
}
// Like moduleCall but takes the request already split into parts, so the name
// header and the request body fold into a single concat. The RS request is large
// (k data blocks ≈ 640 KB); the old `moduleCall(name, concat([head, ...blocks]))`
// built that buffer and then copied the whole of it again to prepend the name —
// two passes over the blocks. One concat copies them once. (The guest reaches the
// codec only through host.call, so the in-place scratch staging a host-owned
// instance could do isn't available here, but folding the two concats is.)
function moduleCallParts(name, parts) {
  const head = new Uint8Array(1 + name.length); head[0] = name.length; head.set(name, 1);
  return host.call(CAP_MODULE_CALL, concat([head, ...parts]));
}
function rsEncode(k, m, blockSize, dataBlocks) {
  const head = new Uint8Array(7);
  head[0] = CODEC_ENCODE; head[1] = k; head[2] = m; wU32(head, 3, blockSize);
  const parity = splitBlocks(moduleCallParts(CODEC_NAME, [head, ...dataBlocks]), blockSize);
  // A codec that returns no/short parity (its handler scratch too small for a
  // k·blockSize request, or the module missing) would otherwise surface far away as
  // the descriptor's "blockIds.length must equal k+m". Fail here, where the cause is.
  if (parity.length !== m) {
    throw new Error("rsEncode: codec returned " + parity.length + " parity blocks, expected " + m +
      " — chunk (k=" + k + " × blockSize=" + blockSize + ") likely exceeds the codec handler's scratch");
  }
  return parity;
}
function rsDecode(k, m, blockSize, present) {
  // Callers (assembleChunk, healCoded) already gate on present.length >= k, but
  // guard the codec seam itself so a short set is a clean throw, never a silently
  // truncated decode request (head[7] = use.length under k → garbage out).
  if (present.length < k) throw new Error("rsDecode: need at least k blocks to reconstruct");
  const use = present.slice(0, k);
  const head = new Uint8Array(8);
  head[0] = CODEC_DECODE; head[1] = k; head[2] = m; wU32(head, 3, blockSize); head[7] = use.length;
  const idx = new Uint8Array(use.length);
  for (let i = 0; i < use.length; i++) idx[i] = use[i].index;
  return splitBlocks(moduleCallParts(CODEC_NAME, [head, idx, ...use.map((p) => p.bytes)]), blockSize);
}
function clockNow() { const b = host.call(CAP_CLOCK, EMPTY); return rU32(b, 0) * 0x100000000 + rU32(b, 4); }
function repScore(peerPk, t) {
  const req = new Uint8Array(41); req[0] = REP_SCORE; req.set(peerPk, 1); wU64(req, 33, t);
  return readF64LE(moduleCall(REP_NAME, req));
}
function repObserve(peerPk, t, pass) {
  const req = new Uint8Array(42); req[0] = REP_OBSERVE; req.set(peerPk, 1); wU64(req, 33, t); req[41] = pass ? 1 : 0;
  moduleCall(REP_NAME, req); // returns the new score; the guest doesn't need it
}

// ── local store over fs.* (the <hex>.blk / <hex>.dsc layout of FsBlobStore) ──
// Existence is `size ≥ 0` (there is no CAP_FS_HAS): the raw CAP_FS_SIZE is 0xFFFFFFFF
// (fs.size → -1) only for an absent key, so a present-but-empty value still reads as held.
function storeHas(id) { return fsSizeRaw(toHex(id) + STORE_BLK) !== 0xffffffff; }
function storeGet(id) {
  const hex = toHex(id);
  const blk = host.call(CAP_FS_GET, strBytes(hex + STORE_BLK));
  if (blk[0] !== 1) return null;
  const dsc = host.call(CAP_FS_GET, strBytes(hex + STORE_DSC));
  return { bytes: blk.slice(1), descriptor: dsc[0] === 1 ? dsc.slice(1) : null };
}
// Just the <hex>.dsc sidecar, without dragging the block ciphertext across the
// bridge — repair audits chunk shape from the descriptor and never needs the .blk
// bytes (it re-fetches those from holders only where healing actually places).
function storeGetDescriptor(id) {
  const dsc = host.call(CAP_FS_GET, strBytes(toHex(id) + STORE_DSC));
  return dsc[0] === 1 ? dsc.slice(1) : null;
}
function storeList() {
  const r = host.call(CAP_FS_LIST, EMPTY), out = [];
  let o = 0; const n = rU32(r, o); o += 4;
  for (let i = 0; i < n; i++) {
    const klen = rU32(r, o); o += 4;
    const key = bytesToStr(r.slice(o, o + klen)); o += klen;
    if (key.length === 68 && key.slice(64) === STORE_BLK) out.push(fromHex(key.slice(0, 64)));
  }
  return out;
}

// ── peers + ranking by reciprocity (§13) ──
function decodePeers(r) {
  const n = rU32(r, 0), out = [];
  for (let i = 0; i < n; i++) out.push(toHex(r.slice(4 + i * 32, 4 + (i + 1) * 32)));
  return out;
}
function cohortPeers() { return decodePeers(host.call(CAP_NET_PEERS, EMPTY)); }
// A reciprocity ranker (§13): orders peers best-score-first. Scoring one peer costs a
// reputation MODULE_CALL across the bridge, so `makeRanker` reads the clock once and
// memoizes each DISTINCT peer's decayed score for its lifetime — reuse one across a
// round and ranking many overlapping holder subsets (a large GET ranks the same
// holders for thousands of ids) costs one crossing per peer, not one per (peer, id).
// Scores decay negligibly within a round, so a shared `t` is fine.
function makeRanker() {
  const t = clockNow();
  const cache = new Map(); // peerHex → decayed score
  const scoreOf = (p) => { let s = cache.get(p); if (s === undefined) { s = repScore(fromHex(p), t); cache.set(p, s); } return s; };
  return (peers) => peers.length === 0 ? [] : peers.map((p) => ({ p, s: scoreOf(p) })).sort((a, b) => b.s - a.s).map((x) => x.p);
}
// One-shot ranker for callers that rank a single list (its own fresh cache).
function rank(peers) { return makeRanker()(peers); }

// ── net (request/response over the generic transport; wire format here) ──
function netSend(peer, type, payload) {
  const head = new Uint8Array(33); head.set(fromHex(peer), 0); head[32] = type;
  const r = host.call(CAP_NET_SEND, concat([head, payload]));
  return r[0] === 1 ? r.slice(1) : null; // null = peer unreachable within the window
}
function netRequestMany(peers, type, payload) {
  const head = new Uint8Array(5); head[0] = type; wU32(head, 1, peers.length);
  const plen = new Uint8Array(4); wU32(plen, 0, payload.length);
  const r = host.call(CAP_NET_REQUEST_MANY, concat([head, ...peers.map(fromHex), plen, payload]));
  const out = []; let o = 0; const n = rU32(r, o); o += 4;
  for (let i = 0; i < n; i++) {
    const peer = toHex(r.slice(o, o + 32)); o += 32;
    const ok = r[o] === 1; o += 1;
    const len = rU32(r, o); o += 4;
    out.push({ peer, ok, bytes: ok ? r.slice(o, o + len) : null }); o += ok ? len : 0;
  }
  return out;
}
// Per-peer fan-out (§6/§7): a DISTINCT request per peer, fanned out CONCURRENTLY by
// the shared transport (CAP_NET_SEND_MANY = the general case of requestMany). This
// is the one concurrency a confined sync guest can express — it issues one batched
// cap per round and blocks; the host fans out; the guest never needs a Promise.all.
// `requests` = [{ peer, type, payload }]; results align to input order, an
// unreachable peer coming back `ok:false`/`bytes:null` (partial, never a throw).
function netSendMany(requests) {
  const head = new Uint8Array(4); wU32(head, 0, requests.length);
  const parts = [head];
  for (const rq of requests) {
    const h = new Uint8Array(37); h.set(fromHex(rq.peer), 0); h[32] = rq.type; wU32(h, 33, rq.payload.length);
    parts.push(h, rq.payload);
  }
  const r = host.call(CAP_NET_SEND_MANY, concat(parts));
  const out = []; let o = 0; const n = rU32(r, o); o += 4;
  for (let i = 0; i < n; i++) {
    const peer = toHex(r.slice(o, o + 32)); o += 32;
    const ok = r[o] === 1; o += 1;
    const len = rU32(r, o); o += 4;
    out.push({ peer, ok, bytes: ok ? r.slice(o, o + len) : null }); o += ok ? len : 0;
  }
  return out;
}
// disc.have/want (§5.2): one round trip to the cohort; the host fans out in
// parallel (net.requestMany) so the guest never needs a Promise.all. A node is
// itself a holder of whatever its own store keeps (repair runs on holders).
function haveWant(ids) {
  const holders = new Map();
  for (const id of ids) holders.set(toHex(id), new Set());
  for (const id of ids) if (storeHas(id)) holders.get(toHex(id)).add(myPeer());
  const peers = cohortPeers();
  // Split the id list so one HAVE request stays under the frame cap, exactly as
  // OFFER/STORE/FETCH do (§18). A HAVE request is 32 bytes/id (the reply is a 1-byte
  // mask, so the request is the binding side): on a tight transport (WebRTC's ~48 KB
  // cap → ~1.5k ids) an unsplit HAVE would break discovery for a modest file. Merge
  // the per-slice masks — a holder accumulates across slices.
  const maxIds = Math.max(1, Math.floor((maxMsgBytes() - 4) / HAVE_ID_LEN));
  for (const slice of sliceN(ids, maxIds)) {
    for (const res of netRequestMany(peers, MSG_HAVE, encodeHaveReq(slice))) {
      if (!res.ok) continue;
      const held = res.bytes;
      for (let i = 0; i < slice.length && i < held.length; i++) {
        if (held[i] === 1) holders.get(toHex(slice[i])).add(res.peer);
      }
    }
  }
  return holders;
}
// The HAVE/OFFER/STORE/FETCH wire codecs (encode/decodeHaveReq, encode/decodeHaveRes,
// encode/decodeOfferBatch, encode/decodeOfferMask, encode/decodeStoreBatch,
// encode/decodeStoreMask, encode/decodeFetchBatchReq, encode/decodeFetchBatchRes)
// come from the SHARED host/protocol.ts, stitched in ahead of this body — one
// definition of the §18 control-plane format, not a hand-copied mirror. The
// transport-policy wrappers below (offerBatch/storeBatch/fetchBatch) compose those
// codecs with netSend and handle the unreachable-peer (null) case.

// Batched fetch from one peer (the GET hot path): one round trip for many blocks.
// Self reads the local store. Returns an array aligned to `ids` (bytes|null), or
// null for the whole batch if the peer was unreachable — so the caller can score a
// reachable-but-didn't-serve as a §8 miss but never an unreachable peer. The
// caller hash-verifies every block (§4.2).
function fetchBatch(peer, ids) {
  if (peer === myPeer()) return ids.map((id) => { const sb = storeGet(id); return sb ? sb.bytes : null; });
  const resp = netSend(peer, MSG_FETCH, encodeFetchBatchReq(ids));
  if (resp === null) return null;
  const blocks = decodeFetchBatchRes(resp);
  return ids.map((_, i) => blocks[i] || null);
}
// verification-fetch (§8): pull one block from a holder, confirm it hashes to its
// id, and score the holder. The hash check + reputation are the guest's, not the
// host's. Used for the manifest + repair; the GET path uses the batched fetchBatch.
function verificationFetch(peer, id) {
  if (peer === myPeer()) {
    const sb = storeGet(id);
    return sb && bytesEqual(hash(sb.bytes), id) ? sb.bytes : null;
  }
  const resp = netSend(peer, MSG_FETCH, encodeFetchBatchReq([id]));
  if (resp === null) return null;                       // unreachable — not a miss to score
  const data = decodeFetchBatchRes(resp)[0] || null;
  const t = clockNow();
  if (data && bytesEqual(hash(data), id)) { repObserve(fromHex(peer), t, true); return data; }
  repObserve(fromHex(peer), t, false);
  return null;
}
// OFFER/STORE transport-policy wrappers: the shared encodeOfferBatch / decodeOfferMask
// (and the STORE twins, host/protocol.ts) over netSend, mapping an unreachable peer
// (netSend → null) to all-declines. The per-peer fan-out (placeChunksBatched) drives
// the same shared codecs directly through netSendMany.
function offerBatch(peer, offers) {
  const resp = netSend(peer, MSG_OFFER, encodeOfferBatch(offers));
  return resp === null ? offers.map(() => false) : decodeOfferMask(resp);
}
function offer(peer, blockId, size, descriptor) {
  return offerBatch(peer, [{ blockId, size, descriptor }])[0];
}
function storeBatch(peer, stores) {
  const resp = netSend(peer, MSG_STORE, encodeStoreBatch(stores));
  return resp === null ? stores.map(() => false) : decodeStoreMask(resp);
}
function storePush(peer, blockId, descriptor, bytes) {
  return storeBatch(peer, [{ blockId, descriptor, bytes }])[0];
}

// ── descriptor + manifest ────────────────────────────────────────────────────
// The pure §4.3 codecs — encode/decodeDescriptorCore, parseSignedDescriptor,
// encode/decodeManifest, descriptorContains, ENC_XCHACHA20, BLOCK_ID_LEN — come from
// the SHARED host/manifest-core.ts, stitched in ahead of this body (one definition).
// What stays here is only the part that needs a capability: verify/sign over the
// CAP_VERIFY / CAP_SIGN seam, composed with the shared parser/encoder.
//
// verifyDescriptor checks the author signature AND structurally validates the core
// (the parity the host holder has): a *signed* but malformed descriptor (junk core,
// n ≠ k+m) is rejected — not parsed into garbage block-ids that sidestep the §10
// sibling rule — because parseSignedDescriptor throws on a bad core.
function verifyDescriptor(env) {
  if (!verifyEnv(env)) return null;
  try { return parseSignedDescriptor(env).descriptor; } catch (_e) { return null; }
}
function signChunk(d) { return signCore(encodeDescriptorCore(d)); }

// ── placement + fetch (coordinator §6/§7) ────────────────────────────────────
// Appended to a placement-failure throw. A holder declines an OFFER/STORE for one of
// two reasons, indistinguishable to the initiator: (1) §14 quota full, or (2) the
// descriptor fails its verify — most often a SIGNING-SCOPE mismatch (§16): the holder
// verifies under storageSignScope(bundleAuthor) but this node signed under a different
// scope (e.g. the zero-author default vs. a seedloader running a signed bundle). GET
// still works either way (serving a FETCH checks neither quota nor the author scope).
const OUT_OF_STORAGE_HINT = " — holders answered but declined. Two causes look identical here: (a) the holders are OUT OF STORAGE (quota/disk full) — clear their data dirs or raise the quota; or (b) a SIGNING-SCOPE mismatch (§16) — the cohort's holders run a signed bundle and verify under its author scope, but this node signs under a different one (set the cohort's bundle author). Or simply connect more holders";
// A batched OFFER / STORE / FETCH is split to stay under config().maxMessageBytes —
// the per-transport cap that keeps one message inside the frame cap AND the request
// timeout. Transport/operator policy injected via the APP preamble (like quota);
// default if absent.
function maxMsgBytes() { const v = config().maxMessageBytes; return (typeof v === "number" && v > 0) ? v : (1 << 20); }
// Ids per FETCH sub-batch, bounded by the RESPONSE frame (blockSize + FETCH_FRAME per
// present block) so a full reply stays under the cap. The GET gather and the repair
// audit both size their batches this way; the holder caps served bytes the same (§18).
function fetchMaxIds() { return Math.max(1, Math.floor(maxMsgBytes() / (config().blockSize + FETCH_FRAME))); }
// The fan-out windows (transport/operator policy, like maxMessageBytes): how many
// per-peer sub-batches a single CAP_NET_SEND_MANY round carries. putWindow bounds
// STORE messages PER PEER (peers concurrent → peak W·peers); getWindow bounds FETCH
// messages TOTAL across the cohort (peak W), so a confined sync guest pipelines a
// holder's many ~1-block messages instead of paying one round trip apiece (the
// tight-cap WebRTC case the lock-step fan-out was meant to keep windowed). The
// StorageNode always injects the config value; this default only bites a driver that
// omits it — keep it equal to core.ts DEFAULT_FANOUT_WINDOW (the host defaultConfig).
const DEFAULT_FANOUT_WINDOW = 16;
function putWindow() { const v = config().putConcurrency; return (typeof v === "number" && v > 0) ? v : DEFAULT_FANOUT_WINDOW; }
function getWindow() { const v = config().getConcurrency; return (typeof v === "number" && v > 0) ? v : DEFAULT_FANOUT_WINDOW; }
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
// Offer to candidates ranked by reciprocity (§13); on accept, push. Up to `count`
// distinct peers not in `exclude`. Returns the peers that stored it. Used for the
// small-file replicas + the manifest; the RS path uses placeChunksBatched.
function placeBlock(blockId, bytes, descriptor, exclude, count) {
  const placed = [];
  const ranked = rank(cohortPeers().filter((p) => !exclude.has(p)));
  for (const peer of ranked) {
    if (placed.length >= count) break;
    if (placed.includes(peer)) continue;
    if (!offer(peer, blockId, bytes.length, descriptor)) continue;
    if (storePush(peer, blockId, descriptor, bytes)) placed.push(peer);
  }
  return placed;
}
// Encode + sign one RS chunk: encrypt k data blocks, add m parity, hash, sign.
function encodeChunk(plaintext, ci, K) {
  const c = config();
  const start = ci * c.k * c.blockSize;
  const chunkPlain = plaintext.slice(start, start + c.k * c.blockSize);
  const ct = encrypt(K, DOMAIN_BODY, ci, padTo(chunkPlain, c.k * c.blockSize));
  const dataBlocks = splitBlocks(ct, c.blockSize);
  const blocks = [...dataBlocks, ...rsEncode(c.k, c.m, c.blockSize, dataBlocks)];
  const blockIds = blocks.map(hash);
  const descriptor = signChunk({ k: c.k, m: c.m, blockSize: c.blockSize, blockIds });
  return { blockIds, blocks, descriptor, placedPeer: new Array(blocks.length).fill(null), placedIds: [] };
}
// Place every chunk's n blocks with one batched OFFER per peer per round, then the
// accepted blocks STORE'd in putWindow()-deep fan-outs per peer. Block index i
// targets ranked[i], ranked[i+n], … (a disjoint residue class per i, so a chunk's n
// blocks land on distinct peers, §6/§10). Per peer the OFFER is one round trip for
// block i of every chunk at once; the STOREs that follow window the peer's many
// capped messages (peak W·peers). Returns nothing; fills each chunk's placedPeer[].
// Throws if a chunk lands < k distinct ids.
function placeChunksBatched(chunks) {
  const c = config();
  const n = c.k + c.m;
  const ranked = rank(cohortPeers());
  const maxBytes = maxMsgBytes();
  const entryBytes = 40 + (chunks.length ? chunks[0].descriptor.length : 0);
  const maxOffers = Math.max(1, Math.floor(maxBytes / entryBytes));

  for (let r = 0; ; r++) {
    const byPeer = new Map(); // peer → [{ch, i}]
    for (const ch of chunks) {
      for (let i = 0; i < n; i++) {
        if (ch.placedPeer[i]) continue;
        const peer = ranked[i + r * n];
        if (!peer) continue;
        let list = byPeer.get(peer); if (!list) byPeer.set(peer, (list = []));
        list.push({ ch, i });
      }
    }
    if (byPeer.size === 0) break;

    // Lock-step fan-out: ALL of this round's OFFERs (one batched cap, peers
    // concurrent) complete before its STOREs (no optimistic STORE — §6). The OFFER
    // phase carries ≤1 message per peer per fan-out (a peer's offers are small and
    // rarely exceed maxOffers, so the sub-batch index is round-robined one-per-peer).
    // The STORE phase windows up to putWindow() of a peer's byte-bounded sub-batches
    // into each fan-out (peers concurrent → peak W·peers), so a holder's many capped
    // STORE messages pipeline instead of going one round trip apiece — a within-phase
    // parallelism bounded by putConcurrency. Within a phase every peer goes in
    // parallel; the only loss vs a per-peer pipeline is ~one slow-peer half-RTT
    // between the two phases.

    // ── OFFER phase ──
    const offerSlices = new Map(); // peer → [slice]
    for (const [peer, items] of byPeer) offerSlices.set(peer, sliceN(items, maxOffers));
    const acceptedByPeer = new Map(); // peer → [{ch, i}]
    for (let s = 0; ; s++) {
      const reqs = [], sliceOf = [];
      for (const [peer, slices] of offerSlices) {
        if (s >= slices.length) continue;
        const slice = slices[s];
        const offers = slice.map(({ ch, i }) => ({ blockId: ch.blockIds[i], size: ch.blocks[i].length, descriptor: ch.descriptor }));
        reqs.push({ peer, type: MSG_OFFER, payload: encodeOfferBatch(offers) });
        sliceOf.push(slice);
      }
      if (reqs.length === 0) break;
      const results = netSendMany(reqs);
      for (let ri = 0; ri < results.length; ri++) {
        const slice = sliceOf[ri];
        const mask = results[ri].ok ? decodeOfferMask(results[ri].bytes) : [];
        const accepted = slice.filter((_, j) => mask[j]);
        if (accepted.length === 0) continue;
        let list = acceptedByPeer.get(results[ri].peer); if (!list) acceptedByPeer.set(results[ri].peer, (list = []));
        for (const it of accepted) list.push(it);
      }
    }

    // ── STORE phase ── the accepted blocks, byte-bounded per peer, fanned out in
    // windows of putWindow() per peer: each round packs up to W of a peer's STORE
    // sub-batches into one netSendMany (all peers concurrent → peak W·peers).
    const storeGroups = new Map(); // peer → [group]
    for (const [peer, accepted] of acceptedByPeer) {
      storeGroups.set(peer, batchBytes(accepted, ({ ch, i }) => 40 + ch.descriptor.length + ch.blocks[i].length, maxBytes));
    }
    const putW = putWindow();
    for (let base = 0; ; base += putW) {
      const reqs = [], groupOf = [];
      for (const [peer, groups] of storeGroups) {
        for (let s = base; s < base + putW && s < groups.length; s++) {
          const group = groups[s];
          reqs.push({ peer, type: MSG_STORE, payload: encodeStoreBatch(group.map(({ ch, i }) => ({ blockId: ch.blockIds[i], descriptor: ch.descriptor, bytes: ch.blocks[i] }))) });
          groupOf.push(group);
        }
      }
      if (reqs.length === 0) break;
      const results = netSendMany(reqs);
      for (let ri = 0; ri < results.length; ri++) {
        const group = groupOf[ri];
        const stored = results[ri].ok ? decodeStoreMask(results[ri].bytes) : [];
        for (let j = 0; j < group.length; j++) if (stored[j]) group[j].ch.placedPeer[group[j].i] = results[ri].peer;
      }
    }
  }

  for (const ch of chunks) {
    const distinct = new Set();
    for (let i = 0; i < ch.blockIds.length; i++) if (ch.placedPeer[i]) distinct.add(toHex(ch.blockIds[i]));
    if (distinct.size < c.k) throw new Error("put: chunk landed " + distinct.size + "/" + c.k + " distinct blocks" + OUT_OF_STORAGE_HINT);
    ch.placedIds = [...distinct].map(fromHex);  // the distinct ids that landed, for the PUT result
  }
}
// Fetch a block from whichever cohort peer holds it, verifying by hash (manifest + repair).
function fetchBlock(id) {
  const holders = haveWant([id]).get(toHex(id)) || new Set();
  for (const peer of rank([...holders])) {
    const b = verificationFetch(peer, id);
    if (b) return b;
  }
  return null;
}
// Run a windowed batched FETCH over a peer→[idHex] plan. Self reads the local store
// directly (no round trip, no scoring); every other holder's sub-batches are flattened
// into one task list and fanned out getWindow() FETCH messages at a time (peak W in
// flight, the getConcurrency window). `apply(peer, sliceHex, ids, blocks)` sees each
// sub-batch's result — blocks aligned to ids (bytes|null), or null for the whole slice
// if the peer was unreachable (partial, never a §8 miss). Shared by the GET gather and
// the repair audit, so both express the same window through one CAP_NET_SEND_MANY round.
function runFetchTasks(byPeer, maxIds, apply) {
  const me = myPeer();
  if (byPeer.has(me)) {
    for (const slice of sliceN(byPeer.get(me), maxIds)) {
      const ids = slice.map(fromHex);
      apply(me, slice, ids, fetchBatch(me, ids));
    }
  }
  const tasks = []; // { peer, slice, ids }
  for (const peer of byPeer.keys()) {
    if (peer === me) continue;
    for (const slice of sliceN(byPeer.get(peer), maxIds)) tasks.push({ peer, slice, ids: slice.map(fromHex) });
  }
  const getW = getWindow();
  for (let base = 0; base < tasks.length; base += getW) {
    const window = tasks.slice(base, base + getW);
    const results = netSendMany(window.map(({ peer, ids }) => ({ peer, type: MSG_FETCH, payload: encodeFetchBatchReq(ids) })));
    for (let ri = 0; ri < results.length; ri++) {
      const { slice, ids } = window[ri];
      const decoded = results[ri].ok ? decodeFetchBatchRes(results[ri].bytes) : null;
      const blocks = decoded === null ? null : ids.map((_, i) => decoded[i] || null);
      apply(results[ri].peer, slice, ids, blocks);
    }
  }
}
// Fetch every block the file's chunks need, batched per holder. After the file-wide
// have/want, each still-missing block is requested from its best untried holder,
// sub-batched under the frame cap and fanned out getWindow() FETCH messages at a time
// (peak W in flight, the getConcurrency window); a coded chunk stops at k, preferring
// data blocks. Every returned block is hash-verified (§4.2) and scores its holder
// (§8). Returns a Map id-hex → bytes.
function gatherBlocks(descriptors, holders) {
  const c = config();
  const got = new Map();
  const tried = new Map();
  const triedOf = (h) => { let s = tried.get(h); if (!s) tried.set(h, (s = new Set())); return s; };
  // Bound a FETCH sub-batch by the RESPONSE size: each present block is blockSize +
  // FETCH_FRAME on the wire, so dividing by blockSize alone would let a full response
  // slip just past the cap (the request side, 32 B/id, is smaller and never binds).
  const maxIds = fetchMaxIds();

  const stillNeeds = (d) => {
    const distinct = new Set();
    for (const id of d.blockIds) if (got.has(toHex(id))) distinct.add(toHex(id));
    const need = d.m === 0 ? d.blockIds.length : d.k;
    return Math.max(0, need - distinct.size);
  };

  for (;;) {
    // One ranker for the whole round: scoring a holder crosses the bridge once, then
    // every id that shares that holder reuses the cached score (§13).
    const rankRound = makeRanker();
    const byPeer = new Map(); // peer → [idHex]
    const queued = new Set();
    for (const d of descriptors) {
      let need = stillNeeds(d);
      if (need === 0) continue;
      for (const id of d.blockIds) {
        if (need === 0) break;
        const h = toHex(id);
        if (got.has(h) || queued.has(h)) continue;
        const cands = rankRound([...(holders.get(h) || new Set())].filter((p) => !triedOf(h).has(p)));
        if (cands.length === 0) continue;
        let list = byPeer.get(cands[0]); if (!list) byPeer.set(cands[0], (list = []));
        list.push(h);
        queued.add(h);
        need--;
      }
    }
    if (byPeer.size === 0) break;

    const me = myPeer();
    // Apply one peer-slice's fetched blocks: verify each by hash (§4.2), record the
    // first good copy, and score the holder (§8) — self is never scored. `blocks` is
    // aligned to `ids` (bytes|null per id), or null for the whole slice if the peer
    // was unreachable (not a §8 miss).
    const applyFetch = (peer, slice, ids, blocks) => {
      const isSelf = peer === me;
      const t = clockNow();
      for (let i = 0; i < slice.length; i++) {
        triedOf(slice[i]).add(peer);
        if (blocks === null) continue;            // unreachable — not a §8 miss
        const b = blocks[i];
        if (b && bytesEqual(hash(b), ids[i])) {
          if (!got.has(slice[i])) got.set(slice[i], b);
          if (!isSelf) repObserve(fromHex(peer), t, true);
        } else if (!isSelf) {
          repObserve(fromHex(peer), t, false);
        }
      }
    };

    // Self reads local; every other holder's sub-batches window by getWindow() (§8/§13).
    runFetchTasks(byPeer, maxIds, applyFetch);
  }
  return got;
}
// Assemble one chunk's ciphertext from the gathered blocks (§4.1/§7).
function assembleChunk(d, got) {
  if (d.m === 0) {
    const blocks = [];
    for (const id of d.blockIds) {
      const b = got.get(toHex(id));
      if (!b) throw new Error("get: a replica is unavailable");
      blocks.push(b);
    }
    return concat(blocks);
  }
  const k = d.k;
  const present = [];
  for (let i = 0; i < d.blockIds.length && present.length < k; i++) {
    const b = got.get(toHex(d.blockIds[i]));
    if (b) present.push({ index: i, bytes: b });
  }
  if (present.length < k) throw new Error("get: fewer than k blocks retrievable — chunk unavailable");
  const allData = present.slice(0, k).every((p) => p.index < k);
  if (allData) {
    const ordered = present.filter((p) => p.index < k).sort((a, b) => a.index - b.index).slice(0, k);
    if (ordered.length === k && ordered.every((p, i) => p.index === i)) return concat(ordered.map((p) => p.bytes));
  }
  return concat(rsDecode(k, d.m, d.blockSize, present));
}

// ── PUT (§6) ─────────────────────────────────────────────────────────────────
function doPut(plaintext) {
  const c = config();
  const fileSize = plaintext.length;
  const K = randomKey();
  const totalBlocks = Math.max(1, Math.ceil(fileSize / c.blockSize));
  const replicated = totalBlocks <= c.smallMaxBlocks;
  const descriptors = [];
  const placedIds = []; // every block id placed (all chunks' blocks + the manifest), in placement order

  if (replicated) {
    // A file too small to fill a chunk is replicated r = m+1 times, not coded (§4.1).
    const d = totalBlocks;
    const ct = encrypt(K, DOMAIN_BODY, 0, padTo(plaintext, d * c.blockSize));
    const dataBlocks = splitBlocks(ct, c.blockSize);
    const blockIds = dataBlocks.map(hash);
    const env = signChunk({ k: d, m: 0, blockSize: c.blockSize, blockIds });
    for (let i = 0; i < d; i++) {
      if (placeBlock(blockIds[i], dataBlocks[i], env, new Set(), c.replicas).length === 0) {
        throw new Error("put: no peer accepted a replica" + OUT_OF_STORAGE_HINT);
      }
      placedIds.push(blockIds[i]);
    }
    descriptors.push(env);
  } else {
    // RS path (§4.1): chunk into k data blocks + m parity, sign each, then place
    // the whole file through batched per-peer OFFERs (placeChunksBatched). A
    // degenerate RS(1,·) repeats an id (parity≡data); the repeat still gets its
    // own peer — k=1 replication — but counts once toward the ≥ k distinct check.
    const numChunks = Math.ceil(totalBlocks / c.k);
    const chunks = [];
    for (let ci = 0; ci < numChunks; ci++) chunks.push(encodeChunk(plaintext, ci, K));
    placeChunksBatched(chunks);
    for (const ch of chunks) { descriptors.push(ch.descriptor); for (const id of ch.placedIds) placedIds.push(id); }
  }

  // Build, encrypt, and replicate the manifest (§4.3).
  const manPlain = encodeManifest({
    fileSize, blockSize: c.blockSize, k: c.k, m: c.m, encAlg: ENC_XCHACHA20, chunks: descriptors,
  });
  const manCt = encrypt(K, DOMAIN_MANIFEST, 0, manPlain);
  const manifestId = hash(manCt);
  // Signed descriptor for the manifest block so repair can self-heal it (§9).
  // Carries as a one-block replicated chunk (k = 1, m = 0) with the manifest's
  // block_id.
  const manEnv = signChunk({ k: 1, m: 0, blockSize: manCt.length, blockIds: [manifestId] });
  if (placeBlock(manifestId, manCt, manEnv, new Set(), c.replicas).length === 0) {
    throw new Error("put: no peer accepted the manifest" + OUT_OF_STORAGE_HINT);
  }
  placedIds.push(manifestId);

  // result: [manifestId 32][replicated u8][chunkCount u32][K 32][idCount u32][ids 32·n].
  // The blockIds tail is appended AFTER K so offsets 0–68 stay fixed (the shell + Go
  // loader read only the length/hex of the response).
  const out = new Uint8Array(73 + placedIds.length * 32);
  out.set(manifestId, 0);
  out[32] = replicated ? 1 : 0;
  wU32(out, 33, descriptors.length);
  out.set(K, 37);
  wU32(out, 69, placedIds.length);
  for (let i = 0; i < placedIds.length; i++) out.set(placedIds[i], 73 + i * 32);
  return out;
}

// ── GET (§7) ─────────────────────────────────────────────────────────────────
function doGet(arg) {
  const manifestId = arg.slice(0, 32), K = arg.slice(32, 64);
  const manCt = fetchBlock(manifestId);
  if (!manCt) throw new Error("get: manifest not found in cohort");
  const man = decodeManifest(decrypt(K, DOMAIN_MANIFEST, 0, manCt));

  // Verify every chunk descriptor's signature before using it (§4.3): the manifest is
  // encrypted, not signed, so a correct K with a tampered manifest is caught only by
  // the per-chunk signature. One file-wide have/want, then one batched FETCH per holder
  // (gatherBlocks), instead of a discovery + fetch per chunk.
  const ds = man.chunks.map((env) => {
    const d = verifyDescriptor(env);
    if (!d) throw new Error("get: chunk descriptor signature invalid");
    return d;
  });
  const allIds = [];
  for (const d of ds) for (const id of d.blockIds) allIds.push(id);
  const holders = haveWant(allIds);
  const got = gatherBlocks(ds, holders);

  const out = new Uint8Array(man.fileSize);
  let written = 0;
  for (let ci = 0; ci < ds.length; ci++) {
    const d = ds[ci];
    const chunkCipher = assembleChunk(d, got);
    const chunkPlain = decrypt(K, DOMAIN_BODY, d.m === 0 ? 0 : ci, chunkCipher);
    const take = Math.min(chunkPlain.length, man.fileSize - written);
    out.set(chunkPlain.subarray(0, take), written);
    written += take;
  }
  return out;
}

// ── repair (§9) ────────────────────────────────────────────────────────────--
// Audit a chunk's blocks: for each block_id, the live holders — advertised via
// have/want, then confirmed retrievable by a verification-fetch (§8). Returns
// { live: Map hex → Set(peer), bytes: Map hex → one verified copy }. The audit
// already pulls a verifying copy from every live holder, so it keeps one per id in
// `bytes` — healing re-places THOSE instead of re-fetching (a whole-cohort have/want
// per id, the pre-batch cost). The verification is unchanged per (peer, block): the
// same hash-check (§4.2) + repObserve (§8), just batched one FETCH per holder (all the
// ids it advertised) and windowed by getWindow(), not one round trip per (id, holder).
function liveHolders(ids) {
  const advertised = haveWant(ids);
  const me = myPeer();
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
  const applyAudit = (peer, slice, idBytes, blocks) => {
    const isSelf = peer === me;
    const t = clockNow();
    for (let i = 0; i < slice.length; i++) {
      if (blocks === null) continue;              // unreachable — not a §8 miss
      const b = blocks[i];
      if (b && bytesEqual(hash(b), idBytes[i])) {
        live.get(slice[i]).add(peer);
        if (!bytes.has(slice[i])) bytes.set(slice[i], b);
        if (!isSelf) repObserve(fromHex(peer), t, true);
      } else if (!isSelf) {
        repObserve(fromHex(peer), t, false);
      }
    }
  };
  runFetchTasks(byPeer, fetchMaxIds(), applyAudit);
  return { live, bytes };
}
// Replicated chunk (§4.1): repair is a single block copy from any live holder — the
// copy the audit already fetched and verified (`verified`), never a fresh have/want.
function healReplicated(d, descEnv, holders, verified) {
  const c = config();
  let replaced = 0;
  for (const id of d.blockIds) {
    const h = toHex(id);
    const set = holders.get(h) || new Set();
    if (set.size >= c.replicas) continue;
    const data = verified.get(h);        // present iff a live holder served it (set.size > 0)
    if (!data) continue;                 // no live holder this pass — nothing to copy from
    replaced += placeBlock(id, data, descEnv, set, c.replicas - set.size).length;
  }
  return replaced;
}
// A chunk's distinct block-ids → their bytes + multiplicity (how many slots each
// fills). Ordinary RS gives every id multiplicity 1; a degenerate k=1 code, whose
// parity is byte-identical to its data, collapses several slots onto one id (§9).
function distinctBlocks(blockIds) {
  const out = new Map(); // hex → { id, count }
  for (const id of blockIds) {
    const h = toHex(id);
    const e = out.get(h);
    if (e) e.count++; else out.set(h, { id, count: 1 });
  }
  return out;
}
// Coded chunk (§9): bring every block back to full redundancy. A block some holder
// still serves but too few hold — a degenerate code's repeated id, or a lost extra
// replica — is copied to fresh peers; a block no live holder serves is reconstructed
// from any k present blocks, re-certified against its signed block_id, then placed.
// Each id lands on as many distinct holders as it has slots (§6/§10).
function healCoded(d, descEnv, holders, distinct, verified) {
  // Reconstruct any entirely-missing id once, up front, from k present blocks — reusing
  // the copies the audit (liveHolders) already fetched and verified, so a block that
  // still has a live holder costs no extra round trip. (A missing id, held by no live
  // holder, isn't in `verified`; it's decoded here and copied below.)
  const regenerated = new Map();
  let anyMissing = false;
  for (const h of distinct.keys()) if ((holders.get(h) || new Set()).size === 0) { anyMissing = true; break; }
  if (anyMissing) {
    const present = [];
    for (let idx = 0; idx < d.blockIds.length && present.length < d.k; idx++) {
      const b = verified.get(toHex(d.blockIds[idx])); // present iff that id has a live holder
      if (b) present.push({ index: idx, bytes: b });
    }
    if (present.length >= d.k) {
      const data = rsDecode(d.k, d.m, d.blockSize, present);
      const all = [...data, ...rsEncode(d.k, d.m, d.blockSize, data)];
      for (let i = 0; i < all.length; i++) {
        const h = toHex(d.blockIds[i]);
        if (regenerated.has(h)) continue;
        // Re-certify against the already-signed id (§9): a mismatch means a bad
        // input/decode — drop it, never propagate (a poisoned descriptor can't mint).
        if (bytesEqual(hash(all[i]), d.blockIds[i])) regenerated.set(h, all[i]);
      }
    }
  }

  // Spread copies onto peers not already holding part of this chunk (§6, §10).
  const occupied = new Set();
  for (const set of holders.values()) for (const p of set) occupied.add(p);

  let replaced = 0;
  for (const [h, info] of distinct) {
    const live = (holders.get(h) || new Set()).size;
    const need = info.count - live;
    if (need <= 0) continue;
    // A live copy (already fetched by the audit) is the cheapest source; otherwise the
    // reconstructed block.
    const bytes = live > 0 ? verified.get(h) : regenerated.get(h);
    if (!bytes) continue; // missing and not reconstructable this pass
    const placed = placeBlock(info.id, bytes, descEnv, occupied, need);
    for (const p of placed) occupied.add(p);
    replaced += placed.length;
  }
  return replaced;
}
// Audit and, if under-replicated, heal one chunk from its signed descriptor.
function repairChunk(descEnv) {
  const d = verifyDescriptor(descEnv);                     // forged/unsigned/malformed → null (§4.3)
  if (!d) return 0;
  const { live: holders, bytes: verified } = liveHolders(d.blockIds);
  const distinct = distinctBlocks(d.blockIds);
  // Effective redundancy: distinct live holders per block, each capped by how many
  // slots that block fills. A degenerate code (RS(1,·), parity≡data) repeats one id
  // across slots, so that id must live on as many distinct holders as it has slots
  // (§6/§10); for ordinary RS every id is unique and this is the live-block count (§8).
  let redundancy = 0;
  for (const [h, info] of distinct) redundancy += Math.min((holders.get(h) || new Set()).size, info.count);
  if (redundancy >= config().lowWater) return 0;           // healthy (§8, §9)
  return d.m === 0 ? healReplicated(d, descEnv, holders, verified) : healCoded(d, descEnv, holders, distinct, verified);
}
// Run the repair loop over every chunk this node holds a block of (§9).
function doRepair() {
  const seen = new Set();
  let replaced = 0;
  for (const id of storeList()) {
    const descriptor = storeGetDescriptor(id);
    if (!descriptor) continue;
    const key = toHex(hash(descriptor));
    if (seen.has(key)) continue;
    seen.add(key);
    replaced += repairChunk(descriptor);
  }
  const out = new Uint8Array(4);
  wU32(out, 0, replaced);
  return out;
}

// ── holder side (§5/§6/§7) ───────────────────────────────────────────────────
// The request side a node serves to its cohort: admission control (the §6 sibling
// rule + §14 quota), content-addressing (§4.2), and the <hex>.blk/.dsc + quota
// writes — the policy of host/storage-node.ts + host/store-fs.ts, now confined.
// Reached only through the generic caps, and entirely *synchronous*: a holder
// answers from local fs + crypto and never makes a net round trip, so it runs in
// a SYNC safe-js realm and can respond while an async orchestration realm is
// parked mid-await (the runtime split). bytesUsed mirrors
// FsBlobStore's byte budget, rebuilt lazily from the fs the first time it matters.
let bytesUsed = -1;
// The §14 byte budget is OPERATOR policy, not author content: the StorageNode
// injects its store's quota, and a seedkernel shell merges the operator's config
// over the (author-signed) manifest. When neither supplies one, fall back to a
// default so a holder never admits unbounded — the budget is never baked into the
// signed bundle. Keep this equal to store-local.ts DEFAULT_QUOTA_BYTES (the host-side
// store default); this fallback only bites a driver that injects no quota.
const DEFAULT_QUOTA = 64 * 1024 * 1024;
function quota() { return APP.quota != null ? APP.quota : DEFAULT_QUOTA; }
// CAP_FS_SIZE returns 0xffffffff for an absent key (fs.size → -1 over the bridge).
// fsSizeRaw preserves that sentinel — it is how existence is asked (storeHas), since
// there is no CAP_FS_HAS. fsSize maps the sentinel to 0 so sizing a bare block's missing
// .dsc adds nothing to the quota total, not ~4 GiB.
function fsSizeRaw(keyStr) { return rU32(host.call(CAP_FS_SIZE, strBytes(keyStr)), 0); }
function fsSize(keyStr) { const v = fsSizeRaw(keyStr); return v === 0xffffffff ? 0 : v; }
function ensureUsed() {
  if (bytesUsed >= 0) return;
  bytesUsed = 0;
  // Mirror FsBlobStore.usedBytes (store-fs.ts): the committed tier is the <hex>.blk
  // ciphertext AND its <hex>.dsc descriptor sidecar — the descriptor is real bytes,
  // so charging only .blk would over-admit relative to the host store's view (§14).
  for (const id of storeList()) { const hex = toHex(id); bytesUsed += fsSize(hex + STORE_BLK) + fsSize(hex + STORE_DSC); }
}
function quotaFree() { ensureUsed(); return Math.max(0, quota() - bytesUsed); }
function fsPut(keyStr, bytes) {
  const kb = strBytes(keyStr);
  const head = new Uint8Array(4); wU32(head, 0, kb.length);
  host.call(CAP_FS_PUT, concat([head, kb, bytes]));
}
// Mirror FsBlobStore.put (store-fs.ts): the <hex>.blk ciphertext + its sibling
// <hex>.dsc descriptor, under the quota budget. Throws past quota so admission
// refuses rather than over-commits.
function storeWrite(id, bytes, descriptor) {
  ensureUsed();
  const hex = toHex(id);
  // Charge the ciphertext AND the descriptor sidecar, crediting whatever was already
  // stored under this id — byte-for-byte as FsBlobStore.put (store-fs.ts) and
  // MemoryBlobStore, so a holder's §14 budget matches the host store's stat() at the
  // boundary instead of writing the .dsc for free.
  const prevBlk = storeHas(id) ? fsSize(hex + STORE_BLK) : 0;
  const prevDsc = fsSize(hex + STORE_DSC);
  const dscLen = descriptor && descriptor.length ? descriptor.length : 0;
  const next = bytesUsed - prevBlk - prevDsc + bytes.length + dscLen;
  if (next > quota()) throw new Error("store: quota exceeded");
  fsPut(hex + STORE_BLK, bytes);
  if (dscLen) fsPut(hex + STORE_DSC, descriptor);
  else if (prevDsc) host.call(CAP_FS_DELETE, strBytes(hex + STORE_DSC)); // described → bare
  bytesUsed = next;
}
// Admission (§6 sibling rule, §14 quota): a holder enforces no-two-blocks-of-a-
// chunk itself, so the §10 invariant survives a careless or malicious placer (a
// repairer included), not just an honest coordinator.
function admit(descriptor, blockId, size) {
  if (quotaFree() < size) return false;                       // committed tier full
  if (descriptor && descriptor.length) {
    const d = verifyDescriptor(descriptor);                   // forged/unsigned/malformed → null (§4.3)
    if (!d) return false;
    if (!d.blockIds.some((id) => bytesEqual(id, blockId))) return false; // not of this chunk
    for (const sib of d.blockIds) {                           // sibling rule (§6)
      if (bytesEqual(sib, blockId)) continue;
      if (storeHas(sib)) return false;
    }
  }
  return true;
}
// Batched admission (mirror StorageNode.admitBatch): one OFFER's worth of blocks
// checked cumulatively — the §14 quota budget shrinks as blocks are provisionally
// accepted, and a block whose sibling (§6) is already held OR provisionally
// accepted in this same batch is declined, so two blocks of one chunk never both
// pass. STORE re-checks each block (acceptStore/admit), so this is the advisory
// pre-check, never the enforcement.
function admitBatch(offers) {
  let free = quotaFree();
  const provisional = new Set();
  return offers.map((o) => {
    if (o.size > free) return false;
    if (o.descriptor && o.descriptor.length) {
      const d = verifyDescriptor(o.descriptor);
      if (!d || !d.blockIds.some((id) => bytesEqual(id, o.blockId))) return false; // forged/unsigned/not-of-chunk
      for (const sib of d.blockIds) {
        if (bytesEqual(sib, o.blockId)) continue;
        if (storeHas(sib) || provisional.has(toHex(sib))) return false;
      }
    }
    free -= o.size;
    provisional.add(toHex(o.blockId));
    return true;
  });
}
function acceptStore(blockId, descriptor, bytes) {
  // The bytes must hash to the claimed id (§4.2) — every holder, every hop.
  if (!bytesEqual(hash(bytes), blockId)) return false;
  if (!admit(descriptor, blockId, bytes.length)) return false;
  try { storeWrite(blockId, bytes, descriptor); return true; } catch (_e) { return false; }
}
// Serve a batched FETCH, but never emit more than one message's worth of bytes:
// an honest requester caps itself at fetchMaxIds() so its whole response fits, but a
// hostile cohort member can name the same id thousands of times in one ~1 MB request
// and make this sync holder concat thousands × blockSize into one reply. Cap the
// served bytes at maxMsgBytes (accounting for the response framing) — blocks past the
// cap come back absent, which the reader already handles by falling back per block, so
// this is pure hardening with no protocol change. A per-id memo keeps a repeated id
// from costing a fresh storeGet each time.
function serveFetch(ids) {
  const cap = maxMsgBytes();
  const out = new Array(ids.length).fill(null);
  const seen = new Map(); // idHex → bytes|null, so a repeated id is one storeGet
  let used = 4;           // the [count u32] response header
  for (let i = 0; i < ids.length; i++) {
    const h = toHex(ids[i]);
    let bytes = seen.get(h);
    if (bytes === undefined) { const sb = storeGet(ids[i]); bytes = sb ? sb.bytes : null; seen.set(h, bytes); }
    if (!bytes) continue;
    const framed = bytes.length + FETCH_FRAME;
    if (used + framed > cap) continue; // over the frame cap → serve as absent (reader falls back)
    out[i] = bytes;
    used += framed;
  }
  return out;
}
// The wire codecs a holder decodes/encodes (decodeHaveReq, encodeHaveRes,
// decodeOfferBatch, encodeOfferMask, decodeStoreBatch, encodeStoreMask,
// decodeFetchBatchReq, encodeFetchBatchRes) all come from the SHARED host/protocol.ts
// stitched in ahead of this body — the holder admits over the SAME §18 format the
// initiator speaks, by construction, not by a hand-kept mirror.

// Dispatch one incoming control message: arg = [type u8][payload]. Synchronous —
// every branch is local fs + crypto; the initiator owns the round trips. OFFER and
// FETCH carry a batch of blocks (one per peer per PUT/GET) and answer all at once.
function doHandle(arg) {
  const type = arg[0], payload = arg.slice(1);
  if (type === MSG_HAVE) return encodeHaveRes(decodeHaveReq(payload).map((id) => storeHas(id)));
  if (type === MSG_OFFER) return encodeOfferMask(admitBatch(decodeOfferBatch(payload)));
  if (type === MSG_STORE) return encodeStoreMask(decodeStoreBatch(payload).map((s) => acceptStore(s.blockId, s.descriptor, s.bytes)));
  if (type === MSG_FETCH) return encodeFetchBatchRes(serveFetch(decodeFetchBatchReq(payload)));
  return EMPTY;
}

register("put", doPut);
register("get", doGet);
register("repair", doRepair);
register("handle", doHandle);

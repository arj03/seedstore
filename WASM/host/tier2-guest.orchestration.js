// The Tier-2 guest — the WHOLE storage protocol (README §6/§7/§9) as zero-authority
// JS that runs *inside* the QuickJS realm (§2.1). This is the single
// implementation of placement, k-of-n, admission, the wire format, and repair: the
// host (host/storage-node.ts) only boots the kernel and runs this guest in one
// realm. Every capability is reached through the one `host.call(op, bytes)` seam.
// The seam is genuinely async: a net op (`CAP_NET_SEND`) resolves to a real Promise
// the initiator `await`s — so a fan-out is just `await Promise.all(peers.map(...))`,
// with the host driving the concurrent round trips — while every other cap
// (crypto/fs/clock/module) still resolves synchronously to its bytes.
//
// Two roles share this one program and this one realm. The *initiator* entrypoints
// (`put`/`get`/`repair`) are async — they fan out over net and park mid-`await`
// while their round trips settle. The *holder* entrypoint (`handle`: HAVE/OFFER/
// STORE/FETCH, admission, content-addressing, quota, fs writes) is purely
// synchronous (local fs + crypto, no net) and is invoked re-entrantly (`callSync`),
// so a node can answer a peer's request *while* its own initiator is parked mid-
// await in the same realm — a suspended async function is just heap state (the
// runtime split). Whichever entrypoint runs, the other role's code is dormant.
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
function rU64(b, off) { return rU32(b, off) * 0x100000000 + rU32(b, off + 4); }
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
// the <hex>.blk/.dsc store layout (read back host-side by host/store-view.ts, which
// implements none of the policy — see there). Config + the codec and
// reputation kernel names arrive as the injected `APP` constant (prepended by
// the driver), not as kernel ops. A sync op (crypto/fs/clock/module) resolves to
// its bytes directly, so its wrapper reads as an ordinary synchronous function; the
// net wrappers below are `async` and `await` the one round-trip op.

// The op bytes of the codec handler (the guest owns its ABI). The reputation handler's
// op bytes + request framing (REP_OBSERVE/REP_SCORE, encodeScoreReq/encodeObserveReq)
// come from the SHARED host/reputation-core.ts, stitched in ahead of this body — the same
// framing StorageNode.score uses host-side, so the two agree by construction.
const CODEC_ENCODE = 1, CODEC_DECODE = 2;     // assembly/codec/index.ts
// Control-plane message types carried over net.send (host/protocol.ts §18).
const MSG_HAVE = 1, MSG_OFFER = 2, MSG_FETCH = 3, MSG_STORE = 4;
// The protocol id this app speaks on the wire (§12.10) — placed in every NET_SEND frame
// so the receiving host routes it to this app. The app name from the manifest ("seedstore")
// is the default protocol id. strBytes encodes ASCII without TextEncoder (QuickJS has none).
const NET_PROTO = strBytes("seedstore");
const HAVE_ID_LEN = 32;      // a HAVE/FETCH request names 32-byte block_ids (§18)
const FETCH_FRAME = 5;       // a present block costs [found u8][len u32] in a FETCH response (§18)
const STORE_BLK = ".blk", STORE_DSC = ".dsc";
// The logical names this app's own modules are installed under. The guest calls
// its own modules by the logical name from its manifest — the cap-bridge resolves
// to the kernel name so kernel names never leave the host. Both are ASCII, so
// strBytes encodes.
const CODEC_NAME = strBytes("codec");
const REP_NAME = strBytes("reputation");
// The scoped-signature prefix `DOMAIN_guest ‖ scope` (README §16): the CAP_SIGN op signs
// `prefix ‖ msg`, never the raw msg, so a descriptor signature verifies only in this app's
// scope. CAP_VERIFY stays raw, so verifyEnv rebuilds `prefix ‖ core` before checking. The
// runtime derives these bytes from the admitted manifest's (author, app) and injects them
// as BUNDLE — the guest treats them as an opaque prefix, never reconstructing the kernel's
// domain string itself, and no build step ever restates them.
const SIGN_PREFIX = fromHex(BUNDLE.signPrefix);

// Two injected constants, with a hard split (seedkernel §12.4):
//   BUNDLE  facts the RUNTIME derived from the admitted manifest — author, app, the
//           signing prefix. Not operator-writable.
//   APP     the author's signed config, with operator policy merged over it
//           (storage-node.ts appPreamble builds it host-side; the shell merges
//           --app-config over the bundle's). Read directly as `APP.*`.
// smallMaxBlocks is §4.1 MATH, not an injected knob: it is fixed by (k, m), so the guest
// derives it here rather than reading an APP field that could disagree with k/m. It is the
// largest file (in blocks) still worth replicating whole instead of padding out to a chunk
// — replication beats padding while d < (k+m)/(m+1), so the largest replicated d is
// ceil((k+m)/(m+1)) − 1. The other two derived quantities, the replica count r = m + 1 and
// the low-water mark, are the same kind of math one step further out: they come off the
// SIGNED DESCRIPTOR (replicaTarget / lowWaterMargin in the shared manifest-core), so repair
// reads them from the chunk in hand and consults no config at all (§4.1, §9). This one is a
// WRITE-side choice — which shape to cut a new file into — so config is its only source.
function smallMaxBlocks() { const c = APP; return Math.max(1, Math.ceil((c.k + c.m) / (c.m + 1)) - 1); }

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
  // the descriptor's "blockIds.length must be k (replicated) or k+m (coded)" — or, worse,
  // as a chunk silently signed with the wrong shape. Fail here, where the cause is.
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
  return readF64LE(moduleCall(REP_NAME, encodeScoreReq(peerPk, t)));
}
function repObserve(peerPk, t, pass) {
  moduleCall(REP_NAME, encodeObserveReq(peerPk, t, pass)); // returns the new score; the guest doesn't need it
}

// ── local store over fs.* (the <hex>.blk / <hex>.dsc layout) ─────────────────
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
// The one genuinely-async cap: CAP_NET_SEND resolves to a Promise the initiator
// awaits (the host round-trips it). An unreachable peer resolves to `[0]` (never a
// reject), so this maps it to null within the request window.
// Wire format: [peer 32][pidLen u8][protocolId][type u8][payload] (§12.10).
async function netSend(peer, type, payload) {
  const head = new Uint8Array(33 + 1 + NET_PROTO.length); // peer(32) + pidLen(1) + proto + type(1)
  head.set(fromHex(peer), 0);
  head[32] = NET_PROTO.length;
  head.set(NET_PROTO, 33);
  head[33 + NET_PROTO.length] = type;
  const r = await host.call(CAP_NET_SEND, concat([head, payload]));
  return r[0] === 1 ? r.slice(1) : null; // null = peer unreachable within the window
}
// Per-peer fan-out (§6/§7): a DISTINCT request per peer, all issued CONCURRENTLY.
// With real net promises the guest fans out itself — `Promise.all` over netSend, the
// host driving every round trip in parallel — so there is no host-side scatter-gather
// cap. A broadcast of one shared payload to many peers (disc.have/want) is just N
// identical entries. `requests` = [{ peer, type, payload }]; results align to input
// order, an unreachable peer coming back `ok:false`/`bytes:null` (partial, never a
// throw — netSend already swallowed the unreachable case).
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
  for (const id of ids) if (storeHas(id)) holders.get(toHex(id)).add(myPeer());
  const peers = cohortPeers();
  // Split the id list so one HAVE request stays under the frame cap, exactly as
  // OFFER/STORE/FETCH do (§18). A HAVE request is 32 bytes/id (the reply is a 1-byte
  // mask, so the request is the binding side): on a tight transport (WebRTC's ~48 KB
  // cap → ~1.5k ids) an unsplit HAVE would break discovery for a modest file. Merge
  // the per-slice masks — a holder accumulates across slices.
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
// The HAVE/OFFER/STORE/FETCH wire codecs (encode/decodeHaveReq, encode/decodeOfferBatch,
// encode/decodeStoreBatch, encode/decodeFetchBatchReq, encode/decodeFetchBatchRes, and
// the shared encodeMask / decodeMask that all three of the HAVE/OFFER/STORE responses use)
// come from the SHARED host/protocol.ts, stitched in ahead of this body — one
// definition of the §18 control-plane format, not a hand-copied mirror. Composing them
// with netSend — and with the unreachable-peer (null) case — is transport policy, and
// there are exactly two places that do it: fetchBatch below, and the placement engine.

// Batched fetch from one peer (the GET hot path): one round trip for many blocks.
// Self reads the local store. Returns an array aligned to `ids` (bytes|null), or
// null for the whole batch if the peer was unreachable — so the caller can score a
// reachable-but-didn't-serve as a §8 miss but never an unreachable peer. The
// caller hash-verifies every block (§4.2).
async function fetchBatch(peer, ids) {
  if (peer === myPeer()) return ids.map((id) => { const sb = storeGet(id); return sb ? sb.bytes : null; });
  const resp = await netSend(peer, MSG_FETCH, encodeFetchBatchReq(ids));
  if (resp === null) return null;
  const blocks = decodeFetchBatchRes(resp);
  return ids.map((_, i) => blocks[i] || null);
}
// verification-fetch (§8): pull one block from a holder, confirm it hashes to its
// id, and score the holder. The hash check + reputation are the guest's, not the
// host's. Used for the manifest + repair; the GET path uses the batched fetchBatch.
async function verificationFetch(peer, id) {
  if (peer === myPeer()) {
    const sb = storeGet(id);
    return sb && bytesEqual(hash(sb.bytes), id) ? sb.bytes : null;
  }
  const resp = await netSend(peer, MSG_FETCH, encodeFetchBatchReq([id]));
  if (resp === null) return null;                       // unreachable — not a miss to score
  const data = decodeFetchBatchRes(resp)[0] || null;
  const t = clockNow();
  if (data && bytesEqual(hash(data), id)) { repObserve(fromHex(peer), t, true); return data; }
  repObserve(fromHex(peer), t, false);
  return null;
}
// There is ONE placement engine (placeChunksBatched, below) and it drives the shared
// §18 codecs — encodeOfferBatch / encodeStoreBatch with the shared decodeMask
// (host/protocol.ts) — directly through netSendMany, mapping an unreachable peer
// (netSend → null) to all-declines. Nothing places a block any other way: a small
// file, a window of coded chunks, the manifest, and a repair pass all express
// themselves as (block, slot) targets and hand them to that one function.

// ── descriptor + manifest ────────────────────────────────────────────────────
// The pure §4.3 codecs — encode/decodeDescriptorCore, parseSignedDescriptor,
// encode/decodeManifest, descriptorContains, ENC_XCHACHA20, BLOCK_ID_LEN — come from
// the SHARED host/manifest-core.ts, stitched in ahead of this body (one definition).
// What stays here is only the part that needs a capability: verify/sign over the
// CAP_VERIFY / CAP_SIGN seam, composed with the shared parser/encoder.
//
// verifyDescriptor checks the author signature AND structurally validates the core
// (the parity the host holder has): a *signed* but malformed descriptor (junk core, an id
// count that is neither k nor k+m) is rejected — not parsed into garbage block-ids that
// sidestep the §10 sibling rule — because parseSignedDescriptor throws on a bad core.
function verifyDescriptor(env) {
  // Length-gate before the CAP_VERIFY seam: the envelope is [pk 32][sig 64][core ≥8]
  // (parseSignedDescriptor's own bound), so anything shorter — an absent descriptor
  // included — is rejected here rather than handed to verify as a short buffer.
  if (!env || env.length < 32 + 64 + 8) return null;
  if (!verifyEnv(env)) return null;
  try { return parseSignedDescriptor(env).descriptor; } catch (_e) { return null; }
}
function signChunk(d) { return signCore(encodeDescriptorCore(d)); }

// ── placement + fetch (coordinator §6/§7) ────────────────────────────────────
// A batched OFFER / STORE / FETCH is split to stay under APP.maxMessageBytes —
// the per-transport cap that keeps one message inside the frame cap AND the request
// timeout. Transport/operator policy injected via the APP preamble (like quota);
// default if absent.
function maxMsgBytes() { const v = APP.maxMessageBytes; return (typeof v === "number" && v > 0) ? v : (1 << 20); }
// Ids per FETCH sub-batch, bounded by the RESPONSE frame (blockSize + FETCH_FRAME per
// present block) so a full reply stays under the cap. The GET gather and the repair
// audit both size their batches this way; the holder caps served bytes the same (§18).
function fetchMaxIds() { return Math.max(1, Math.floor(maxMsgBytes() / (APP.blockSize + FETCH_FRAME))); }
// The fan-out windows (transport/operator policy, like maxMessageBytes): how many
// per-peer sub-batches a single Promise.all round fires at once. putWindow bounds
// STORE messages PER PEER (peers concurrent → peak W·peers); getWindow bounds FETCH
// messages TOTAL across the cohort (peak W), so the guest pipelines a holder's many
// ~1-block messages instead of paying one round trip apiece (the tight-cap WebRTC
// case the lock-step fan-out was meant to keep windowed). Injected in full by the
// driver (core.ts homes the default); the guest reads APP and never guesses.
function putWindow() { return APP.putWindow; }
function getWindow() { return APP.getWindow; }
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
// A placement JOB: the unit the one engine below consumes. It is a flat list of SLOTS —
// (block bytes, id) targets to land on distinct peers — plus the signed descriptor that
// admits them, a `floor` of distinct ids that must land, and the peers the job may not
// use. Everything that places blocks builds one of these:
//
//   a chunk (makeChunk)  slotIndices(d) — a coded chunk's k+m blocks once each, a
//                        replicated chunk's k blocks r = m+1 times each; floor = its own k
//   the manifest         the k=1 replicated case of exactly that
//   a repair pass (heal) only the copies still owed, floor 0 (best-effort), excluding the
//                        peers already holding part of the chunk
//
// So placement has one sentence of semantics: a set of (block, slot) targets negotiated
// in batched rounds.
function makeJob(slotIds, slotBlocks, descriptor, floor, exclude) {
  return {
    floor, slotIds, slotBlocks, descriptor, exclude,
    placedPeer: new Array(slotIds.length).fill(null),
    placedIds: [],
  };
}
// A signed chunk ready to place, expanded into its placement slots (§6/§10). Placement
// then treats both kinds identically: it only ever sees a list of slots to land on
// distinct peers. The floor is the chunk's OWN k, not config's — a small file's chunk has
// k = d — and a fresh chunk excludes nothing.
function makeChunk(d, blocks, descriptor) {
  const slots = slotIndices(d);
  return makeJob(slots.map((i) => d.blockIds[i]), slots.map((i) => blocks[i]), descriptor, d.k, new Set());
}
// Encode + sign one chunk: encrypt k data blocks, then add m parity (k ≥ 2, a coded
// chunk) or, at k = 1, replicate the lone block r = m+1 ways (see below). `source` is
// the plaintext this chunk is cut from — the whole file (localCi == globalCi) or just a
// window slice (localCi indexes within the slice). The AEAD counter is the GLOBAL chunk
// index (§4.4), so a windowed encode is byte-identical to a whole-file one regardless of
// how the plaintext was sliced.
function encodeChunk(source, localCi, globalCi, K) {
  const c = APP;
  const start = localCi * c.k * c.blockSize;
  const chunkPlain = source.slice(start, start + c.k * c.blockSize);
  const ct = encrypt(K, DOMAIN_BODY, globalCi, padTo(chunkPlain, c.k * c.blockSize));
  const dataBlocks = splitBlocks(ct, c.blockSize);
  // RS(1,m) is replication in disguise: its m parity blocks come out byte-identical to
  // the lone data block (parity ≡ data), so the chunk is ONE block on r = m+1 distinct
  // peers and the codec is skipped entirely — coding is k ≥ 2 only. The descriptor is a
  // replicated one (its k ids listed once) and still records the SAME m: "survives m
  // losses", bought with copies rather than parity. Nothing downstream branches on which
  // it got — makeChunk expands either into slots, and repair reads m off the signature.
  const blocks = c.k === 1 ? dataBlocks : [...dataBlocks, ...rsEncode(c.k, c.m, c.blockSize, dataBlocks)];
  const d = { k: c.k, m: c.m, blockSize: c.blockSize, blockIds: blocks.map(hash) };
  return makeChunk(d, blocks, signChunk(d));
}
// THE placement engine (§6/§10). Place every job's slots with one batched OFFER per peer
// per round, then the accepted blocks STORE'd in putWindow()-deep fan-outs per peer.
// Slot i targets cands[i], cands[i+slots], … (a disjoint residue class per i, so one
// job's slots land on distinct peers — which is the sibling rule for a coded chunk, the
// r distinct replica holders for a replicated one, and "somewhere new" for a repaired
// copy: one rule). Per peer the OFFER is one round trip for slot i of every job at once;
// the STOREs that follow window the peer's many capped messages (peak W·peers). Returns
// nothing; fills each job's placedPeer[] and placedIds[].
//
// Throws if a job lands fewer than its `floor` distinct ids — for a chunk, the readable
// floor either way: any k of a coded chunk's blocks reconstruct it, and a replicated
// chunk lists exactly the k blocks it needs. `what` names the job in that error, so a
// failure says which placement gave up; a floor of 0 is best-effort (repair places what
// the cohort will take and the next pass retries the rest), which cannot raise it and so
// passes no name.
async function placeChunksBatched(jobs, what) {
  const ranked = rank(cohortPeers());
  // Each job draws from the ranked cohort minus the peers it must avoid. PUT excludes
  // nothing (a fresh chunk is nowhere yet); repair excludes the peers already holding
  // part of the chunk, so a restored copy lands somewhere new instead of being pushed at
  // a holder that would either decline it as a sibling (§6) or silently overwrite the
  // copy it already has.
  const candsOf = new Map();
  for (const job of jobs) candsOf.set(job, job.exclude.size === 0 ? ranked : ranked.filter((p) => !job.exclude.has(p)));
  const maxBytes = maxMsgBytes();
  const entryBytes = 36 + (jobs.length ? jobs[0].descriptor.length : 0); // one OFFER entry: [blockId 32][dlen u32][descriptor]
  const maxOffers = Math.max(1, Math.floor(maxBytes / entryBytes));

  // Advisory diagnostics collected from holder verdicts — a holder may lie, so the
  // reason is never policy, but the error a failed PUT throws becomes exact.
  const diag = { quota: 0, sibling: 0, descriptor: 0 };

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

    // Lock-step fan-out: ALL of this round's OFFERs (one Promise.all over the peers)
    // complete before its STOREs (no optimistic STORE — §6). The OFFER
    // phase carries ≤1 message per peer per fan-out (a peer's offers are small and
    // rarely exceed maxOffers, so the sub-batch index is round-robined one-per-peer).
    // The STORE phase windows up to putWindow() of a peer's byte-bounded sub-batches
    // into each fan-out (peers concurrent → peak W·peers), so a holder's many capped
    // STORE messages pipeline instead of going one round trip apiece — a within-phase
    // parallelism bounded by putWindow. Within a phase every peer goes in
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
        }
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
      storeGroups.set(peer, batchBytes(accepted, ({ ch, i }) => 40 + ch.descriptor.length + ch.slotBlocks[i].length, maxBytes));
    }
    const putW = putWindow();
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
      const detail = parts.length ? " (" + total + " holders: " + parts.join(", ") + ")" : "";
      throw new Error("put: " + what + " landed " + distinct.size + "/" + ch.floor + " distinct blocks — holders declined" + detail + ". Check quota (--app-config), signing scope (§16), or connect more holders");
    }
    ch.placedIds = [...distinct].map(fromHex);  // the distinct ids that landed, for the PUT result
  }
}
// Fetch a block from whichever cohort peer holds it, verifying by hash (manifest + repair).
async function fetchBlock(id) {
  const holders = (await haveWant([id])).get(toHex(id)) || new Set();
  for (const peer of rank([...holders])) {
    const b = await verificationFetch(peer, id);
    if (b) return b;
  }
  return null;
}
// Run a windowed batched FETCH over a peer→[idHex] plan. Self reads the local store
// directly (no round trip, no scoring); every other holder's sub-batches are flattened
// into one task list and fanned out getWindow() FETCH messages at a time (peak W in
// flight, the getWindow window). `apply(peer, sliceHex, ids, blocks)` sees each
// sub-batch's result — blocks aligned to ids (bytes|null), or null for the whole slice
// if the peer was unreachable (partial, never a §8 miss). Shared by the GET gather and
// the repair audit, so both express the same window through one Promise.all round.
//
// Truncation vs miss is a wire bit: a holder bounds one FETCH response by ITS
// maxMessageBytes (serveFetch), which can be smaller than ours (the caps are per-node
// operator policy, so they diverge). A block it has but couldn't fit comes back tagged
// FETCH_UNANSWERED, distinct from an ABSENT genuine miss (§18). Re-request exactly the
// unanswered blocks as a fresh task; report present/absent as final verdicts, so `apply`
// (and the tried/§8-miss bookkeeping on it) only ever sees decided blocks. serveFetch
// always serves the first present block, so each re-request round resolves ≥1 block, which
// terminates. A genuine miss is ABSENT even past the cap, so it is ruled a miss in one
// round trip.
async function runFetchTasks(byPeer, maxIds, apply) {
  const me = myPeer();
  if (byPeer.has(me)) {
    for (const slice of sliceN(byPeer.get(me), maxIds)) {
      const ids = slice.map(fromHex);
      apply(me, slice, ids, await fetchBatch(me, ids));
    }
  }
  const tasks = []; // { peer, slice, ids } — re-requested unanswered blocks are appended and picked up by later windows
  for (const peer of byPeer.keys()) {
    if (peer === me) continue;
    for (const slice of sliceN(byPeer.get(peer), maxIds)) tasks.push({ peer, slice, ids: slice.map(fromHex) });
  }
  const getW = getWindow();
  for (let base = 0; base < tasks.length; base += getW) {
    const window = tasks.slice(base, base + getW);
    const results = await netSendMany(window.map(({ peer, ids }) => ({ peer, type: MSG_FETCH, payload: encodeFetchBatchReq(ids) })));
    for (let ri = 0; ri < results.length; ri++) {
      const { peer, slice, ids } = window[ri];
      if (!results[ri].ok) { apply(results[ri].peer, slice, ids, null); continue; } // unreachable
      const decoded = decodeFetchBatchRes(results[ri].bytes);
      // Split the holder's answers over the ids we asked: FETCH_UNANSWERED blocks (no room
      // under the holder's cap) re-queue as a fresh task; present/absent are final verdicts
      // for `apply`. A short/malformed response leaves an id undefined, ruled absent.
      const reSlice = [], reIds = [], aSlice = [], aIds = [], aBlocks = [];
      for (let i = 0; i < slice.length; i++) {
        if (decoded[i] === FETCH_UNANSWERED) { reSlice.push(slice[i]); reIds.push(ids[i]); }
        else { aSlice.push(slice[i]); aIds.push(ids[i]); aBlocks.push(decoded[i] || null); }
      }
      if (reSlice.length) tasks.push({ peer, slice: reSlice, ids: reIds });
      if (aSlice.length) apply(results[ri].peer, aSlice, aIds, aBlocks);
    }
  }
}
// Fetch every block the file's chunks need, batched per holder. After the file-wide
// have/want, each still-missing block is requested from its best untried holder,
// sub-batched under the frame cap and fanned out getWindow() FETCH messages at a time
// (peak W in flight, the getWindow window); a coded chunk stops at k, preferring
// data blocks. Every returned block is hash-verified (§4.2) and scores its holder
// (§8). Returns a Map id-hex → bytes.
async function gatherBlocks(descriptors, holders) {
  const c = APP;
  const got = new Map();
  const tried = new Map();
  const triedOf = (h) => { let s = tried.get(h); if (!s) tried.set(h, (s = new Set())); return s; };
  // Bound a FETCH sub-batch by the RESPONSE size: each present block is blockSize +
  // FETCH_FRAME on the wire, so dividing by blockSize alone would let a full response
  // slip just past the cap (the request side, 32 B/id, is smaller and never binds).
  const maxIds = fetchMaxIds();

  // k distinct ids read a chunk, whichever kind it is (§4.1): any k of a coded chunk's
  // k+m blocks reconstruct it, and a replicated chunk lists exactly the k blocks it needs.
  const stillNeeds = (d) => {
    const distinct = new Set();
    for (const id of d.blockIds) if (got.has(toHex(id))) distinct.add(toHex(id));
    return Math.max(0, d.k - distinct.size);
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
    await runFetchTasks(byPeer, maxIds, applyFetch);
  }
  return got;
}
// Assemble one chunk's ciphertext from the gathered blocks (§4.1/§7). One path for both
// kinds of chunk: take the first k listed blocks that arrived, and if they are the k data
// blocks in order just concatenate them (systematic RS — the common case, and the ONLY
// case for a replicated chunk, whose k listed blocks are all data). Anything else decodes.
function assembleChunk(d, got) {
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
// A large file is never wholly resident in the confined guest heap: it is encoded
// and placed in chunk-aligned WINDOWS, and each window's ciphertext blocks are
// dropped once placed (README §3). The driver streams the plaintext IN a window at a
// time (putStart → putWindow* → putFinish), so not even the 1× plaintext ever fully
// crosses into the guest. The whole-file `put` entry (used by the seedkernel shell and
// the Go loader, which hand over bytes and read bytes back) drives that very same loop
// over its own in-memory argument — one windowed loop, not two.

// Target footprint for one window's plaintext slice; the ciphertext it expands to
// (≈ n/k×) plus the slice stays a small fraction of the realm heap at any file size.
// The host driver awaits each window fully (OFFER→STORE→ack) before feeding the next,
// so on a fat/low-loss link a too-small window idles the wire between windows; the
// deployment raises it (with realmMemoryBytes) via APP.windowTargetBytes. Injected in
// full by the driver (core.ts homes the default); the guest reads APP and never guesses.
// This is the reader's/writer's OWN memory policy, not file geometry, so it stays a
// config value even on the descriptor-authoritative GET path.
function windowTarget() { return APP.windowTargetBytes; }
// A chunk-aligned window size in bytes: as many whole chunks (k·blockSize) as fit
// under the target, at least one. Kept a multiple of k·blockSize so slicing the file
// at window boundaries never splits a chunk. This is the WRITE side, so k·blockSize is
// the config the writer encodes with.
function putWindowBytes() { const chunkData = APP.k * APP.blockSize; return Math.max(1, Math.floor(windowTarget() / chunkData)) * chunkData; }
// Chunks per GET window — the reconstruct side's counterpart, bounding the plaintext a
// single getChunk holds before it is handed back to the host. `chunkData` (k·blockSize)
// is the DESCRIPTOR's geometry (§4.3), passed in by the reader, never config's.
function getWindowChunks(chunkData) { return Math.max(1, Math.floor(windowTarget() / chunkData)); }

// Replicate a small file r = m+1 times, not coded (§4.1) — a file too small to fill a
// chunk. It is ONE replicated chunk of d ≤ smallMaxBlocks() blocks: its descriptor lists
// those d ids (so k = d, the file's own geometry, not config's) and records the same m the
// deployment codes with, since r = m+1 copies survive the same m losses a coded chunk does.
// From there it is an ordinary chunk — the same slot expansion and the same batched
// placement a window uses. The file is small by definition, so it needs no windowing.
async function placeSmall(plaintext, K) {
  const c = APP;
  const d = Math.max(1, Math.ceil(plaintext.length / c.blockSize));
  const ct = encrypt(K, DOMAIN_BODY, 0, padTo(plaintext, d * c.blockSize));
  const blocks = splitBlocks(ct, c.blockSize);
  const desc = { k: d, m: c.m, blockSize: c.blockSize, blockIds: blocks.map(hash) };
  const chunks = [makeChunk(desc, blocks, signChunk(desc))];
  await placeChunksBatched(chunks, "chunk");
  return chunks;
}

// Encode + place the chunks wholly contained in `slice` — a chunk-aligned slice of the
// file starting at byte offset `baseByteOffset` (a multiple of k·blockSize). Returns the
// placed chunks; their ciphertext blocks fall out of scope once the caller has folded
// the descriptors into the stream. A k ≥ 2 window is RS-coded (n distinct blocks per
// chunk, one per peer); a k = 1 window is replication (one block per chunk, r = m+1
// copies on r distinct peers) — encodeChunk decides, placeChunksBatched fans both out
// the same way.
async function placeWindow(slice, baseByteOffset, K) {
  const c = APP;
  const chunkData = c.k * c.blockSize;
  const baseCi = Math.floor(baseByteOffset / chunkData);
  const numChunks = Math.max(1, Math.ceil(slice.length / chunkData));
  const chunks = [];
  for (let lc = 0; lc < numChunks; lc++) chunks.push(encodeChunk(slice, lc, baseCi + lc, K));
  await placeChunksBatched(chunks, "chunk");
  return chunks;
}

// Build, encrypt, and replicate the manifest (§4.3) over the collected chunk
// descriptors. Carried as a one-block replicated chunk (k=1, the manifest's own
// block_id, m = the deployment's), so it goes through the SAME placement engine as
// everything else — r = m+1 copies on distinct peers — and repair audits and
// re-replicates it exactly as it does any other replicated chunk (§9). Returns the
// manifest block id; a floor of k = 1 means placement throws if no peer took a copy.
async function placeManifest(K, fileSize, descriptors) {
  const manPlain = encodeManifest({ fileSize, encAlg: ENC_XCHACHA20, chunks: descriptors });
  const manCt = encrypt(K, DOMAIN_MANIFEST, 0, manPlain);
  const manifestId = hash(manCt);
  const man = { k: 1, m: APP.m, blockSize: manCt.length, blockIds: [manifestId] };
  await placeChunksBatched([makeChunk(man, [manCt], signChunk(man))], "manifest");
  return manifestId;
}

// ── the streamed PUT session ─────────────────────────────────────────────────
// The protocol state a PUT carries between windows — the file's content key K, how far
// into the file we are, the signed descriptors placed so far, the replica accounting —
// lives HERE, in realm state, instead of being round-tripped through the driver. One
// implicit session is safe by construction: every driver runs an initiator operation to
// completion before starting the next (StorageNode's runExclusive; the whole-file
// wrappers below are a single call), so two streams never overlap in this realm.
let putStream = null;
function requirePut() {
  if (!putStream) throw new Error("put: no stream open — call putStart first");
  return putStream;
}
// Open a stream: mint K, decide the file's shape (§4.1 — a file too small to fill a chunk
// is replicated whole rather than coded), and answer with the plaintext window the driver
// should feed. A replicated file is ONE window, since it is smaller than a chunk by
// definition; the `max(1, …)` keeps a driver's feed loop finite for an empty file.
function putStart(fileSize) {
  const c = APP;
  const replicated = Math.max(1, Math.ceil(fileSize / c.blockSize)) <= smallMaxBlocks();
  putStream = {
    K: randomKey(), fileSize, replicated, offset: 0,
    descriptors: [], placedIds: [], placed: 0, intended: 0,
  };
  return replicated ? Math.max(1, fileSize) : putWindowBytes();
}
// Fold one placed window's chunks into the stream (§8). Durability accounting counts
// REPLICA PLACEMENTS — one stored (block, peer), i.e. one filled slot — not distinct ids:
// a replicated chunk is k ids on r peers each, so counting ids would report k even when
// every copy landed. `intended` is capped at the reachable cohort because the §6/§10
// sibling rule puts at most one of a chunk's blocks on any one peer — so a genuinely
// small cohort is not flagged, while a reachable-but-declining (full) holder makes
// placed < intended.
function recordWindow(chunks) {
  const s = putStream;
  const peerCount = cohortPeers().length;
  for (const ch of chunks) {
    s.descriptors.push(ch.descriptor);
    for (const id of ch.placedIds) s.placedIds.push(id);
    for (const p of ch.placedPeer) if (p) s.placed++;
    s.intended += Math.min(ch.slotIds.length, peerCount);
  }
}
// Feed the next plaintext window, in file order — the whole file for a replicated one,
// a chunk-aligned slice otherwise. Its ciphertext is placed and dropped before this
// returns; the driver never learns the window's byte offset, because the stream knows it.
async function putFeed(slice) {
  const s = requirePut();
  recordWindow(s.replicated ? await placeSmall(slice, s.K) : await placeWindow(slice, s.offset, s.K));
  s.offset += slice.length;
}
// Seal the stream: replicate the manifest over every descriptor placed, then report the
// whole PUT. The stream closes first, so a failed or abandoned PUT leaves nothing behind
// for the next one to inherit.
async function putFinish() {
  const s = requirePut();
  putStream = null;
  const manifestId = await placeManifest(s.K, s.fileSize, s.descriptors);
  s.placedIds.push(manifestId);
  return encodePutResult(manifestId, s);
}
// The ONE PUT result format, read by every driver:
//   [manifestId 32][replicated u8][chunkCount u32][K 32][placed u32][intended u32]
//   [idCount u32]{id 32}
// Offsets 0–68 are fixed and the id tail comes last, so the byte-in/byte-out drivers (the
// seedkernel shell, the Go loader) can read the root and K without knowing the rest.
// (placed, intended) is the replica accounting (§8) — how many replicas landed vs how many
// were reachable-and-intended — so a driver can warn on a PUT that met the ≥ k floor but
// is silently under-replicated (a full/declining holder, or a short cohort).
function encodePutResult(manifestId, s) {
  const out = new Uint8Array(81 + s.placedIds.length * 32);
  out.set(manifestId, 0);
  out[32] = s.replicated ? 1 : 0;
  wU32(out, 33, s.descriptors.length);
  out.set(s.K, 37);
  wU32(out, 69, s.placed);
  wU32(out, 73, s.intended);
  wU32(out, 77, s.placedIds.length);
  for (let i = 0; i < s.placedIds.length; i++) out.set(s.placedIds[i], 81 + i * 32);
  return out;
}

// [fileSize u64] → [windowBytes u32]: open the stream, report the feed size.
function doPutStart(arg) { const out = new Uint8Array(4); wU32(out, 0, putStart(rU64(arg, 0))); return out; }
// The window's plaintext, raw — no framing, since the stream holds everything else.
async function doPutWindow(arg) { await putFeed(arg); return EMPTY; }
// No argument — the stream is the argument.
function doPutFinish() { return putFinish(); }

// Whole-file PUT: one call, bytes in, result out — what the seedkernel shell and the Go
// loader drive, since they pass raw bytes and read raw bytes and hold no protocol
// structure of their own. It runs the very same session as the streamed path, so there
// is one windowed loop and one result format; only the 1× plaintext is resident, which
// still bounds the ≈ n/k× ciphertext amplification.
async function doPut(plaintext) {
  const wb = putStart(plaintext.length);
  for (let off = 0; ; off += wb) {
    await putFeed(plaintext.subarray(off, Math.min(off + wb, plaintext.length)));
    if (off + wb >= plaintext.length) break;
  }
  return putFinish();
}

// ── GET (§7) ─────────────────────────────────────────────────────────────────
// Fetch, reconstruct (§4.1) and decrypt (§4.4) the plaintext for a run of already-
// verified chunk descriptors `ds` whose first chunk is global index `chunkStart`.
// `fileSize` bounds the tail so the last chunk's zero-padding is trimmed. One
// have/want + batched FETCH per holder (gatherBlocks) over just these chunks' block
// ids — shared by the whole-file `get` and the streamed getChunk window.
async function reconstructChunks(ds, K, chunkStart, fileSize) {
  const allIds = [];
  for (const d of ds) for (const id of d.blockIds) allIds.push(id);
  const holders = await haveWant(allIds);
  const got = await gatherBlocks(ds, holders);
  // Geometry is the DESCRIPTOR's, never config's (§4.1/§4.3): descriptors are self-
  // describing, so a reader/repairer needs no config and — the point of the fix — a file
  // decodes (assembleChunk/rsDecode use d.k/d.blockSize) and offsets by the SAME numbers,
  // never one by the descriptor and the other by a config that could disagree. Every full
  // chunk contributes k·blockSize plaintext bytes; only the file's final chunk is shorter
  // (trailing padding, trimmed below), and all of a file's chunks share one geometry.
  const chunkData = ds.length ? ds[0].k * ds[0].blockSize : 0;
  let written = chunkStart * chunkData; // bytes of the file before this run (all prior chunks are full)
  const parts = [];
  for (let i = 0; i < ds.length; i++) {
    const d = ds[i];
    const chunkCipher = assembleChunk(d, got);
    // AEAD counter = the GLOBAL chunk index (§4.4), matching encodeChunk. A replicated
    // chunk is no special case: placeSmall's whole-file chunk is index 0, and a windowed
    // k=1 chunk carries its own index, so both decrypt at chunkStart + i.
    const chunkPlain = decrypt(K, DOMAIN_BODY, chunkStart + i, chunkCipher);
    const take = Math.min(chunkPlain.length, fileSize - written);
    parts.push(take === chunkPlain.length ? chunkPlain : chunkPlain.subarray(0, take));
    written += take;
  }
  return concat(parts);
}
// ── the streamed GET session ─────────────────────────────────────────────────
// The mirror of the PUT stream: getStart fetches the manifest, verifies EVERY chunk
// descriptor once, and keeps them — parsed, verified, in file order — in realm state.
// The driver then calls getNext until it has the file, each call reconstructing one
// window's chunks, so only one window's plaintext is ever resident. Because the
// descriptors never leave the realm there is nothing to re-parse or re-verify per
// window: a descriptor is checked exactly once, where the signature actually matters.
let getStream = null;
// Open a stream. The manifest is encrypted, not signed, so a correct K over a tampered
// manifest is caught only by the per-chunk signature — verify every descriptor here,
// before a single block is fetched against it (§4.3).
async function getStart(manifestId, K) {
  const manCt = await fetchBlock(manifestId);
  if (!manCt) throw new Error("get: manifest not found in cohort");
  const man = decodeManifest(decrypt(K, DOMAIN_MANIFEST, 0, manCt));
  const ds = man.chunks.map((env) => {
    const d = verifyDescriptor(env);
    if (!d) throw new Error("get: chunk descriptor signature invalid");
    return d;
  });
  // Window granularity from the chunk's OWN geometry (§4.3), not config: a full chunk is
  // k·blockSize plaintext, and the reader holds windowTarget()-worth at a time.
  const chunkData = ds.length ? ds[0].k * ds[0].blockSize : 1;
  getStream = { K, ds, fileSize: man.fileSize, next: 0, windowChunks: getWindowChunks(chunkData) };
  return man.fileSize;
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
  return reconstructChunks(ds, s.K, start, s.fileSize);
}

// [manifestId 32][K 32] → [fileSize u64]: open the stream, report how much to drain.
async function doGetStart(arg) {
  const out = new Uint8Array(8);
  wU64(out, 0, await getStart(arg.slice(0, 32), arg.slice(32, 64)));
  return out;
}
// No argument — the stream is the argument.
function doGetNext() { return getNext(); }

// Whole-file GET: the counterpart of the whole-file `put`, draining the same stream in
// one call for the byte-in/byte-out drivers.
async function doGet(arg) {
  await getStart(arg.slice(0, 32), arg.slice(32, 64));
  const parts = [];
  while (getStream) parts.push(await getNext());
  return concat(parts);
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
async function liveHolders(ids) {
  const advertised = await haveWant(ids);
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
  const applyAudit = (peer, slice, idBytes, blocks) => { // synchronous — hash + repObserve are sync ops
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
  await runFetchTasks(byPeer, fetchMaxIds(), applyAudit);
  return { live, bytes };
}
// Heal one chunk back toward full redundancy (§9), from its signed descriptor alone.
// ONE slot model covers both kinds, because the descriptor says which it is: every
// listed block wants r copies on distinct peers — r = m+1 for a replicated chunk, r = 1
// for a coded one, whose redundancy is its m parity blocks instead. A block short of r
// is topped up from the copy the audit (liveHolders) already fetched and verified, so a
// block that still has a live holder costs no extra round trip. A CODED block no live
// holder serves at all has no copy to lean on, so it is first reconstructed from any k
// present blocks and re-certified against its signed block_id; a lost replica has no
// parity to rebuild from — its other copies were the redundancy — so it can only be
// copied while one survives. The copies it ends up owing are then just placement slots,
// handed to the same engine PUT uses.
async function heal(d, descEnv, holders, verified) {
  const r = replicaTarget(d);
  const copiesOf = (h) => (holders.get(h) || new Set()).size;

  const regenerated = new Map();
  if (!isReplicated(d) && d.blockIds.some((id) => copiesOf(toHex(id)) === 0)) {
    const present = [];
    for (let idx = 0; idx < d.blockIds.length && present.length < d.k; idx++) {
      const b = verified.get(toHex(d.blockIds[idx])); // present iff that id has a live holder
      if (b) present.push({ index: idx, bytes: b });
    }
    if (present.length >= d.k) {
      const data = rsDecode(d.k, d.m, d.blockSize, present);
      const all = [...data, ...rsEncode(d.k, d.m, d.blockSize, data)];
      for (let i = 0; i < all.length; i++) {
        // Re-certify against the already-signed id (§9): a mismatch means a bad
        // input/decode — drop it, never propagate (a poisoned descriptor can't mint).
        if (bytesEqual(hash(all[i]), d.blockIds[i])) regenerated.set(toHex(d.blockIds[i]), all[i]);
      }
    }
  }

  // Every peer already holding part of this chunk. Restored copies go somewhere else
  // (§6, §10 — the sibling rule, which is also what keeps r replicas distinct).
  const occupied = new Set();
  for (const set of holders.values()) for (const p of set) occupied.add(p);

  // The copies still owed, expressed as PLACEMENT SLOTS — exactly what a PUT window hands
  // the engine, so "place the regenerated blocks" is the same call as placing a window.
  // A block already at full redundancy contributes no slots, and neither does one with no
  // live copy that this pass couldn't reconstruct.
  const slotIds = [], slotBlocks = [];
  for (const id of d.blockIds) {
    const h = toHex(id);
    const bytes = verified.get(h) || regenerated.get(h);
    if (!bytes) continue;
    for (let have = copiesOf(h); have < r; have++) { slotIds.push(id); slotBlocks.push(bytes); }
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
  const d = verifyDescriptor(descEnv);                     // forged/unsigned/malformed → null (§4.3)
  if (!d) return 0;
  const { live: holders, bytes: verified } = await liveHolders(d.blockIds);
  // Chunk health is ONE number for both kinds of chunk (§8, §9): the loss margin — how
  // many further losses this chunk survives — against the low-water mark ⌈m/2⌉. Both
  // come out of the shared manifest-core from the SIGNED descriptor, so a repairer needs
  // no deployment config here either: a cohort running mixed geometry (§4.1) repairs
  // each chunk to the count its own author signed.
  const copies = d.blockIds.map((id) => (holders.get(toHex(id)) || new Set()).size);
  if (lossMargin(d, copies) >= lowWaterMargin(d)) return 0;          // healthy
  return heal(d, descEnv, holders, verified);
}
// Run the repair loop over every chunk this node holds a block of (§9).
async function doRepair() {
  const seen = new Set();
  let replaced = 0;
  for (const id of storeList()) {
    const descriptor = storeGetDescriptor(id);
    if (!descriptor) continue;
    const key = toHex(hash(descriptor));
    if (seen.has(key)) continue;
    seen.add(key);
    replaced += await repairChunk(descriptor);
  }
  const out = new Uint8Array(4);
  wU32(out, 0, replaced);
  return out;
}

// ── holder side (§5/§6/§7) ───────────────────────────────────────────────────
// The request side a node serves to its cohort: admission control (the §6 sibling
// rule + §14 quota), content-addressing (§4.2), and the <hex>.blk/.dsc + quota
// writes — all of it confined here, and nowhere else: the host has a read view of
// the same fs (host/store-view.ts) and no write path at all.
// Reached only through the generic caps, and entirely *synchronous*: a holder
// answers from local fs + crypto and never makes a net round trip, so it is invoked
// synchronously (`callSync`) and can respond while this realm's own initiator is
// parked mid-await (the runtime split — a suspended async function is just heap
// state). Because it reaches only sync ops, `doHandle` and every function it calls
// must stay synchronous: an `await` here would return a guest promise that callSync
// cannot settle. This is the ONLY implementation of the quota rule — the host keeps a
// read view of the fs (host/store-view.ts) and no write path — so bytesUsed is the
// budget, rebuilt lazily from the fs the first time it matters.
let bytesUsed = -1;
// The §14 byte budget is OPERATOR policy, not author content: the StorageNode injects
// its store's quota, and a seedkernel shell merges the operator's config over the
// (author-signed) manifest — so it is always present in the injected APP, never baked
// into the signed bundle. The guest reads it and never guesses a *generous* default: if
// a driver under-injects (a shell holder booted with no operator quota — the shell keeps
// no default of its own), fall to 0 and FAIL CLOSED, so the holder admits nothing rather
// than becoming an unbounded sink. Reads (FETCH) never check quota, so serving still works.
function quota() { return APP.quota != null ? APP.quota : 0; }
// CAP_FS_SIZE returns 0xffffffff for an absent key (fs.size → -1 over the bridge).
// fsSizeRaw preserves that sentinel — it is how existence is asked (storeHas), since
// there is no CAP_FS_HAS. fsSize maps the sentinel to 0 so sizing a bare block's missing
// .dsc adds nothing to the quota total, not ~4 GiB.
function fsSizeRaw(keyStr) { return rU32(host.call(CAP_FS_SIZE, strBytes(keyStr)), 0); }
function fsSize(keyStr) { const v = fsSizeRaw(keyStr); return v === 0xffffffff ? 0 : v; }
function ensureUsed() {
  if (bytesUsed >= 0) return;
  bytesUsed = 0;
  // The committed tier is the <hex>.blk ciphertext AND its <hex>.dsc descriptor
  // sidecar — the descriptor is real bytes a holder keeps per block, so charging only
  // .blk would over-admit by the whole descriptor tier (§14). Rebuilt from the fs, so
  // a restarted holder re-derives its budget from what is actually on the backend.
  for (const id of storeList()) { const hex = toHex(id); bytesUsed += fsSize(hex + STORE_BLK) + fsSize(hex + STORE_DSC); }
}
function quotaFree() { ensureUsed(); return Math.max(0, quota() - bytesUsed); }
function fsPut(keyStr, bytes) {
  const kb = strBytes(keyStr);
  const head = new Uint8Array(4); wU32(head, 0, kb.length);
  host.call(CAP_FS_PUT, concat([head, kb, bytes]));
}
// The one write path into store.local: the <hex>.blk ciphertext + its sibling
// <hex>.dsc descriptor, under the quota budget. Throws past quota so admission
// refuses rather than over-commits.
function storeWrite(id, bytes, descriptor) {
  ensureUsed();
  const hex = toHex(id);
  // Charge the ciphertext AND the descriptor sidecar, crediting whatever was already
  // stored under this id, instead of writing the .dsc for free. Admission (admitBatch)
  // has already verified the descriptor, so every committed block has one: the .dsc
  // write is unconditional, with no described-block-overwritten-by-a-bare-one case to
  // unwind.
  const prevBlk = storeHas(id) ? fsSize(hex + STORE_BLK) : 0;
  const prevDsc = fsSize(hex + STORE_DSC);
  const next = bytesUsed - prevBlk - prevDsc + bytes.length + descriptor.length;
  if (next > quota()) throw new Error("store: quota exceeded");
  fsPut(hex + STORE_BLK, bytes);
  fsPut(hex + STORE_DSC, descriptor);
  bytesUsed = next;
}
// Admission (§4.3 descriptor check, §6 sibling rule, §14 quota): a holder verifies
// the chunk's signed descriptor and enforces no-two-blocks-of-a-chunk itself, so the
// §10 invariant survives a careless or malicious placer (a repairer included), not
// just an honest coordinator. A single block is just the one-element case of
// admitBatch — same verify, sibling, and quota checks (the batch's provisional set is
// empty for one block), so there is one implementation.
//
// `size` is the length of the block ACTUALLY in hand, which only STORE has; an OFFER
// carries no size on the wire (the geometry is the descriptor's) and passes null.
function admit(descriptor, blockId, size) {
  return admitBatch([{ blockId, descriptor, size }])[0];
}
// Batched admission: one OFFER's worth of blocks checked cumulatively — the §14 quota
// budget shrinks as blocks are provisionally accepted, and a block whose sibling (§6)
// is already held OR provisionally accepted in this same batch is declined, so two
// blocks of one chunk never both pass. STORE re-checks each block (acceptStore/admit),
// so this is the advisory pre-check, never the enforcement.
//
// The signed descriptor is REQUIRED on every path (§4.3: "every peer that accepts a
// block first verifies its descriptor"). There is deliberately no descriptor-less
// branch: one would be an admission gated by quota alone, letting any cohort peer push
// arbitrary bytes past the sibling rule — the wire decoders reject a descriptor-less
// entry outright, and a forged, malformed, or not-of-this-chunk one is declined here.
function admitBatch(offers) {
  let free = quotaFree();
  const provisional = new Set();
  return offers.map((o) => {
    const d = verifyDescriptor(o.descriptor);
    if (!d) return VERDICT_DESCRIPTOR;                       // absent, forged, unsigned, or malformed
    if (!descriptorContains(d, o.blockId)) return VERDICT_DESCRIPTOR; // not a block of this chunk
    // Geometry is the SIGNED descriptor's, never a field the sender picks: every block
    // is exactly blockSize bytes, so bytes in hand that disagree are not the block that
    // was offered, whatever they hash to.
    if (o.size != null && o.size !== d.blockSize) return VERDICT_DESCRIPTOR;
    // Charge what storeWrite will actually commit — the ciphertext AND its .dsc
    // sidecar — so this pre-check answers the same question the binding write does
    // instead of over-admitting by the descriptor's own size.
    const cost = d.blockSize + o.descriptor.length;
    if (cost > free) return VERDICT_QUOTA;
    for (const sib of d.blockIds) {
      if (bytesEqual(sib, o.blockId)) continue;
      if (storeHas(sib) || provisional.has(toHex(sib))) return VERDICT_SIBLING;
    }
    free -= cost;
    provisional.add(toHex(o.blockId));
    return VERDICT_ACCEPTED;
  });
}
function acceptStore(blockId, descriptor, bytes) {
  // The bytes must hash to the claimed id (§4.2) — every holder, every hop.
  if (!bytesEqual(hash(bytes), blockId)) return VERDICT_DECLINED;
  const v = admit(descriptor, blockId, bytes.length);
  if (v !== VERDICT_ACCEPTED) return v;
  try { storeWrite(blockId, bytes, descriptor); return VERDICT_ACCEPTED; } catch (_e) { return VERDICT_QUOTA; }
}
// Serve a batched FETCH, but never emit much more than one message's worth of bytes:
// an honest requester caps itself at fetchMaxIds() so its whole response fits, but a
// hostile cohort member can name the same id thousands of times in one ~1 MB request
// and make this sync holder concat thousands × blockSize into one reply. Cap the served
// bytes at maxMsgBytes (accounting for the response framing). A block the holder has but
// that won't fit under the cap is tagged FETCH_UNANSWERED, so the reader re-requests
// exactly those (runFetchTasks); a block it doesn't have is ABSENT. The FIRST present
// block is served even when it alone exceeds the cap — the same single-over-cap-item rule
// as batchBytes — so every request a holder can serve at all makes progress: a requester
// whose config assumes a bigger cap than ours (the caps are per-node operator policy, so
// they can diverge) degrades to one block per round trip instead of an absent-forever
// block it verifiably holds. The DoS bound stays: one block + cap per request. A per-id
// memo keeps a repeated id from costing a fresh storeGet.
function serveFetch(ids) {
  const cap = maxMsgBytes();
  const out = new Array(ids.length).fill(null);
  const seen = new Map(); // idHex → bytes|null, so a repeated id is one storeGet
  let used = 4;           // the [count u32] response header
  let servedAny = false;
  for (let i = 0; i < ids.length; i++) {
    const h = toHex(ids[i]);
    let bytes = seen.get(h);
    if (bytes === undefined) { const sb = storeGet(ids[i]); bytes = sb ? sb.bytes : null; seen.set(h, bytes); }
    if (!bytes) continue; // genuine miss — leave it ABSENT (null)
    const framed = bytes.length + FETCH_FRAME;
    if (servedAny && used + framed > cap) { out[i] = FETCH_UNANSWERED; continue; } // held but over the byte cap → mark for re-ask
    out[i] = bytes;
    used += framed;
    servedAny = true;
  }
  return out;
}
// The wire codecs a holder decodes/encodes (decodeHaveReq, decodeOfferBatch,
// decodeStoreBatch, decodeFetchBatchReq, encodeFetchBatchRes, and the shared
// encodeMask the HAVE/OFFER/STORE responses share) all come from the SHARED
// host/protocol.ts stitched in ahead of this body — the holder admits over the SAME
// §18 format the initiator speaks, by construction, not by a hand-kept mirror.

// Dispatch one incoming control message: arg = [type u8][payload]. Synchronous —
// every branch is local fs + crypto; the initiator owns the round trips. OFFER and
// FETCH carry a batch of blocks (one per peer per PUT/GET) and answer all at once.
function doHandle(arg) {
  const type = arg[0], payload = arg.slice(1);
  if (type === MSG_HAVE) return encodeMask(decodeHaveReq(payload).map((id) => storeHas(id)));
  if (type === MSG_OFFER) return encodeMask(admitBatch(decodeOfferBatch(payload)));
  if (type === MSG_STORE) return encodeMask(decodeStoreBatch(payload).map((s) => acceptStore(s.blockId, s.descriptor, s.bytes)));
  if (type === MSG_FETCH) return encodeFetchBatchRes(serveFetch(decodeFetchBatchReq(payload)));
  return EMPTY;
}

// ── warm (boot-time JIT warmup) ──────────────────────────────────────────────
// One throwaway RS encode + decode + verify under a random key, with NO network
// and NO store, run once at boot. It pays V8's cold-JIT tax on the codec (RS) and
// crypto (XChaCha20 / BLAKE2b / Ed25519) caps up front, off the latency-sensitive
// path: the first real PUT encodes the WHOLE file before the first byte reaches
// the wire, so on a cold realm that tax (~0.25 s for a 10 MB PUT) lands entirely
// in front of the transfer. Self-contained and idempotent; the result is discarded.
function doWarm() {
  const c = APP;
  const K = randomKey();
  const perRound = Math.max(1, c.k) * c.blockSize;
  const buf = new Uint8Array(perRound);
  // The cold-JIT tax is per-byte (un-optimized codec/crypto), not per-call, so one
  // chunk only reaches V8's baseline tier — measured first-PUT encode stays ~2× the
  // warm floor. Push ~4 MB through (the same volume a real PUT's first chunks take to
  // tier up), capped at 64 rounds so a tiny test-scale blockSize can't spin forever.
  const rounds = Math.min(64, Math.max(1, Math.ceil((4 * 1024 * 1024) / perRound)));
  for (let r = 0; r < rounds; r++) {
    const chunk = encodeChunk(buf, 0, 0, K);                                    // encrypt + RS-encode + hash + sign
    const d = verifyDescriptor(chunk.descriptor);                                // Ed25519 verify (+ §16 scope preimage)
    // Reconstruct from the k data blocks to warm the GET-side decode seam too — for a
    // CODED chunk only, on the same descriptor-kind test the real path uses: a replicated
    // deployment (k = 1) never reaches the codec on PUT, GET, or repair, so there is no
    // cold-JIT tax there to pay down.
    if (d && !isReplicated(d)) {
      rsDecode(c.k, c.m, c.blockSize, chunk.slotBlocks.slice(0, c.k).map((bytes, index) => ({ index, bytes })));
    }
  }
  return EMPTY;
}

register("put", doPut);
register("putStart", doPutStart);
register("putWindow", doPutWindow);
register("putFinish", doPutFinish);
register("get", doGet);
register("getStart", doGetStart);
register("getNext", doGetNext);
register("repair", doRepair);
register("handle", doHandle);
register("warm", doWarm);

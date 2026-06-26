// The Tier-2 guest — the storage orchestration (README §6/§7/§9) as zero-authority
// JS that runs *inside* the QuickJS realm (BUN.md §2.1). This is the real port the
// spike pointed at: the bodies of `cohort` / `coordinator` / `repair` rewritten so
// every `node.*` capability is reached only through the single `host.call(op,
// bytes)` seam, and de-async'd to straight-line synchronous code over the blocking
// Asyncify bridge (the load-bearing finding — a host call from a deferred promise
// job aborts the VM, so there is no async/await in here at all). Logic-for-logic
// this mirrors host/cohort.ts, host/coordinator.ts, and host/repair.ts; only the
// seam differs.
//
// Two roles share this one program. The *initiator* entrypoints (`put`/`get`/
// `repair`) are async — they fan out over net and run in the Asyncify realm. The
// *holder* entrypoint (`handle`: HAVE/OFFER/STORE/FETCH, admission, content-
// addressing, quota, fs writes — mirroring host/storage-node.ts + host/store-fs.ts)
// is purely synchronous (local fs + crypto, no net) and runs in a SYNC realm, so a
// node can answer requests while its own initiator realm is parked mid-await
// (the runtime split). Whichever entrypoint a realm calls, the other
// role's code is simply dormant there.
//
// This is a plain script, not a module: it has no imports/exports and no ambient
// authority. It is loaded as source by a driver (host/tier2-coordinator.ts, or
// the seedkernel shell) which prepends two constant blocks — the generic
// `const CAP_* = n;` op catalog (seedkernel's host/cap-bridge.ts) and an `APP`
// object carrying the storage config + the codec/reputation kernel names — and
// runs it after the safe-js PREAMBLE that defines `host.call` and `register`.
// Every capability the guest reaches is an application-neutral primitive; all
// storage *structure* is right here. The same file is hosted by JSC on Bun today
// and by WAMR in the native node later — one artifact, both runtimes.

"use strict";

// ── byte helpers (mirror host/util.ts) ──────────────────────────────────────
const HEX_CHARS = "0123456789abcdef";
function toHex(b) {
  const chars = new Array(b.length * 2);
  for (let i = 0; i < b.length; i++) {
    const h = b[i];
    chars[i * 2] = HEX_CHARS[(h >> 4) & 0xf];
    chars[i * 2 + 1] = HEX_CHARS[h & 0xf];
  }
  return chars.join("");
}
function fromHex(h) {
  const out = new Uint8Array(h.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function concat(parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
function wU32(out, off, v) {
  out[off] = (v >>> 24) & 255; out[off + 1] = (v >>> 16) & 255;
  out[off + 2] = (v >>> 8) & 255; out[off + 3] = v & 255;
}
function rU32(b, off) {
  return ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0;
}
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

const DOMAIN_MANIFEST = 0, DOMAIN_BODY = 1, ENC_XCHACHA20 = 1;
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
const CODEC_ENCODE = 1, CODEC_DECODE = 2;     // host/codec-client.ts
const REP_OBSERVE = 1, REP_SCORE = 2;         // host/reputation-client.ts
// Control-plane message types carried over net.send (host/protocol.ts §18).
const MSG_HAVE = 1, MSG_OFFER = 2, MSG_FETCH = 3, MSG_STORE = 4;
const STORE_BLK = ".blk", STORE_DSC = ".dsc";
const CODEC_NAME = fromHex(APP.codecName);
const REP_NAME = fromHex(APP.repName);

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
// Signed chunk descriptor envelope: [authorPk 32][sig 64][core] (§4.3, §16).
function signCore(core) { return concat([identity(), host.call(CAP_SIGN, core), core]); }
function verifyEnv(env) {
  return host.call(CAP_VERIFY, concat([env.slice(0, 32), env.slice(32, 96), env.slice(96)]))[0] === 1;
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
// two passes over the blocks. One concat copies them once (the host fast path got
// the same single-copy treatment in codec-client.ts; the guest reaches the codec
// only through host.call so the in-place scratch staging isn't available here, but
// folding the two concats is).
function moduleCallParts(name, parts) {
  const head = new Uint8Array(1 + name.length); head[0] = name.length; head.set(name, 1);
  return host.call(CAP_MODULE_CALL, concat([head, ...parts]));
}
function rsEncode(k, m, blockSize, dataBlocks) {
  const head = new Uint8Array(7);
  head[0] = CODEC_ENCODE; head[1] = k; head[2] = m; wU32(head, 3, blockSize);
  return splitBlocks(moduleCallParts(CODEC_NAME, [head, ...dataBlocks]), blockSize);
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
function storeHas(id) { return host.call(CAP_FS_HAS, strBytes(toHex(id) + STORE_BLK))[0] === 1; }
function storeGet(id) {
  const hex = toHex(id);
  const blk = host.call(CAP_FS_GET, strBytes(hex + STORE_BLK));
  if (blk[0] !== 1) return null;
  const dsc = host.call(CAP_FS_GET, strBytes(hex + STORE_DSC));
  return { bytes: blk.slice(1), descriptor: dsc[0] === 1 ? dsc.slice(1) : null };
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
function rank(peers) {
  if (peers.length === 0) return [];
  const t = clockNow();
  return peers.map((p) => ({ p, s: repScore(fromHex(p), t) })).sort((a, b) => b.s - a.s).map((x) => x.p);
}
function markSeen(_peer) { /* liveness hint — no generic cap; reputation observe scores peers (§8) */ }

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
// disc.have/want (§5.2): one round trip to the cohort; the host fans out in
// parallel (net.requestMany) so the guest never needs a Promise.all. A node is
// itself a holder of whatever its own store keeps (repair runs on holders).
function haveWant(ids) {
  const holders = new Map();
  for (const id of ids) holders.set(toHex(id), new Set());
  for (const id of ids) if (storeHas(id)) holders.get(toHex(id)).add(myPeer());
  const head = new Uint8Array(4); wU32(head, 0, ids.length);
  const req = concat([head, ...ids]);
  for (const res of netRequestMany(cohortPeers(), MSG_HAVE, req)) {
    if (!res.ok) continue;
    markSeen(res.peer);
    const held = res.bytes;
    for (let i = 0; i < ids.length && i < held.length; i++) {
      if (held[i] === 1) holders.get(toHex(ids[i])).add(res.peer);
    }
  }
  return holders;
}
// Batched FETCH wire: [count u32][id*32] → [count u32][ found u8 (| len u32 | bytes) ].
function encodeFetchBatchReq(ids) {
  const head = new Uint8Array(4); wU32(head, 0, ids.length);
  return concat([head, ...ids]);
}
function decodeFetchBatchRes(buf) {
  if (buf.length < 4) throw new Error("protocol: decodeFetchBatchRes truncated header");
  const count = rU32(buf, 0), out = []; let o = 4;
  for (let i = 0; i < count; i++) {
    if (o >= buf.length) throw new Error("protocol: decodeFetchBatchRes truncated found");
    const found = buf[o]; o += 1;
    if (found !== 1) { out.push(null); continue; }
    if (o + 4 > buf.length) throw new Error("protocol: decodeFetchBatchRes truncated len");
    const len = rU32(buf, o); o += 4;
    if (o + len > buf.length) throw new Error("protocol: decodeFetchBatchRes truncated block");
    out.push(buf.slice(o, o + len)); o += len;
  }
  return out;
}
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
// Batched OFFER wire: [count u32][ blockId 32 | size u32 | descLen u32 | desc ]+ →
// one accept byte per entry. Returns the accept mask aligned to `offers`.
function offerBatch(peer, offers) {
  let total = 4;
  for (const o of offers) total += 40 + (o.descriptor ? o.descriptor.length : 0);
  const req = new Uint8Array(total); wU32(req, 0, offers.length);
  let p = 4;
  for (const o of offers) {
    req.set(o.blockId, p); wU32(req, p + 32, o.size);
    const desc = o.descriptor || EMPTY; wU32(req, p + 36, desc.length);
    req.set(desc, p + 40); p += 40 + desc.length;
  }
  const resp = netSend(peer, MSG_OFFER, req);
  if (resp === null) return offers.map(() => false);
  return offers.map((_, i) => resp[i] === 1);
}
function offer(peer, blockId, size, descriptor) {
  return offerBatch(peer, [{ blockId, size, descriptor }])[0];
}
// Batched STORE wire: [count u32][ blockId 32 | descLen u32 | bytesLen u32 | desc |
// bytes ]+ → one stored/failed byte per entry. The upload twin of the batched FETCH.
function storeBatch(peer, stores) {
  let total = 4;
  for (const s of stores) total += 40 + (s.descriptor ? s.descriptor.length : 0) + s.bytes.length;
  const req = new Uint8Array(total); wU32(req, 0, stores.length);
  let p = 4;
  for (const s of stores) {
    req.set(s.blockId, p);
    const desc = s.descriptor || EMPTY;
    wU32(req, p + 32, desc.length); wU32(req, p + 36, s.bytes.length);
    req.set(desc, p + 40); req.set(s.bytes, p + 40 + desc.length);
    p += 40 + desc.length + s.bytes.length;
  }
  const resp = netSend(peer, MSG_STORE, req);
  if (resp === null) return stores.map(() => false);
  return stores.map((_, i) => resp[i] === 1);
}
function storePush(peer, blockId, descriptor, bytes) {
  return storeBatch(peer, [{ blockId, descriptor, bytes }])[0];
}

// ── manifest + descriptor (pure; mirror host/manifest.ts) ────────────────────
function encodeDescriptorCore(d) {
  const head = new Uint8Array(8);
  head[0] = 1; head[1] = d.k; head[2] = d.m; wU32(head, 3, d.blockSize); head[7] = d.blockIds.length;
  return concat([head, ...d.blockIds]);
}
function decodeDescriptorCore(core) {
  // Same structural guards host/manifest.ts enforces — a holder must reject a
  // junk core exactly as the host holder does (§4.3).
  if (core.length < 8 || core[0] !== 1) throw new Error("descriptor: bad core");
  const k = core[1], m = core[2], blockSize = rU32(core, 3), n = core[7], blockIds = [];
  if (k < 1) throw new Error("descriptor: k must be >= 1");
  if (blockSize < 1) throw new Error("descriptor: blockSize must be >= 1");
  if (n !== k + m) throw new Error("descriptor: n != k+m");
  if (core.length !== 8 + n * 32) throw new Error("descriptor: truncated");
  for (let i = 0; i < n; i++) blockIds.push(core.slice(8 + i * 32, 8 + (i + 1) * 32));
  return { k, m, blockSize, blockIds };
}
function parseSignedDescriptor(env) {
  if (env.length < 32 + 64 + 8) throw new Error("signed descriptor: too short");
  const core = env.slice(96); // [authorPk 32][sig 64][core]
  return { core, descriptor: decodeDescriptorCore(core) };
}
// Verify the author signature AND structurally validate the core, mirroring
// host/manifest.ts verifyDescriptor: returns the parsed descriptor or null. The
// holder admits over this so a *signed* but malformed descriptor (junk core, n ≠
// k+m) is rejected, not parsed into garbage block-ids that sidestep the §10
// sibling invariant — the parity the host holder already had.
function verifyDescriptor(env) {
  if (!verifyEnv(env)) return null;
  try { return parseSignedDescriptor(env).descriptor; } catch (_e) { return null; }
}
function signChunk(d) { return signCore(encodeDescriptorCore(d)); }
function encodeManifest(man) {
  const head = new Uint8Array(20);
  let o = 0;
  head[o++] = 1;
  wU32(head, o, Math.floor(man.fileSize / 0x100000000)); o += 4;
  wU32(head, o, man.fileSize >>> 0); o += 4;
  wU32(head, o, man.blockSize); o += 4;
  head[o++] = man.k; head[o++] = man.m; head[o++] = man.encAlg;
  wU32(head, o, man.chunks.length); o += 4;
  const parts = [head];
  for (const env of man.chunks) {
    const len = new Uint8Array(4); wU32(len, 0, env.length);
    parts.push(len, env);
  }
  return concat(parts);
}
function decodeManifest(buf) {
  // Same bounds checks host/manifest.ts makes (version byte + every length read).
  // A wrong-K GET decrypts the manifest to noise: without these the random
  // chunkCount drives the realm into billions of slice() calls until QuickJS's
  // memory cap aborts it; with them it is a clean throw (crypto-shredding, §11).
  if (buf.length < 19 || buf[0] !== 1) throw new Error("manifest: bad header");
  let o = 1;
  const hi = rU32(buf, o); o += 4;
  const lo = rU32(buf, o); o += 4;
  const fileSize = hi * 0x100000000 + lo;
  const blockSize = rU32(buf, o); o += 4;
  const k = buf[o++], m = buf[o++], encAlg = buf[o++];
  const chunkCount = rU32(buf, o); o += 4;
  if (fileSize > 0x10000000000) throw new Error("manifest: fileSize out of bounds");
  if (blockSize < 1) throw new Error("manifest: blockSize must be >= 1");
  if (k < 1) throw new Error("manifest: k must be >= 1");
  if (chunkCount === 0) throw new Error("manifest: chunkCount must be >= 1");
  const chunks = [];
  for (let i = 0; i < chunkCount; i++) {
    if (o + 4 > buf.length) throw new Error("manifest: truncated chunk length");
    const len = rU32(buf, o); o += 4;
    if (o + len > buf.length) throw new Error("manifest: truncated chunk");
    chunks.push(buf.slice(o, o + len)); o += len;
  }
  return { fileSize, blockSize, k, m, encAlg, chunks };
}

// ── placement + fetch (coordinator §6/§7) ────────────────────────────────────
// Appended to a placement-failure throw: on a fresh PUT a holder only declines on
// the §14 quota, so "nothing landed" almost always means the holders are full (GET
// still works — serving a FETCH never checks quota). Mirror of Coordinator.declineHint.
const OUT_OF_STORAGE_HINT = " — holders answered but declined: most likely OUT OF STORAGE (quota/disk full); clear the holders' data dirs or raise their quota, or connect more holders";
// A batched OFFER / STORE / FETCH is split to stay under config().maxMessageBytes —
// the per-transport cap that keeps one message inside the frame cap AND the request
// timeout (mirror coordinator.ts). Transport/operator policy injected via the APP
// preamble (like quota); default if absent.
function maxMsgBytes() { const v = config().maxMessageBytes; return (typeof v === "number" && v > 0) ? v : (1 << 20); }
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
    if (storePush(peer, blockId, descriptor, bytes)) { placed.push(peer); markSeen(peer); }
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
  return { blockIds, blocks, descriptor, placedPeer: new Array(blocks.length).fill(null) };
}
// Place every chunk's n blocks with one batched OFFER per peer per round, then the
// accepted blocks STORE'd. Block index i targets ranked[i], ranked[i+n], … (a
// disjoint residue class per i, so a chunk's n blocks land on distinct peers,
// §6/§10). Synchronous: serial over the (small) peer set, but per-peer the OFFER
// is one round trip for block i of every chunk at once. Returns nothing; fills
// each chunk's placedPeer[]. Throws if a chunk lands < k distinct ids.
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

    for (const [peer, items] of byPeer) {
      for (const slice of sliceN(items, maxOffers)) {
        const offers = slice.map(({ ch, i }) => ({ blockId: ch.blockIds[i], size: ch.blocks[i].length, descriptor: ch.descriptor }));
        const mask = offerBatch(peer, offers);
        const accepted = slice.filter((_, j) => mask[j]);
        // STORE the accepted blocks in byte-bounded batches (one streamed message
        // each — the upload twin of the batched FETCH).
        for (const group of batchBytes(accepted, ({ ch, i }) => 40 + ch.descriptor.length + ch.blocks[i].length, maxBytes)) {
          const stored = storeBatch(peer, group.map(({ ch, i }) => ({ blockId: ch.blockIds[i], descriptor: ch.descriptor, bytes: ch.blocks[i] })));
          for (let j = 0; j < group.length; j++) if (stored[j]) { group[j].ch.placedPeer[group[j].i] = peer; markSeen(peer); }
        }
      }
    }
  }

  for (const ch of chunks) {
    const distinct = new Set();
    for (let i = 0; i < ch.blockIds.length; i++) if (ch.placedPeer[i]) distinct.add(toHex(ch.blockIds[i]));
    if (distinct.size < c.k) throw new Error("put: chunk landed " + distinct.size + "/" + c.k + " distinct blocks" + OUT_OF_STORAGE_HINT);
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
// Fetch every block the file's chunks need, batched per holder (mirror
// coordinator.ts gatherBlocks). After the file-wide have/want, each still-missing
// block is requested from its best untried holder, one FETCH per peer per round
// (sub-batched under the frame cap); a coded chunk stops at k, preferring data
// blocks. Every returned block is hash-verified (§4.2) and scores its holder (§8).
// Returns a Map id-hex → bytes. Synchronous, serial over peers.
function gatherBlocks(descriptors, holders) {
  const c = config();
  const got = new Map();
  const tried = new Map();
  const triedOf = (h) => { let s = tried.get(h); if (!s) tried.set(h, (s = new Set())); return s; };
  const maxIds = Math.max(1, Math.floor(maxMsgBytes() / c.blockSize));

  const stillNeeds = (d) => {
    const distinct = new Set();
    for (const id of d.blockIds) if (got.has(toHex(id))) distinct.add(toHex(id));
    const need = d.m === 0 ? d.blockIds.length : d.k;
    return Math.max(0, need - distinct.size);
  };

  for (;;) {
    const byPeer = new Map(); // peer → [idHex]
    const queued = new Set();
    for (const d of descriptors) {
      let need = stillNeeds(d);
      if (need === 0) continue;
      for (const id of d.blockIds) {
        if (need === 0) break;
        const h = toHex(id);
        if (got.has(h) || queued.has(h)) continue;
        const cands = rank([...(holders.get(h) || new Set())].filter((p) => !triedOf(h).has(p)));
        if (cands.length === 0) continue;
        let list = byPeer.get(cands[0]); if (!list) byPeer.set(cands[0], (list = []));
        list.push(h);
        queued.add(h);
        need--;
      }
    }
    if (byPeer.size === 0) break;

    for (const [peer, hexes] of byPeer) {
      const isSelf = peer === myPeer();
      for (const slice of sliceN(hexes, maxIds)) {
        const ids = slice.map(fromHex);
        const blocks = fetchBatch(peer, ids);
        const t = clockNow();
        for (let i = 0; i < slice.length; i++) {
          triedOf(slice[i]).add(peer);
          if (blocks === null) continue;            // unreachable — not a §8 miss
          const b = blocks[i];
          if (b && bytesEqual(hash(b), ids[i])) {
            if (!got.has(slice[i])) got.set(slice[i], b);
            if (!isSelf) { markSeen(peer); repObserve(fromHex(peer), t, true); }
          } else if (!isSelf) {
            repObserve(fromHex(peer), t, false);
          }
        }
      }
    }
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
    for (const ch of chunks) descriptors.push(ch.descriptor);
  }

  // Build, encrypt, and replicate the manifest (§4.3).
  const manPlain = encodeManifest({
    fileSize, blockSize: c.blockSize, k: c.k, m: c.m, encAlg: ENC_XCHACHA20, chunks: descriptors,
  });
  const manCt = encrypt(K, DOMAIN_MANIFEST, 0, manPlain);
  const manifestId = hash(manCt);
  // Signed descriptor for the manifest block so repair can self-heal it (§9).
  // Carries as a one-block replicated chunk (k = 1, m = 0) with the manifest's
  // block_id, matching the host-side Coordinator.put (coordinator.ts §123).
  const manEnv = signChunk({ k: 1, m: 0, blockSize: manCt.length, blockIds: [manifestId] });
  if (placeBlock(manifestId, manCt, manEnv, new Set(), c.replicas).length === 0) {
    throw new Error("put: no peer accepted the manifest" + OUT_OF_STORAGE_HINT);
  }

  // result: [manifestId 32][replicated u8][chunkCount u32][K 32]
  const out = new Uint8Array(69);
  out.set(manifestId, 0);
  out[32] = replicated ? 1 : 0;
  wU32(out, 33, descriptors.length);
  out.set(K, 37);
  return out;
}

// ── GET (§7) ─────────────────────────────────────────────────────────────────
function doGet(arg) {
  const manifestId = arg.slice(0, 32), K = arg.slice(32, 64);
  const manCt = fetchBlock(manifestId);
  if (!manCt) throw new Error("get: manifest not found in cohort");
  const man = decodeManifest(decrypt(K, DOMAIN_MANIFEST, 0, manCt));

  // Verify every chunk descriptor's signature before using it (§4.3), mirroring
  // the host-side Coordinator.get: the manifest is encrypted, not signed, so a
  // correct K with a tampered manifest is caught only by the per-chunk signature.
  // One file-wide have/want, then one batched FETCH per holder (gatherBlocks),
  // instead of a discovery + fetch per chunk.
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
// For each block_id, the live holders — advertised via have/want, then confirmed
// retrievable by a verification-fetch (§8).
function liveHolders(ids) {
  const advertised = haveWant(ids);
  const verified = new Map();
  for (const id of ids) {
    const key = toHex(id);
    const live = new Set();
    for (const peer of advertised.get(key) || new Set()) {
      if (verificationFetch(peer, id)) live.add(peer);
    }
    verified.set(key, live);
  }
  return verified;
}
// Replicated chunk (§4.1): repair is a single block copy from any live holder.
function healReplicated(d, descEnv, holders) {
  const c = config();
  let replaced = 0;
  for (const id of d.blockIds) {
    const set = holders.get(toHex(id)) || new Set();
    if (set.size >= c.replicas) continue;
    const bytes = fetchBlock(id);
    if (!bytes) continue;
    replaced += placeBlock(id, bytes, descEnv, set, c.replicas - set.size).length;
  }
  return replaced;
}
// Coded chunk (§9): fetch any k retrievable blocks, reconstruct, re-encode the
// missing blocks, re-certify each against its signed block_id, place on fresh peers.
function healCoded(d, descEnv, holders) {
  const present = [];
  for (let idx = 0; idx < d.blockIds.length && present.length < d.k; idx++) {
    const set = holders.get(toHex(d.blockIds[idx]));
    if (!set || set.size === 0) continue;
    // Try each live holder until one serves the block, rather than picking the
    // first and silently skipping if it's stale or unreachable.
    const ranked = rank([...set]);
    let b = null;
    for (const peer of ranked) {
      b = verificationFetch(peer, d.blockIds[idx]);
      if (b) break;
    }
    if (b) present.push({ index: idx, bytes: b });
  }
  if (present.length < d.k) return 0; // cannot heal — fewer than k retrievable

  const data = rsDecode(d.k, d.m, d.blockSize, present);
  const all = [...data, ...rsEncode(d.k, d.m, d.blockSize, data)];

  const occupied = new Set();
  for (const set of holders.values()) for (const p of set) occupied.add(p);

  let replaced = 0;
  for (let i = 0; i < all.length; i++) {
    const id = d.blockIds[i];
    const held = holders.get(toHex(id));
    if (held && held.size > 0) continue;                 // already live
    if (!bytesEqual(hash(all[i]), id)) continue;          // re-certify (§9)
    const placed = placeBlock(id, all[i], descEnv, occupied, 1);
    for (const p of placed) occupied.add(p);
    replaced += placed.length;
  }
  return replaced;
}
// Audit and, if under-replicated, heal one chunk from its signed descriptor.
function repairChunk(descEnv) {
  const d = verifyDescriptor(descEnv);                     // forged/unsigned/malformed → null (§4.3)
  if (!d) return 0;
  const holders = liveHolders(d.blockIds);
  let liveCount = 0;
  for (const set of holders.values()) if (set.size > 0) liveCount++;
  if (liveCount >= config().lowWater) return 0;            // healthy (§8, §9)
  return d.m === 0 ? healReplicated(d, descEnv, holders) : healCoded(d, descEnv, holders);
}
// Run the repair loop over every chunk this node holds a block of (§9).
function doRepair() {
  const seen = new Set();
  let replaced = 0;
  for (const id of storeList()) {
    const sb = storeGet(id);
    if (!sb || !sb.descriptor) continue;
    const key = toHex(hash(sb.descriptor));
    if (seen.has(key)) continue;
    seen.add(key);
    replaced += repairChunk(sb.descriptor);
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
// signed bundle.
const DEFAULT_QUOTA = 64 * 1024 * 1024;
function quota() { return APP.quota != null ? APP.quota : DEFAULT_QUOTA; }
function fsSize(keyStr) { return rU32(host.call(CAP_FS_SIZE, strBytes(keyStr)), 0); }
function ensureUsed() {
  if (bytesUsed >= 0) return;
  bytesUsed = 0;
  for (const id of storeList()) bytesUsed += fsSize(toHex(id) + STORE_BLK);
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
  const prev = storeHas(id) ? fsSize(hex + STORE_BLK) : 0;
  const next = bytesUsed - prev + bytes.length;
  if (next > quota()) throw new Error("store: quota exceeded");
  fsPut(hex + STORE_BLK, bytes);
  if (descriptor && descriptor.length) fsPut(hex + STORE_DSC, descriptor);
  else if (prev) host.call(CAP_FS_DELETE, strBytes(hex + STORE_DSC));
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
// Wire decoders for the requests a holder receives (mirror host/protocol.ts).
function decodeHaveIds(buf) {
  if (buf.length < 4) throw new Error("protocol: decodeHaveIds truncated header");
  const n = rU32(buf, 0), out = [];
  const need = 4 + n * 32;
  if (buf.length < need) throw new Error("protocol: decodeHaveIds truncated");
  for (let i = 0; i < n; i++) out.push(buf.slice(4 + i * 32, 4 + (i + 1) * 32));
  return out;
}
function encodeHaveRes(held) {
  const out = new Uint8Array(held.length);
  for (let i = 0; i < held.length; i++) out[i] = held[i] ? 1 : 0;
  return out;
}
function decodeOfferBatch(buf) {
  if (buf.length < 4) throw new Error("protocol: decodeOfferBatch truncated header");
  const count = rU32(buf, 0), out = [];
  let o = 4;
  for (let i = 0; i < count; i++) {
    if (o + 40 > buf.length) throw new Error("protocol: decodeOfferBatch truncated entry");
    const blockId = buf.slice(o, o + 32), size = rU32(buf, o + 32), dlen = rU32(buf, o + 36);
    if (o + 40 + dlen > buf.length) throw new Error("protocol: decodeOfferBatch truncated descriptor");
    out.push({ blockId, size, descriptor: dlen > 0 ? buf.slice(o + 40, o + 40 + dlen) : null });
    o += 40 + dlen;
  }
  return out;
}
function encodeOfferMask(accepts) {
  const out = new Uint8Array(accepts.length);
  for (let i = 0; i < accepts.length; i++) out[i] = accepts[i] ? 1 : 0;
  return out;
}
function decodeStoreBatch(buf) {
  if (buf.length < 4) throw new Error("protocol: decodeStoreBatch truncated header");
  const count = rU32(buf, 0), out = [];
  let o = 4;
  for (let i = 0; i < count; i++) {
    if (o + 40 > buf.length) throw new Error("protocol: decodeStoreBatch truncated entry");
    const blockId = buf.slice(o, o + 32), dlen = rU32(buf, o + 32), blen = rU32(buf, o + 36);
    if (o + 40 + dlen + blen > buf.length) throw new Error("protocol: decodeStoreBatch truncated data");
    out.push({
      blockId,
      descriptor: dlen > 0 ? buf.slice(o + 40, o + 40 + dlen) : null,
      bytes: buf.slice(o + 40 + dlen, o + 40 + dlen + blen),
    });
    o += 40 + dlen + blen;
  }
  return out;
}
function encodeStoreMask(stored) {
  const out = new Uint8Array(stored.length);
  for (let i = 0; i < stored.length; i++) out[i] = stored[i] ? 1 : 0;
  return out;
}
function decodeFetchBatchReq(buf) {
  if (buf.length < 4) throw new Error("protocol: decodeFetchBatchReq truncated header");
  const count = rU32(buf, 0), out = [];
  const need = 4 + count * 32;
  if (buf.length < need) throw new Error("protocol: decodeFetchBatchReq truncated");
  for (let i = 0; i < count; i++) out.push(buf.slice(4 + i * 32, 4 + (i + 1) * 32));
  return out;
}
function encodeFetchBatchRes(blocks) {
  let total = 4;
  for (const b of blocks) total += b ? 5 + b.length : 1;
  const out = new Uint8Array(total);
  wU32(out, 0, blocks.length);
  let o = 4;
  for (const b of blocks) {
    if (!b) { out[o++] = 0; continue; }
    out[o++] = 1; wU32(out, o, b.length); o += 4; out.set(b, o); o += b.length;
  }
  return out;
}
// Dispatch one incoming control message: arg = [type u8][payload]. Synchronous —
// every branch is local fs + crypto; the initiator owns the round trips. OFFER and
// FETCH carry a batch of blocks (one per peer per PUT/GET) and answer all at once.
function doHandle(arg) {
  const type = arg[0], payload = arg.slice(1);
  if (type === MSG_HAVE) return encodeHaveRes(decodeHaveIds(payload).map((id) => storeHas(id)));
  if (type === MSG_OFFER) return encodeOfferMask(admitBatch(decodeOfferBatch(payload)));
  if (type === MSG_STORE) return encodeStoreMask(decodeStoreBatch(payload).map((s) => acceptStore(s.blockId, s.descriptor, s.bytes)));
  if (type === MSG_FETCH) return encodeFetchBatchRes(decodeFetchBatchReq(payload).map((id) => { const sb = storeGet(id); return sb ? sb.bytes : null; }));
  return EMPTY;
}

register("put", doPut);
register("get", doGet);
register("repair", doRepair);
register("handle", doHandle);

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
function toHex(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
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
function rsEncode(k, m, blockSize, dataBlocks) {
  const head = new Uint8Array(7);
  head[0] = CODEC_ENCODE; head[1] = k; head[2] = m; wU32(head, 3, blockSize);
  return splitBlocks(moduleCall(CODEC_NAME, concat([head, ...dataBlocks])), blockSize);
}
function rsDecode(k, m, blockSize, present) {
  const use = present.slice(0, k);
  const head = new Uint8Array(8);
  head[0] = CODEC_DECODE; head[1] = k; head[2] = m; wU32(head, 3, blockSize); head[7] = use.length;
  const idx = new Uint8Array(use.length);
  for (let i = 0; i < use.length; i++) idx[i] = use[i].index;
  return splitBlocks(moduleCall(CODEC_NAME, concat([head, idx, ...use.map((p) => p.bytes)])), blockSize);
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
// verification-fetch (§8): pull a block from a holder, confirm it hashes to its
// id, and score the holder. The hash check + reputation are the guest's, not the
// host's. Self-fetch reads the local store directly (no round trip).
function verificationFetch(peer, id) {
  if (peer === myPeer()) {
    const sb = storeGet(id);
    return sb && bytesEqual(hash(sb.bytes), id) ? sb.bytes : null;
  }
  const resp = netSend(peer, MSG_FETCH, id.slice());
  if (resp === null) return null;                       // unreachable — not a miss to score
  const data = resp.length >= 1 && resp[0] === 1 ? resp.slice(1) : null;
  const t = clockNow();
  if (data && bytesEqual(hash(data), id)) { repObserve(fromHex(peer), t, true); return data; }
  repObserve(fromHex(peer), t, false);
  return null;
}
function offer(peer, blockId, size, descriptor) {
  const head = new Uint8Array(40); head.set(blockId, 0); wU32(head, 32, size);
  const desc = descriptor || EMPTY; wU32(head, 36, desc.length);
  const resp = netSend(peer, MSG_OFFER, concat([head, desc]));
  return resp !== null && resp.length >= 1 && resp[0] === 1;
}
function storePush(peer, blockId, descriptor, bytes) {
  const head = new Uint8Array(36); head.set(blockId, 0);
  const desc = descriptor || EMPTY; wU32(head, 32, desc.length);
  const resp = netSend(peer, MSG_STORE, concat([head, desc, bytes]));
  return resp !== null && resp.length >= 1 && resp[0] === 1;
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
// Offer to candidates ranked by reciprocity (§13); on accept, push. Up to `count`
// distinct peers not in `exclude`. Returns the peers that stored it.
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
// Fetch a block from whichever cohort peer holds it, verifying by hash.
function fetchBlock(id) {
  const holders = haveWant([id]).get(toHex(id)) || new Set();
  for (const peer of rank([...holders])) {
    const b = verificationFetch(peer, id);
    if (b) return b;
  }
  return null;
}
// Replicated chunk (§4.1): fetch each data block from any live holder.
function fetchReplicatedChunk(d) {
  const blocks = [];
  for (const id of d.blockIds) {
    const b = fetchBlock(id);
    if (!b) throw new Error("get: a replica is unavailable");
    blocks.push(b);
  }
  return concat(blocks);
}
// Coded chunk (§7): locate via have/want, fetch any k of n, decode. With all k
// data blocks present, systematic RS lets us just concatenate them (§4.1).
function fetchCodedChunk(d) {
  const k = d.k;
  const holders = haveWant(d.blockIds);
  const present = [];
  for (let idx = 0; idx < d.blockIds.length && present.length < k; idx++) {
    const set = holders.get(toHex(d.blockIds[idx]));
    if (!set || set.size === 0) continue;
    const peer = rank([...set])[0];
    const b = verificationFetch(peer, d.blockIds[idx]);
    if (b) present.push({ index: idx, bytes: b });
  }
  if (present.length < k) throw new Error("get: fewer than k blocks retrievable — chunk unavailable");

  const allData = present.slice(0, k).every((p) => p.index < k);
  if (allData) {
    const ordered = present.filter((p) => p.index < k).sort((a, b) => a.index - b.index).slice(0, k);
    if (ordered.length === k && ordered.every((p, i) => p.index === i)) {
      return concat(ordered.map((p) => p.bytes)); // systematic — no decode
    }
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
        throw new Error("put: no peer accepted a replica");
      }
    }
    descriptors.push(env);
  } else {
    // RS path (§4.1): chunk into k data blocks, add m parity, place on distinct peers.
    const numChunks = Math.ceil(totalBlocks / c.k);
    for (let ci = 0; ci < numChunks; ci++) {
      const start = ci * c.k * c.blockSize;
      const chunkPlain = plaintext.slice(start, start + c.k * c.blockSize);
      const ct = encrypt(K, DOMAIN_BODY, ci, padTo(chunkPlain, c.k * c.blockSize));
      const dataBlocks = splitBlocks(ct, c.blockSize);
      const all = [...dataBlocks, ...rsEncode(c.k, c.m, c.blockSize, dataBlocks)];
      const blockIds = all.map(hash);
      const env = signChunk({ k: c.k, m: c.m, blockSize: c.blockSize, blockIds });
      const used = new Set();
      for (let i = 0; i < all.length; i++) {
        const placed = placeBlock(blockIds[i], all[i], env, used, 1);
        if (placed.length === 0) throw new Error("put: no peer accepted block " + i + " of chunk " + ci);
        for (const p of placed) used.add(p);
      }
      descriptors.push(env);
    }
  }

  // Build, encrypt, and replicate the manifest (§4.3).
  const manPlain = encodeManifest({
    fileSize, blockSize: c.blockSize, k: c.k, m: c.m, encAlg: ENC_XCHACHA20, chunks: descriptors,
  });
  const manCt = encrypt(K, DOMAIN_MANIFEST, 0, manPlain);
  const manifestId = hash(manCt);
  if (placeBlock(manifestId, manCt, null, new Set(), c.replicas).length === 0) {
    throw new Error("put: no peer accepted the manifest");
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

  const out = new Uint8Array(man.fileSize);
  let written = 0;
  for (let ci = 0; ci < man.chunks.length; ci++) {
    const d = parseSignedDescriptor(man.chunks[ci]).descriptor;
    const chunkCipher = d.m === 0 ? fetchReplicatedChunk(d) : fetchCodedChunk(d);
    const domainIndex = d.m === 0 ? 0 : ci;
    const chunkPlain = decrypt(K, DOMAIN_BODY, domainIndex, chunkCipher);
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
    const b = verificationFetch([...set][0], d.blockIds[idx]);
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
function acceptStore(blockId, descriptor, bytes) {
  // The bytes must hash to the claimed id (§4.2) — every holder, every hop.
  if (!bytesEqual(hash(bytes), blockId)) return false;
  if (!admit(descriptor, blockId, bytes.length)) return false;
  try { storeWrite(blockId, bytes, descriptor); return true; } catch (_e) { return false; }
}
// Wire decoders for the requests a holder receives (mirror host/protocol.ts).
function decodeHaveIds(buf) {
  const n = rU32(buf, 0), out = [];
  for (let i = 0; i < n; i++) out.push(buf.slice(4 + i * 32, 4 + (i + 1) * 32));
  return out;
}
function encodeHaveRes(held) {
  const out = new Uint8Array(held.length);
  for (let i = 0; i < held.length; i++) out[i] = held[i] ? 1 : 0;
  return out;
}
function decodeOfferReq(buf) {
  const dlen = rU32(buf, 36);
  return { blockId: buf.slice(0, 32), size: rU32(buf, 32), descriptor: dlen > 0 ? buf.slice(40, 40 + dlen) : null };
}
function decodeStoreReq(buf) {
  const dlen = rU32(buf, 32);
  return { blockId: buf.slice(0, 32), descriptor: dlen > 0 ? buf.slice(36, 36 + dlen) : null, bytes: buf.slice(36 + dlen) };
}
function encodeFetchRes(bytes) {
  if (!bytes) return new Uint8Array([0]);
  const out = new Uint8Array(1 + bytes.length); out[0] = 1; out.set(bytes, 1);
  return out;
}
// Dispatch one incoming control message: arg = [type u8][payload]. Synchronous —
// every branch is local fs + crypto; the initiator owns the round trips.
function doHandle(arg) {
  const type = arg[0], payload = arg.slice(1);
  if (type === MSG_HAVE) return encodeHaveRes(decodeHaveIds(payload).map((id) => storeHas(id)));
  if (type === MSG_OFFER) { const o = decodeOfferReq(payload); return new Uint8Array([admit(o.descriptor, o.blockId, o.size) ? 1 : 0]); }
  if (type === MSG_STORE) { const s = decodeStoreReq(payload); return new Uint8Array([acceptStore(s.blockId, s.descriptor, s.bytes) ? 1 : 0]); }
  if (type === MSG_FETCH) { const sb = storeGet(payload.slice(0, 32)); return encodeFetchRes(sb ? sb.bytes : null); }
  return EMPTY;
}

register("put", doPut);
register("get", doGet);
register("repair", doRepair);
register("handle", doHandle);

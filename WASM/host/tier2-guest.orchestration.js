// The Tier-2 guest — the WHOLE storage protocol (README §6/§7/§9) as zero-authority
// JS that runs *inside* the QuickJS realm (§2.1). This is the single
// implementation of placement, k-of-n, admission, the wire format, and repair: the
// host (host/storage-node.ts) only boots the kernel and runs this guest in one
// realm. Every capability is reached through the one `host.call(name, bytes)` seam.
// The seam is genuinely async where the world behind it is: the network (a call
// to the reserved id `_net`), every `fs/*` name, and since guest ABI 6 every bare
// module call (the codec and reputation modules run in their own worker on the JS
// targets, so their answers cross an isolate) resolve to a real Promise the guest
// `await`s — so a fan-out is just `await Promise.all(peers.map(...))`, and the
// holder's own store reads await like the initiator's round trips — while the pure
// crypto (the `crypto/*` primitive catalog) and clock resolve synchronously to
// their bytes.
//
// Two roles share this one program, this one realm, and this ONE entrypoint. `handle`
// is reached two ways (seedkernel §12.2): a peer's inbound frame carries
// `[peer 32][MsgType u8][payload]` (HAVE/OFFER/STORE/FETCH — admission,
// content-addressing, quota, fs writes), and the host's own `invoke` loopback carries
// `[zero 32][opLen u8][opName][payload]` (put/get/repair/request/warm) — both split by
// the guest ABI's own `callerOf`/`readOp`. Both may `await` — the
// initiator fans out over net and parks mid-round-trip, the holder answers from local
// storage, and the fs seam is asynchronous on every backend (seedkernel core/fs.ts) —
// so what keeps the two roles from interleaving is the realm's explicit per-realm FIFO
// (seedkernel realm-queue.ts): one invocation runs to completion before the next
// begins, an inbound request queues behind a parked initiator and is served when the
// queue drains (the serialization cost the runtime documents; a node that must serve
// while initiating runs two realms).
//
// This is a plain script, not a module: it has no imports/exports and no ambient
// authority. It is loaded as source by the host (host/storage-node.ts, or the
// seedkernel shell) which prepends an `APP`
// object carrying the storage config + the codec/reputation kernel names, and
// runs it after the safe-js PREAMBLE that defines `host.call` and `register`.
// The seam is name-addressed (seedkernel §12.2): the guest writes "fs/get",
// "_net", "crypto/blake2b-256" — never a number. Every capability the guest
// reaches is an application-neutral primitive; all storage *structure* is right
// here. The same file is hosted by JSC on Bun today and by WAMR in the native
// node later — one artifact, both runtimes.

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

// ── the capability seam: storage policy over GENERIC kernel caps ─────────────
// Every wrapper is built from the application-neutral names of the one seam —
// crypto primitives, fs, module-call, clock, identity (host/guest-seam.ts in
// seedkernel) plus the one cross-realm call that reaches the transport. All *structure*
// lives here in the guest, never in the kernel:
// the nonce convention, the signed-descriptor envelope, the HAVE/OFFER/FETCH/
// STORE wire format (host/protocol.ts), the codec & reputation module ABIs, and
// the <hex>.blk/.dsc store layout (read back host-side by host/store-view.ts, which
// implements none of the policy — see there). Config + the codec and
// reputation kernel names arrive as the injected `APP` constant (prepended by
// the driver), not as kernel names. The pure crypto primitives go through the
// `crypto/` prefix of the catalog (`host.call("crypto/blake2b-256", …)` etc.) and
// resolve to their bytes directly; the net, fs and module-call wrappers are `async`
// and `await` their one round-trip name (the fs seam is asynchronous on every
// backend, so the holder awaits its store ops exactly as the initiator awaits its
// round trips — and since guest ABI 6 a bare module call round-trips like an `fs/`
// name, so the codec and reputation calls await too).

// The op bytes of the codec handler (the guest owns its ABI). The reputation handler's
// op bytes + request framing (REP_OBSERVE/REP_SCORE, encodeScoreReq/encodeObserveReq)
// come from the SHARED host/reputation-core.ts, stitched in ahead of this body — the same
// framing StorageNode.score uses host-side, so the two agree by construction.
const CODEC_ENCODE = 1, CODEC_DECODE = 2;     // assembly/codec/index.ts
// Control-plane message types carried over netSend (host/protocol.ts §18).
const MSG_HAVE = 1, MSG_OFFER = 2, MSG_FETCH = 3, MSG_STORE = 4;
// The protocol id this app speaks on the wire (§12.10) — named in every request this
// guest sends so the receiving host routes it to this app, and the SAME id this bundle's manifest
// claims (`protocols`, scripts/storage-bundle.mjs). That is what makes the frame arrive:
// the load that admitted this code claimed the id, so what a sender writes here and what
// a receiver routes by are one fact. The constant lives host-side (STORAGE_PROTO,
// manifest.ts) and both the manifest and this line come from it.
// strBytes encodes ASCII without TextEncoder (QuickJS has none).
const NET_PROTO = strBytes("seedstore");
const HAVE_ID_LEN = 32;      // a HAVE/FETCH request names 32-byte block_ids (§18)
const FETCH_FRAME = 5;       // a present block costs [found u8][len u32] in a FETCH response (§18)
const STORE_BLK = ".blk", STORE_DSC = ".dsc";
// The logical names this app's own modules are installed under. The guest calls them
// by the logical name from its manifest, straight through `host.call` — a bare name
// (no `/`) is what makes it a module rather than a host name (seedkernel §12.2), and
// the guest seam resolves it against this app's map, so app keys never leave the host.
const CODEC_NAME = "codec";
const REP_NAME = "reputation";

// The injected constant is just `APP` (seedkernel §12.4): the author's signed config
// with operator policy merged over it (storage-node.ts appPreamble builds it host-side;
// the shell merges --app-config over the bundle's). Read directly as `APP.*`.
// Nothing the RUNTIME derives is injected anymore — the signing scope in particular
// lives on the host side of the seam: node/sign applies it when signing, node/verify
// when checking, so the guest never holds (or reconstructs) the prefix bytes.

// ── crypto primitives + storage framing ──
// The pure transforms reach the host under the `crypto/` prefix of the one seam
// (host.call("crypto/<name>", args) — seedkernel §12.2): BLAKE2b-256 for
// block-ids and XChaCha20 stream XOR for the §4.4 keystream. The authorities —
// node/sign, node/verify, node/identity, node/random — are host.call names like
// anything else, as are the clock and the module call. Signing AND verification are
// scoped, never raw: the host applies `DOMAIN_guest ‖ scope` to the message on both
// sides (seedkernel §12.2), so this guest names the key it signs with / checks under
// and never reconstructs host-owned prefix bytes.
function hash(bytes) { return host.call("crypto/blake2b-256", bytes); }
function randomKey() { const n = new Uint8Array(4); wU32(n, 0, 32); return host.call("node/random", n); }
function identity() { return host.call("node/identity", EMPTY); }
let myPeerCache = null;
function myPeer() { if (myPeerCache === null) myPeerCache = toHex(identity()); return myPeerCache; }
// 24-byte nonce = [level u8][chunk index u32 BE][0…] (§4.4) — the guest's convention.
function nonce(level, index) { const n = new Uint8Array(24); n[0] = level & 255; wU32(n, 1, index >>> 0); return n; }
// crypto/xchacha20/xor takes [nonce 24][key 32][message ..] for the xchacha20/xor primitive.
function streamXor(K, non, msg) { return host.call("crypto/xchacha20/xor", concat([non, K, msg])); }
function encrypt(K, level, index, msg) { return streamXor(K, nonce(level, index), msg); }
function decrypt(K, level, index, ct) { return streamXor(K, nonce(level, index), ct); }
// Signed chunk descriptor envelope: [authorPk 32][sig 64][core] (§4.3, §16). The
// scope rides the seam: `node/sign` signs `DOMAIN_guest ‖ scope ‖ core` for us (so
// signCore passes the bare core and gets back a scoped signature), and node/verify
// checks the same preimage for the author key in the envelope. The stored envelope
// holds only [pk][sig][core] — the prefix is preimage-only, never transmitted.
function signCore(core) { return concat([identity(), host.call("node/sign", core), core]); }
function verifyEnv(env) {
  return host.call("node/verify", concat([env.slice(0, 32), env.slice(32, 96), env.slice(96)]))[0] === 1;
}

// ── codec + reputation ──
// Both are ordinary `host.call`s: the module name IS the seam's name argument, so
// there is no header to build and the request body crosses as itself. The RS request
// is large (k data blocks ≈ 640 KB) and this is the one place that matters — the old
// framing prepended a length-prefixed name, so every encode copied the blocks into a
// request buffer and then copied that whole buffer again. Now the single `concat`
// below is the only pass over them.
//
// Since guest ABI 6 a module call is ASYNC — the module runs in its own worker on the
// JS targets, so its answer crosses an isolate — so every module call here is awaited
// like an `fs/*` call, and the transforms built on them (encodeChunk, assembleChunk,
// the ranker) are async in turn. The call still runs under the calling guest's
// remaining execution budget (§4.3), which is what keeps the module interruptible.
async function rsEncode(k, m, blockSize, dataBlocks) {
  const head = new Uint8Array(7);
  head[0] = CODEC_ENCODE; head[1] = k; head[2] = m; wU32(head, 3, blockSize);
  const parity = splitBlocks(await host.call(CODEC_NAME, concat([head, ...dataBlocks])), blockSize);
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
  // The seam check rsEncode makes above, on the side where a miss costs more. The
  // geometry is the DESCRIPTOR's, never this node's config (§4.1), so a chunk written
  // under a k·blockSize past this codec handler's scratch reaches here on an ordinary
  // GET — and the module answers short or empty rather than throwing. Unchecked, that
  // is a chunk silently reassembled from fewer blocks than it has: content addressing
  // verified the INPUT blocks (§4.2) and nothing on the read path re-verifies the
  // codec's OUTPUT (heal re-certifies its own against the signed ids, §9, which is why
  // repair degrades where a read would corrupt). A short decode must be an error.
  if (data.length !== k) {
    throw new Error("rsDecode: codec returned " + data.length + " blocks, expected " + k +
      " — chunk (k=" + k + " × blockSize=" + blockSize + ") likely exceeds the codec handler's scratch");
  }
  return data;
}
function clockNow() { const b = host.call("clock/now", EMPTY); return rU32(b, 0) * 0x100000000 + rU32(b, 4); }
async function repScore(peerPk, t) {
  return readF64LE(await repScoreBytes(peerPk, t));
}
// The module's answer as it stands — [score f64 LE] — for the one caller that wants the
// bytes rather than the number: Op.SCORE, the host asking this guest what standing it
// holds for a peer. The reputation module is this slot's private one, so the host cannot
// call it itself, and re-encoding a float it will only decode again would be two framings
// of one fact.
function repScoreBytes(peerPk, t) { return host.call(REP_NAME, encodeScoreReq(peerPk, t)); }
function repObserve(peerPk, t, pass) {
  // Returns the new score; the guest doesn't need it. Fire-and-forget — the promise is
  // dropped on purpose, and the catch is hygiene: a module call resolves (never
  // rejects) but an unhandled rejection in the realm would surface as a job failure.
  void host.call(REP_NAME, encodeObserveReq(peerPk, t, pass)).catch(() => {});
}

// ── local store over fs.* (the <hex>.blk / <hex>.dsc layout) ─────────────────
// Every fs/* name round-trips now (the seam is async — seedkernel core/fs.ts), so
// the whole store layer is async and every caller awaits it. Existence is
// `size ≥ 0` (there is no fs/has): the raw fs/size is 0xFFFFFFFF
// (−1 over the bridge) only for an absent key, so a present-but-empty value still reads as held.
async function storeHas(id) { return (await fsSizeRaw(toHex(id) + STORE_BLK)) !== 0xffffffff; }
async function storeGet(id) {
  const hex = toHex(id);
  const blk = await host.call("fs/get", strBytes(hex + STORE_BLK));
  if (blk[0] !== 1) return null;
  const dsc = await host.call("fs/get", strBytes(hex + STORE_DSC));
  return { bytes: blk.slice(1), descriptor: dsc[0] === 1 ? dsc.slice(1) : null };
}
// Just the <hex>.dsc sidecar, without dragging the block ciphertext across the
// bridge — repair audits chunk shape from the descriptor and never needs the .blk
// bytes (it re-fetches those from holders only where healing actually places).
async function storeGetDescriptor(id) {
  const dsc = await host.call("fs/get", strBytes(toHex(id) + STORE_DSC));
  return dsc[0] === 1 ? dsc.slice(1) : null;
}
async function storeList() {
  const r = await host.call("fs/list", EMPTY), out = [];
  let o = 0; const n = rU32(r, o); o += 4;
  for (let i = 0; i < n; i++) {
    const klen = rU32(r, o); o += 4;
    const key = bytesToStr(r.slice(o, o + klen)); o += klen;
    if (key.length === 68 && key.slice(64) === STORE_BLK) out.push(fromHex(key.slice(0, 64)));
  }
  return out;
}

// ── the network: one reserved id, two ops ────────────────────────────────────
// The network is not a host capability any more (seedkernel §12.10): it is a bundle —
// the transport — that claims the reserved protocol id `_net`, and an app reaches it with
// the ONE cross-realm call, `host.call("_net", …)`. The host's whole contribution is
// attribution: it prepends this app's 32-byte key as the caller, exactly as it prepends
// a sender's key on an inbound frame, so the transport can tell an app's request from the
// platform's own events without a second seam.
//
// What crosses is the transport's op wire: `[opLen u8][op][args]`, where the op is a NAME
// (never a number two sides must agree on) and `args` is a fixed field order the op
// declares — a u8, a u32 BE, or a `[len u32][bytes]` blob. Two ops are an app's to
// name, and they are the two that were app-facing host names before the transport
// became a bundle: `send` (was `net/send`) and `peers` (was `net/peers`). Anything
// else the transport refuses, because the platform's events are not an app's to fake.
//
// Both answer on a LATER turn — the callee never runs inside this guest's frame — so
// both are awaited, `peers` included. That is the one shape change from the old host
// names, and it is why the roster reads flow through `await` here.
const NET_ID = "_net";
function netBlob(b) { const h = new Uint8Array(4); wU32(h, 0, b.length); return concat([h, b]); }
function netOp(op, args) {
  // Framed by the preamble's `writeOp` (seedkernel `host/guest-seam.ts`) — the same
  // envelope this app's own `handle` is called with, written by the one function that
  // defines it rather than open-coded per caller.
  const out = writeOp(op, args);
  // A cross-realm call REJECTS for the two cases that are not about a peer at all: no
  // realm claims `_net` (a node whose transport bundle was never loaded or was replaced)
  // and a transport that is being torn down under us. Neither is an error this app can act on
  // — both mean "the network is not there" — and both read here as the empty answer,
  // which is exactly how an unreachable peer already reads: `send` answers no `[1]`, so
  // netSend returns null, and `peers` answers an empty roster. A PUT then reports "no
  // holder answered" instead of a stack trace out of a fan-out.
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
// A reciprocity ranker (§13): orders peers best-score-first. Scoring one peer costs a
// reputation MODULE_CALL across the bridge, so `makeRanker` reads the clock once and
// memoizes each DISTINCT peer's decayed score for its lifetime — reuse one across a
// round and ranking many overlapping holder subsets (a large GET ranks the same
// holders for thousands of ids) costs one crossing per peer, not one per (peer, id).
// Scores decay negligibly within a round, so a shared `t` is fine. The module call is
// async since guest ABI 6, so the ranker's per-peer scores resolve in a Promise.all
// before the sort — and what is memoized is the PROMISE, not the settled score, so two
// scorings of one peer in the same fan-out share the one crossing the cache exists for
// rather than both missing it while the first is still in flight.
function makeRanker() {
  const t = clockNow();
  const cache = new Map(); // peerHex → Promise<decayed score>
  const scoreOf = (p) => { let s = cache.get(p); if (s === undefined) cache.set(p, s = repScore(fromHex(p), t)); return s; };
  return async (peers) => {
    if (peers.length === 0) return [];
    const scored = await Promise.all(peers.map(async (p) => ({ p, s: await scoreOf(p) })));
    return scored.sort((a, b) => b.s - a.s).map((x) => x.p);
  };
}
// One-shot ranker for callers that rank a single list (its own fresh cache).
function rank(peers) { return makeRanker()(peers); }

// ── net (request/response over the transport; wire format here) ──
// One round trip to one peer, as the transport's `send` op:
//   [noReply u8][deadlineMs u32][to blob][proto blob][payload blob]
// A zero deadline means the node's own default (the host's `requestDeadlineMs`), which
// is where that number belongs — one place, not mirrored on both sides of the seam.
// The answer is `[ok u8][response]`: an unreachable peer comes back `[0]` rather than a
// rejection, so this maps it to null within the request window.
//
// `proto` is the routing (§12.10) — the id the receiving host resolves to the app that
// claims it — and the storage message type leads the payload, which is this app's own
// framing and opaque to everything in between.
async function netSend(peer, type, payload) {
  const head = new Uint8Array(5); // noReply=0, deadline=0 (the node's default)
  const body = new Uint8Array(1 + payload.length);
  body[0] = type;
  body.set(payload, 1);
  const r = await netOp("send", concat([head, netBlob(fromHex(peer)), netBlob(NET_PROTO), netBlob(body)]));
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
  for (const id of ids) if (await storeHas(id)) holders.get(toHex(id)).add(myPeer());
  const peers = await cohortPeers();
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
  if (peer === myPeer()) return Promise.all(ids.map(async (id) => { const sb = await storeGet(id); return sb ? sb.bytes : null; }));
  const resp = await netSend(peer, MSG_FETCH, encodeFetchBatchReq(ids));
  if (resp === null) return null;
  const blocks = decodeFetchBatchRes(resp);
  return ids.map((_, i) => blocks[i] || null);
}
// There is ONE placement engine (placeChunksBatched, below) and it drives the shared
// §18 codecs — encodeOfferBatch / encodeStoreBatch with the shared decodeMask
// (host/protocol.ts) — directly through netSendMany, mapping an unreachable peer
// (netSend → null) to all-declines. Nothing places a block any other way: a small
// file, a window of coded chunks, an index level, and a repair pass all express
// themselves as (block, slot) targets and hand them to that one function.

// ── descriptor ───────────────────────────────────────────────────────────────
// The pure §4.3 codecs — encode/decodeDescriptorCore, parseSignedDescriptor,
// encode/decodeDescriptorList, descriptorContains, copyTargets, BLOCK_ID_LEN — come
// from the SHARED host/manifest-core.ts, stitched in ahead of this body (one
// definition). What stays here is only the part that needs a capability: verify/sign
// over the scoped `node/verify` / `node/sign` seam, composed with the shared
// parser/encoder.
//
// verifyDescriptor checks the author signature AND structurally validates the core
// (the parity the host holder has): a *signed* but malformed descriptor (junk core, an
// id count that is not k+m) is rejected — not parsed into garbage block-ids that
// sidestep the §10 sibling rule — because parseSignedDescriptor throws on a bad core.
// It returns the whole signed envelope, because a valid signature is only half the
// check: knownAuthors below is the other half.
function verifyDescriptor(env) {
  // Length-gate before the verify seam: the envelope is [pk 32][sig 64][core ≥13]
  // (parseSignedDescriptor's own bound), so anything shorter — an absent descriptor
  // included — is rejected here rather than handed to verify as a short buffer.
  if (!env || env.length < 32 + 64 + 13) return null;
  if (!verifyEnv(env)) return null;
  try { return parseSignedDescriptor(env); } catch (_e) { return null; }
}
// The §4.3 ANCHOR. A signature checked against a public key carried inside the object
// it signs proves only that *someone* held a private key — any cohort peer can mint a
// fresh keypair and self-sign whatever descriptor it likes, which is exactly the
// substitution §4.3 forbids and exactly what would let a malicious placer ship a
// truncated sibling list and concentrate a chunk on itself (§6, §10). So the author must
// also be an identity this node's cohort knows (§5.1). Forgery then costs a known peer
// its standing instead of nothing, which is §13's job, not new machinery.
async function knownAuthors() { const s = new Set(await cohortPeers()); s.add(myPeer()); return s; }
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
// The fan-out window (transport/operator policy, like maxMessageBytes): how many
// per-peer sub-batches a single Promise.all round fires at once. PUT and GET share
// one window — they have never been tuned apart in practice, so fanoutWindow bounds
// STORE messages PER PEER and FETCH messages TOTAL across the cohort, letting the
// guest pipeline a holder's many ~1-block messages instead of paying one round trip
// apiece (the tight-cap WebRTC case the lock-step fan-out was meant to keep
// windowed). Injected in full by the driver (core.ts homes the default); the guest
// reads APP and never guesses.
function fanoutWindow() { return APP.fanoutWindow; }
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
//   a chunk (makeChunk)  one slot per LISTED id — which is a coded chunk's k+m blocks
//                        once each and a k=1 chunk's lone block m+1 times, by the same
//                        rule (§4.1); floor = its own k
//   an index chunk       exactly that, one level up (§4.3) — not a special case
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
// A signed chunk ready to place, expanded into its placement slots (§6/§10). One slot per
// listed id — since a k=1 chunk lists its block m+1 times, that IS its r = m+1 replica
// slots, with no branch and no slot table. Placement only ever sees a list of slots to
// land on distinct peers. The floor is the chunk's OWN k, not config's, and a fresh chunk
// excludes nothing.
function makeChunk(d, blocks, descriptor) {
  return makeJob(d.blockIds.slice(), blocks.slice(), descriptor, d.k, new Set());
}
// Encode + sign one chunk at its OWN k: every chunk is coded at k = ceil(plain / blockSize),
// the actual block count it carries, rather than padded to the deployment's k. At k = 1 the
// code degenerates — RS(1,m) parity ≡ data — so the codec is skipped and the chunk simply
// LISTS its lone block m+1 times; n = k+m either way and multiplicity is the replica count
// (§4.1). At k ≥ 2 it is RS(k, m). The nonce is (this chunk's level, its GLOBAL index within
// that level) (§4.4), so a windowed encode is byte-identical to a whole-level one, and an
// index chunk can never collide with a body chunk. `tailBytes` records how much of the
// chunk is real, which is what a reader trims by instead of a manifest-wide file_size.
async function encodeChunk(source, localCi, globalCi, K, level) {
  const c = APP;
  const plain = source.slice(localCi * c.k * c.blockSize, (localCi + 1) * c.k * c.blockSize);
  const kc = Math.max(1, Math.ceil(plain.length / c.blockSize));
  const ct = encrypt(K, level, globalCi, padTo(plain, kc * c.blockSize));
  const dataBlocks = splitBlocks(ct, c.blockSize);
  const blocks = kc === 1 ? new Array(c.m + 1).fill(dataBlocks[0])
                          : [...dataBlocks, ...await rsEncode(kc, c.m, c.blockSize, dataBlocks)];
  const ids = kc === 1 ? new Array(c.m + 1).fill(hash(dataBlocks[0])) : blocks.map(hash);
  const d = { level, k: kc, m: c.m, blockSize: c.blockSize, tailBytes: plain.length, blockIds: ids };
  return makeChunk(d, blocks, signChunk(d));
}
// THE placement engine (§6/§10). Place every job's slots with one batched OFFER per peer
// per round, then the accepted blocks STORE'd in fanoutWindow()-deep fan-outs per peer.
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
  const ranked = await rank(await cohortPeers());
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

    // Lock-step fan-out: ALL of this round's OFFERs (one Promise.all over the peers)
    // complete before its STOREs (no optimistic STORE — §6). The OFFER
    // phase carries ≤1 message per peer per fan-out (a peer's offers are small and
    // rarely exceed maxOffers, so the sub-batch index is round-robined one-per-peer).
    // The STORE phase windows up to fanoutWindow() of a peer's byte-bounded sub-batches
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
      // NO verdicts at all is itself the diagnosis, and the most confusing failure to
      // read: every response failed (a request deadline that expired while the bytes
      // were still queued behind a deep socket buffer, or an unreachable peer), so no
      // holder ever judged anything. Saying "holders declined" with an empty tally
      // points at the holders, which is precisely where the fault is NOT.
      const why = parts.length
        ? "holders declined (" + total + " holders: " + parts.join(", ") + "). Check quota (--app-config), signing scope (§16), or connect more holders"
        : "no holder returned a verdict — the requests timed out or the peers were unreachable rather than refusing. Raise the request deadline if a large PUT is queueing past it (p2p-cli --timeout, loader --request-deadline)";
      throw new Error("put: " + what + " landed " + distinct.size + "/" + ch.floor + " distinct blocks — " + why);
    }
    ch.placedIds = [...distinct].map(fromHex);  // the distinct ids that landed, for the PUT result
  }
}
// Run a windowed batched FETCH over a peer→[idHex] plan. Self reads the local store
// directly (no round trip, no scoring); every other holder's sub-batches are flattened
// into one task list and fanned out fanoutWindow() FETCH messages at a time (peak W in
// flight, the fanoutWindow window). `apply(peer, sliceHex, ids, blocks)` sees each
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
// terminates — an honest holder's property, so the loop CHECKS it (a round that decides
// nothing is ruled a miss, below) instead of taking the answering peer's word for its own
// termination. A genuine miss is ABSENT even past the cap, so it is ruled a miss in one
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
  const getW = fanoutWindow();
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
      // Re-queue the unanswered ids only if this round DECIDED something — the
      // strictly-smaller-slice invariant, checked rather than assumed. Every round
      // resolving ≥1 block is a property of an honest serveFetch, not of the wire: a peer
      // that answers UNANSWERED for every id it was asked has resolved nothing, and
      // re-queueing it would append a same-size task forever — an unbounded loop, and
      // unbounded `tasks` growth in this realm, that ONE holder could hang any GET or
      // repair pass with. No progress therefore rules those ids absent for this peer,
      // which is what a claimed-but-never-served block is: a §8 miss that scores the
      // holder down and sends the reader to the next holder of the block.
      if (reSlice.length && aSlice.length === 0) {
        for (let i = 0; i < reSlice.length; i++) { aSlice.push(reSlice[i]); aIds.push(reIds[i]); aBlocks.push(null); }
        reSlice.length = 0;
      }
      if (reSlice.length) tasks.push({ peer, slice: reSlice, ids: reIds });
      if (aSlice.length) apply(results[ri].peer, aSlice, aIds, aBlocks);
    }
  }
}
// Fetch every block the file's chunks need, batched per holder. After the file-wide
// have/want, each still-missing block is requested from its best untried holder,
// sub-batched under the frame cap and fanned out fanoutWindow() FETCH messages at a time
// (peak W in flight, the fanoutWindow window); a coded chunk stops at k, preferring
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
        const cands = await rankRound([...(holders.get(h) || new Set())].filter((p) => !triedOf(h).has(p)));
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

    // Self reads local; every other holder's sub-batches window by fanoutWindow() (§8/§13).
    await runFetchTasks(byPeer, maxIds, applyFetch);
  }
  return got;
}
// Assemble one chunk's ciphertext from the gathered blocks (§4.1/§7): take the first k
// DISTINCT listed blocks that arrived, and if they are the k data blocks in order just
// concatenate them (systematic RS — the common case, and the only case at k = 1, whose
// one listed block is data). Anything else decodes. Distinct matters because a k = 1
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
  const allData = present.slice(0, k).every((p) => p.index < k);
  if (allData) {
    const ordered = present.filter((p) => p.index < k).sort((a, b) => a.index - b.index).slice(0, k);
    if (ordered.length === k && ordered.every((p, i) => p.index === i)) return concat(ordered.map((p) => p.bytes));
  }
  return concat(await rsDecode(k, d.m, d.blockSize, present));
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
// The host driver derives it from realmMemoryBytes (~realmMemoryBytes / 3, peak
// guest footprint ratio) and injects it as APP.windowTargetBytes; an explicit
// override stays for benchmarking. The host awaits each window fully (OFFER→STORE→ack)
// before feeding the next, so on a fat/low-loss link a too-small window idles the wire
// between windows. This is the reader's/writer's OWN memory policy, not file geometry,
// so it stays a config value even on the descriptor-authoritative GET path.
function windowTarget() { return APP.windowTargetBytes ?? 4 * 1024 * 1024; }
// A chunk-aligned window size in bytes: as many whole chunks (k·blockSize) as fit
// under the target, at least one. Kept a multiple of k·blockSize so slicing the file
// at window boundaries never splits a chunk. This is the WRITE side, so k·blockSize is
// the config the writer encodes with.
function putWindowBytes() { const chunkData = APP.k * APP.blockSize; return Math.max(1, Math.floor(windowTarget() / chunkData)) * chunkData; }
// Chunks per GET window — the reconstruct side's counterpart, bounding the plaintext a
// single getChunk holds before it is handed back to the host. `chunkData` (k·blockSize)
// is the DESCRIPTOR's geometry (§4.3), passed in by the reader, never config's.
function getWindowChunks(chunkData) { return Math.max(1, Math.floor(windowTarget() / chunkData)); }

// Encode + place the chunks wholly contained in `slice` — a chunk-aligned slice of a
// LEVEL's byte stream starting at byte offset `baseByteOffset` within it. Each chunk is
// coded at its own k (§4.1): RS(kc, m) at kc ≥ 2, the m+1-way listing at kc = 1.
// placeChunksBatched places both the same way, and level 0 (the file) and level ℓ > 0
// (an index over level ℓ−1) are the same call.
async function placeWindow(slice, baseByteOffset, K, level) {
  const c = APP;
  const chunkData = c.k * c.blockSize;
  const baseCi = Math.floor(baseByteOffset / chunkData);
  const numChunks = Math.max(1, Math.ceil(slice.length / chunkData));
  const chunks = [];
  for (let lc = 0; lc < numChunks; lc++) chunks.push(await encodeChunk(slice, lc, baseCi + lc, K, level));
  await placeChunksBatched(chunks, "chunk");
  return chunks;
}

// Place a whole byte stream as a run of chunks, windowed exactly as the driver windows
// the file body, and answer with their signed descriptors. This is the ONLY thing that
// turns bytes into placed chunks — and a file's own descriptor list is bytes, so it goes
// through here too, at a different `level`. One path, called twice; not two paths.
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
// The largest a signed descriptor gets, framed for the descriptor list: the deployment's
// own (k, m), since a partial chunk lists fewer ids (§4.3).
function descriptorBytes() { return 4 + 32 + 64 + 13 + (APP.k + APP.m) * BLOCK_ID_LEN; }
// Open a stream: mint K and answer with the plaintext window the driver should feed. The
// file size is no longer an argument — each chunk signs its own `tailBytes` (§4.3), so
// the writer never needs the total and the reader derives it from the leaves.
//
// The ONE thing a descriptor list asks of the deployment: a chunk must hold at least two
// descriptors, or a list of them could never shrink to a single root. That is a property
// of (k, blockSize) alone, so it is checked here, once, before a byte moves — never
// discovered halfway through a placement. Production geometry clears it ~2000×.
function putStart() {
  const chunkData = APP.k * APP.blockSize;
  if (chunkData < 2 * descriptorBytes()) {
    throw new Error("put: k·blockSize (" + chunkData + " B) must hold two chunk descriptors ("
      + descriptorBytes() + " B each) so a file's descriptor list can reach a single root — raise blockSize or k");
  }
  putStream = { K: randomKey(), offset: 0, descriptors: [], placedIds: [], placed: 0, intended: 0 };
  return putWindowBytes();
}
// Fold placed chunks into the stream's durability accounting (§8), whichever level they
// belong to. It counts REPLICA PLACEMENTS — one stored (block, peer), i.e. one filled
// slot — not distinct ids: a k=1 chunk is one id on m+1 peers, so counting ids would
// report 1 even when every copy landed. `intended` is capped at the reachable cohort
// because the §6/§10 sibling rule puts at most one of a chunk's blocks on any one peer —
// so a genuinely small cohort is not flagged, while a reachable-but-declining (full)
// holder makes placed < intended.
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
// Seal the stream and report the whole PUT. The stream closes first, so a failed or
// abandoned PUT leaves nothing behind for the next one to inherit.
//
// The descriptors this PUT placed are bytes, so they go through placeStream like the body
// did — and so do the descriptors THAT produces, until one chunk is left. Its signed
// descriptor is the file's root (§4.3). The loop is bounded and shallow: one chunk holds
// thousands of descriptors at production geometry, so it runs 0 times up to 512 KiB, once
// up to ~1 GB, twice up to ~2.5 TB. A file that fits one chunk has no index at all — its
// own descriptor IS the root, which a reader tells apart by the signed `level`.
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
// The root is the signed ROOT DESCRIPTOR (§4.3), not a 32-byte hash — that is the whole
// ergonomic cost of deleting the manifest object, and it is why the head carries its
// length. Offsets 0–47 are fixed and the root starts at 48, so the byte-in/byte-out
// drivers (the seedkernel shell, the Go loader) can read K and the root without knowing
// the rest. (placed, intended) is the replica accounting (§8) — how many replicas landed
// vs how many were reachable-and-intended — so a driver can warn on a PUT that met the
// ≥ k floor but is silently under-replicated (a full/declining holder, or a short cohort).
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
function doPutStart() { const out = new Uint8Array(4); wU32(out, 0, putStart()); return out; }
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
  const wb = putStart();
  for (let off = 0; ; off += wb) {
    await putFeed(plaintext.subarray(off, Math.min(off + wb, plaintext.length)));
    if (off + wb >= plaintext.length) break;
  }
  return putFinish();
}

// ── GET (§7) ─────────────────────────────────────────────────────────────────
// Fetch, reconstruct (§4.1) and decrypt (§4.4) the plaintext for a run of parsed chunk
// descriptors `ds` whose first chunk is index `chunkStart` within its level. One
// have/want + batched FETCH per holder (gatherBlocks) over just these chunks' block ids —
// shared by the whole-file `get`, the streamed getNext window, AND the index walk, since
// an index level is read exactly like a run of file chunks. Geometry is the DESCRIPTOR's,
// never config's (§4.1/§4.3): the nonce level, the decode (assembleChunk/rsDecode use
// d.k/d.blockSize) and the tail trim all come from the chunk in hand, so there is no
// cumulative byte bookkeeping to keep in step and nothing to disagree.
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
    const plain = decrypt(K, d.level, chunkStart + i, await assembleChunk(d, got));
    parts.push(plain.length === d.tailBytes ? plain : plain.subarray(0, d.tailBytes));
  }
  return concat(parts);
}
// ── the streamed GET session ─────────────────────────────────────────────────
// The mirror of the PUT stream: getStart walks the index down to the leaf descriptors and
// keeps them — parsed, in file order — in realm state. The driver then calls getNext until
// it has the file, each call reconstructing one window's chunks, so only one window's
// plaintext is ever resident.
let getStream = null;
// Open a stream from the ROOT DESCRIPTOR the reader was handed. Its signed `level` says
// what it describes: 0 is the file's own ciphertext (a one-chunk file needs no index at
// all), ℓ > 0 an index whose plaintext is the descriptor list of level ℓ−1 — read by the
// very same reconstruct path. Walk down to the leaves, then sum their signed tailBytes for
// the file size.
//
// No signature check on this path. It would be checking something already proven: the
// reader holds the root, and every level below it is reached through content-addressed
// block ids (§4.2), so a tampered index fails its hash long before it is parsed. The
// author signature is what a HOLDER checks, at admission, where it is load-bearing (§4.3).
async function getStart(rootEnv, K) {
  let ds;
  try { ds = [parseSignedDescriptor(rootEnv).descriptor]; }
  catch (_e) { throw new Error("get: malformed root descriptor"); }
  while (ds[0].level > 0) {
    const above = ds[0].level;
    ds = decodeDescriptorList(await reconstructChunks(ds, K, 0)).map((env) => parseSignedDescriptor(env).descriptor);
    // The descent MUST strictly decrease, and this is the one place that is worth
    // enforcing rather than assuming. A reader is HANDED (root, K) by a sharer, and a
    // stream cipher with no tag (§4.4) means that sharer chose the plaintext at every
    // level — so a hostile one can hand out an index whose chunk decrypts to a list
    // naming itself. Content-addressing does not catch it (the bytes really do hash to
    // their ids); without this check the walk fetches in a loop forever, which is a hang
    // rather than an error. Levels are a u8, so this also bounds the descent at 255.
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
// have/want, then confirmed retrievable by a verification-fetch (§8). Returns
// { live: Map hex → Set(peer), bytes: Map hex → one verified copy }. The audit
// already pulls a verifying copy from every live holder, so it keeps one per id in
// `bytes` — healing re-places THOSE instead of re-fetching (a whole-cohort have/want
// per id, the pre-batch cost). The verification is unchanged per (peer, block): the
// same hash-check (§4.2) + repObserve (§8), just batched one FETCH per holder (all the
// ids it advertised) and windowed by fanoutWindow(), not one round trip per (id, holder).
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
// ONE slot model, because the descriptor already says how many copies each listed block
// wants: its MULTIPLICITY in the id list (copyTargets) — once for each of a coded chunk's
// k+m blocks, whose redundancy is the parity instead, and m+1 times for a k=1 chunk's lone
// block. A block short of that count is topped up from the copy the audit (liveHolders)
// already fetched and verified, so a block that still has a live holder costs no extra
// round trip. A CODED block (k ≥ 2) no live holder serves at all has no copy to lean on,
// so it is first reconstructed from any k present blocks and re-certified against its
// signed block_id; a k=1 chunk has no parity to rebuild from — its other copies were the
// redundancy — so it can only be copied while one survives. The copies it ends up owing
// are then just placement slots, handed to the same engine PUT uses.
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
  const sd = verifyDescriptor(descEnv);                    // forged/unsigned/malformed → null (§4.3)
  if (!sd) return 0;
  const d = sd.descriptor;
  const { live: holders, bytes: verified } = await liveHolders(d.blockIds);
  // Chunk health is ONE number, whatever the chunk's k (§8, §9): the loss margin — how
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
  for (const id of await storeList()) {
    const descriptor = await storeGetDescriptor(id);
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
// Reached only through the generic caps, and *async*: a holder answers from local
// fs, and the fs seam is asynchronous on every backend (seedkernel core/fs.ts), so
// `doHandle` is an async entrypoint — the transport driver already accepts an async
// app handler (it answers through the `respond` entrypoint on a later turn). This
// is the ONLY implementation of the quota rule — the host keeps a read view of the
// fs (host/store-view.ts) and no write path — so bytesUsed is the budget, rebuilt
// lazily from the fs the first time it matters.
let bytesUsed = -1;
// The §14 byte budget is OPERATOR policy, not author content: the StorageNode injects
// its store's quota, and a seedkernel shell merges the operator's config over the
// (author-signed) manifest — so it is always present in the injected APP, never baked
// into the signed bundle. The guest reads it and never guesses a *generous* default: if
// a driver under-injects (a shell holder booted with no operator quota — the shell keeps
// no default of its own), fall to 0 and FAIL CLOSED, so the holder admits nothing rather
// than becoming an unbounded sink. Reads (FETCH) never check quota, so serving still works.
function quota() { return APP.quota != null ? APP.quota : 0; }
// fs/size returns 0xffffffff for an absent key (−1 over the bridge).
// fsSizeRaw preserves that sentinel — it is how existence is asked (storeHas), since
// there is no fs/has. fsSize maps the sentinel to 0 so sizing a bare block's missing
// .dsc adds nothing to the quota total, not ~4 GiB.
async function fsSizeRaw(keyStr) { return rU32(await host.call("fs/size", strBytes(keyStr)), 0); }
async function fsSize(keyStr) { const v = await fsSizeRaw(keyStr); return v === 0xffffffff ? 0 : v; }
async function ensureUsed() {
  if (bytesUsed >= 0) return;
  bytesUsed = 0;
  // The committed tier is the <hex>.blk ciphertext AND its <hex>.dsc descriptor
  // sidecar — the descriptor is real bytes a holder keeps per block, so charging only
  // .blk would over-admit by the whole descriptor tier (§14). Rebuilt from the fs, so
  // a restarted holder re-derives its budget from what is actually on the backend.
  for (const id of await storeList()) { const hex = toHex(id); bytesUsed += await fsSize(hex + STORE_BLK) + await fsSize(hex + STORE_DSC); }
}
async function quotaFree() { await ensureUsed(); return Math.max(0, quota() - bytesUsed); }
async function fsPut(keyStr, bytes) {
  const kb = strBytes(keyStr);
  const head = new Uint8Array(4); wU32(head, 0, kb.length);
  await host.call("fs/put", concat([head, kb, bytes]));
}
// The one write path into store.local: the <hex>.blk ciphertext + its sibling
// <hex>.dsc descriptor, under the quota budget. Throws past quota so admission
// refuses rather than over-commits.
//
// The quota throw is TAGGED, because it is the only failure here the caller can
// name: everything else (a full disk, a backend error, a realm OOM) surfaces as
// some other exception from the fs seam, and reporting those as "quota" sends an
// operator to raise a number that was never the constraint. A holder has no
// console — the verdict byte is its ONLY way to say what happened — so the two
// cases must not share one code.
async function storeWrite(id, bytes, descriptor) {
  await ensureUsed();
  const hex = toHex(id);
  // Charge the ciphertext AND the descriptor sidecar, crediting whatever was already
  // stored under this id, instead of writing the .dsc for free. Admission (admitBatch)
  // has already verified the descriptor, so every committed block has one: the .dsc
  // write is unconditional, with no described-block-overwritten-by-a-bare-one case to
  // unwind.
  const prevBlk = (await storeHas(id)) ? await fsSize(hex + STORE_BLK) : 0;
  const prevDsc = await fsSize(hex + STORE_DSC);
  const next = bytesUsed - prevBlk - prevDsc + bytes.length + descriptor.length;
  if (next > quota()) { const e = new Error("store: quota exceeded"); e.quota = true; throw e; }
  await fsPut(hex + STORE_BLK, bytes);
  await fsPut(hex + STORE_DSC, descriptor);
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
async function admit(descriptor, blockId, size) {
  return (await admitBatch([{ blockId, descriptor, size }]))[0];
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
async function admitBatch(offers) {
  let free = await quotaFree();
  const provisional = new Set();
  const known = await knownAuthors();                        // read the roster once per batch
  const verdicts = [];
  for (const o of offers) {
    const sd = verifyDescriptor(o.descriptor);
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
    // Charge what storeWrite will actually commit — the ciphertext AND its .dsc
    // sidecar — so this pre-check answers the same question the binding write does
    // instead of over-admitting by the descriptor's own size.
    const cost = d.blockSize + o.descriptor.length;
    if (cost > free) { verdicts.push(VERDICT_QUOTA); continue; }
    // The sibling rule, over the whole id list. A block this holder ALREADY has counts:
    // a k=1 chunk lists its one block m+1 times, so those m+1 slots are m+1 distinct
    // peers — accepting a second copy here would silently burn one of them and leave the
    // chunk short of replicas while looking placed.
    if ((await storeHas(o.blockId)) || provisional.has(toHex(o.blockId))) { verdicts.push(VERDICT_SIBLING); continue; }
    let sibling = false;
    for (const sib of d.blockIds) {
      if (bytesEqual(sib, o.blockId)) continue;
      if ((await storeHas(sib)) || provisional.has(toHex(sib))) { sibling = true; break; }
    }
    if (sibling) { verdicts.push(VERDICT_SIBLING); continue; }
    free -= cost;
    provisional.add(toHex(o.blockId));
    verdicts.push(VERDICT_ACCEPTED);
  }
  return verdicts;
}
async function acceptStore(blockId, descriptor, bytes) {
  // The bytes must hash to the claimed id (§4.2) — every holder, every hop.
  if (!bytesEqual(hash(bytes), blockId)) return VERDICT_DECLINED;
  const v = await admit(descriptor, blockId, bytes.length);
  if (v !== VERDICT_ACCEPTED) return v;
  // A tagged quota throw is the §14 budget saying no — policy, and the operator's
  // number to raise. Anything else is this holder failing to keep a block it already
  // admitted, which is a broken holder, not a full one: report it as such.
  try { await storeWrite(blockId, bytes, descriptor); return VERDICT_ACCEPTED; }
  catch (e) { return (e && e.quota) ? VERDICT_QUOTA : VERDICT_ERROR; }
}
// Serve a batched FETCH, but never emit much more than one message's worth of bytes:
// an honest requester caps itself at fetchMaxIds() so its whole response fits, but a
// hostile cohort member can name the same id thousands of times in one ~1 MB request
// and make this holder concat thousands × blockSize into one reply. Cap the served
// bytes at maxMsgBytes (accounting for the response framing). A block the holder has but
// that won't fit under the cap is tagged FETCH_UNANSWERED, so the reader re-requests
// exactly those (runFetchTasks); a block it doesn't have is ABSENT. The FIRST present
// block is served even when it alone exceeds the cap — the same single-over-cap-item rule
// as batchBytes — so every request a holder can serve at all makes progress: a requester
// whose config assumes a bigger cap than ours (the caps are per-node operator policy, so
// they can diverge) degrades to one block per round trip instead of an absent-forever
// block it verifiably holds. The DoS bound stays: one block + cap per request. A per-id
// memo keeps a repeated id from costing a fresh storeGet.
async function serveFetch(ids) {
  const cap = maxMsgBytes();
  const out = new Array(ids.length).fill(null);
  const seen = new Map(); // idHex → bytes|null, so a repeated id is one storeGet
  let used = 4;           // the [count u32] response header
  let servedAny = false;
  for (let i = 0; i < ids.length; i++) {
    const h = toHex(ids[i]);
    let bytes = seen.get(h);
    if (bytes === undefined) { const sb = await storeGet(ids[i]); bytes = sb ? sb.bytes : null; seen.set(h, bytes); }
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

// Dispatch one incoming control message: arg = [type u8][payload]. Async — every
// branch is local fs + crypto, and the fs seam is async (core/fs.ts), so the holder
// awaits its store ops like the initiator awaits its round trips. OFFER and FETCH
// carry a batch of blocks (one per peer per PUT/GET) and answer all at once.
//
// A STORE batch is processed SEQUENTIALLY, not in parallel: admission spends the
// §14 budget cumulatively across the batch (admitBatch's provisional accounting is
// the same rule, and a parallel fan-out would race `bytesUsed` — two blocks both
// seeing the pre-batch budget and both passing). A HAVE batch is independent reads
// and may fan out.
async function doHandle(arg) {
  // The call envelope is the guest ABI's, read with the preamble's own two functions
  // (seedkernel `host/guest-seam.ts`) rather than open-coded here — the same shape the
  // transport's `handle` reads, and the same one `shell.invoke` writes.
  const { fromHost, body } = callerOf(arg);
  // The host's loopback (caller = 32 zero bytes) drives the initiator ops, so `handle`
  // serves a peer's wire frame and the host's own local call alike. The op is a NAME;
  // a peer's frame is a MsgType BYTE, and the caller id is what tells the two framings
  // apart — the wire keeps a compact tag because it is a protocol with peers, while the
  // local vocabulary is an API and names itself.
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
      case Op.SCORE: return repScoreBytes(payload, clockNow());
      default: return EMPTY;
    }
  }
  const type = body[0], payload = body.slice(1);
  if (type === MSG_HAVE) return encodeMask((await Promise.all(decodeHaveReq(payload).map((id) => storeHas(id)))));
  if (type === MSG_OFFER) return encodeMask(await admitBatch(decodeOfferBatch(payload)));
  if (type === MSG_STORE) {
    const stores = decodeStoreBatch(payload);
    const verdicts = [];
    for (const s of stores) verdicts.push(await acceptStore(s.blockId, s.descriptor, s.bytes));
    return encodeMask(verdicts);
  }
  if (type === MSG_FETCH) return encodeFetchBatchRes(await serveFetch(decodeFetchBatchReq(payload)));
  return EMPTY;
}

// ── one control message, on the host's behalf ────────────────────────────────
// arg = [to 32][type u8][payload] — the mirror image of `handle`, and the ONLY way a
// host-side caller reaches a peer now. There is no host request facade left to route
// around: an app's send is a call to the id the transport claims (§12.10), so it leaves from
// in here or not at all, and a console line that wants to probe a holder asks this app to
// ask. It grants nothing new — the same netSend the placement engine drives unprompted,
// on this app's own protocol id — which is why it is a local op (Op.REQUEST) on the one
// `handle` rather than a second entrypoint.
//
// Answers `[ok u8][response]`: an unreachable peer is `[0]`, exactly as netSend reads it,
// so a caller distinguishes "declined" from "never arrived" without a rejection.
async function doRequest(arg) {
  const resp = await netSend(toHex(arg.slice(0, 32)), arg[32], arg.slice(33));
  return resp === null ? Uint8Array.from([0]) : concat([Uint8Array.from([1]), resp]);
}

// ── warm (boot-time JIT warmup) ──────────────────────────────────────────────
// One throwaway RS encode + decode + verify under a random key, with NO network
// and NO store, run once at boot. It pays V8's cold-JIT tax on the codec (RS) and
// crypto (XChaCha20 / BLAKE2b / Ed25519) caps up front, off the latency-sensitive
// path: the first real PUT encodes the WHOLE file before the first byte reaches
// the wire, so on a cold realm that tax (~0.25 s for a 10 MB PUT) lands entirely
// in front of the transfer. Self-contained and idempotent; the result is discarded.
async function doWarm() {
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
    // `r` is the chunk index, which is the NONCE counter (encrypt(K, level, globalCi, …)):
    // one key with a fixed counter would reuse one keystream every round, which is the
    // shape of a two-time pad. Nothing here leaves the realm and the plaintext is a
    // constant buffer, so there is nothing to leak — but this loop is the compact example
    // of "encrypt a sequence of chunks" in the file, and it should not be the one someone
    // copies. The counter advances, exactly as the real PUT path advances it.
    const chunk = await encodeChunk(buf, 0, r, K, LEVEL_BODY);                       // encrypt + RS-encode + hash + sign
    const sd = verifyDescriptor(chunk.descriptor);                               // Ed25519 verify (+ §16 scope preimage)
    // Reconstruct from the k data blocks to warm the GET-side decode seam too — at k ≥ 2
    // only, the same test the real path makes: a k = 1 deployment never reaches the codec
    // on PUT, GET, or repair, so there is no cold-JIT tax there to pay down.
    if (sd && sd.descriptor.k > 1) {
      await rsDecode(c.k, c.m, c.blockSize, chunk.slotBlocks.slice(0, c.k).map((bytes, index) => ({ index, bytes })));
    }
  }
  return EMPTY;
}

register("handle", doHandle);

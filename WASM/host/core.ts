// Shared types + deployment configuration for the storage layer (README §17).
// The protocol itself is the confined guest (host/tier2-guest.js); StorageNode
// runs it. This module only holds the identity + the durability/overhead dial
// every node agrees on.

export interface Identity {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** The durability/overhead dial, set once per deployment (§4.1, §27). */
export interface StorageConfig {
  k: number;
  m: number;
  blockSize: number;
  /** How many per-holder STORE sub-batches a PUT pushes concurrently
   *  (putWindow) and per-holder FETCH sub-batches a GET pulls
   *  (getWindow). OFFER/STORE/FETCH are batched per holder, so the round-trip
   *  count no longer scales with the file; these window the bulk transfers when a
   *  transport's frame cap splits a holder's blocks across many messages. The
   *  window binds hardest under a small cap (WebRTC's ~64 KB channel forces ~one
   *  block per STORE/FETCH): without it those messages would go one serial round
   *  trip per block. Under a large cap (WS) each holder has only a few big batches,
   *  so it is a no-op. With the genuinely-async guest seam the guest overlaps the
   *  round trips itself — one Promise.all over NET_SEND fires W per-peer requests at
   *  once (the host driving them concurrently) — so W bounds the peak in flight. */
  putWindow: number;
  getWindow: number;
  /** Max bytes in one batched OFFER/STORE/FETCH message. Every per-holder batch is
   *  split to stay under it, so a single message both fits the transport's frame cap
   *  AND transfers within the request timeout — and the holder (synchronous in the
   *  confined realm) only ever hashes/admits/serves one capped batch at a time. Set
   *  per transport: a WS/TCP frame holds up to 16 MB, but a multi-MB transfer can
   *  outrun a tight request timeout, so the default stays ~1 MB; a WebRTC data
   *  channel reassembles only ~64 KB, so the browser demo drops it to ~48 KB. (The
   *  browser picks the value from the connection mode.) */
  maxMessageBytes: number;
  /** Target plaintext bytes per streamed PUT/GET window (§3). The host driver feeds
   *  the guest one chunk-aligned window at a time and awaits it fully — OFFER, STORE,
   *  and acks — before the next, so the whole window's ciphertext is dropped before
   *  more plaintext crosses in and the guest heap never holds the file. Bigger windows
   *  mean fewer inter-window barriers (less link idle on a fat/low-loss path) but a
   *  larger peak guest footprint (≈ n/k× the window in ciphertext), so raise
   *  realmMemoryBytes alongside it. Always set (defaultConfig homes the 4 MiB default);
   *  the confined guest reads it from the injected APP and never keeps its own copy. */
  windowTargetBytes: number;
  /** Hard cap on the guest realm's QuickJS heap (safe-js default 64 MiB). Raise
   *  it to run larger windowTargetBytes without the guest OOMing. Host-only (passed to
   *  createSafeRealm, not injected into the guest APP). Omit for the default. */
  realmMemoryBytes?: number;
}

/** Default fan-out window for putWindow / getWindow: how many per-holder
 *  STORE/FETCH sub-batches are pushed/pulled concurrently. core.ts is the single home
 *  of the guest's config defaults — the confined guest reads the injected APP and keeps
 *  no copy of its own. */
export const DEFAULT_FANOUT_WINDOW = 16;

/** Default target plaintext bytes per streamed PUT/GET window (§3): 4 MiB. Homed here
 *  (not in the guest) for the same reason as DEFAULT_FANOUT_WINDOW. */
export const DEFAULT_WINDOW_TARGET_BYTES = 4 * 1024 * 1024;

/** The block size a real DEPLOYMENT uses — the single value the signed bundle and the
 *  CLI derive their geometry from, so "production geometry" is one named constant, not a
 *  magic number copied per site. 256 KiB keeps a k=2 codec request at the 512 KiB the
 *  deployed codec's scratch is proven on, and one block + framing well inside the default
 *  maxMessageBytes (the serveFetch response bound). The browser demo deliberately picks a
 *  per-transport size instead (bigger on WS, tiny on WebRTC's ~64 KiB channel), so it does
 *  NOT consume this — but see it referenced there for why those diverge. */
export const PRODUCTION_BLOCK_SIZE = 256 * 1024;

/** NB the bare blockSize default is TEST-SCALE — 256 bytes, so unit tests exercise
 *  multi-block chunking on tiny payloads. Anything producing a deployed config (the
 *  bundle producer, a demo page) must pass a real block size (PRODUCTION_BLOCK_SIZE);
 *  baking this default into a deployment chunks a 10 MB file into ~41k blocks. */
export function defaultConfig(k = 2, m = 2, blockSize = 256): StorageConfig {
  // (k, m, blockSize) is the whole of the durability dial. Everything derivable from it
  // is derived where it is used and never carried here, so it cannot drift out of step:
  // smallMaxBlocks in the guest (a write-side choice, §4.1), and the replica count
  // r = m + 1 plus the low-water mark ⌈m/2⌉ from each chunk's own SIGNED descriptor
  // (manifest-core's replicaTarget / lowWaterMargin), so a repairer needs no config
  // at all and a mixed-geometry cohort repairs each chunk to what its author signed.
  return {
    k,
    m,
    blockSize,
    putWindow: DEFAULT_FANOUT_WINDOW,
    getWindow: DEFAULT_FANOUT_WINDOW,
    // ~1 MiB: a batch transfers well inside a typical request timeout and keeps a
    // synchronous holder's per-message work small, while still collapsing per-block
    // round trips. A transport with a tighter frame cap (WebRTC) lowers it.
    maxMessageBytes: 1 << 20,
    windowTargetBytes: DEFAULT_WINDOW_TARGET_BYTES,
  };
}

/** peer_id is the hex of a peer's kernel public key (§2). */
export { type PeerId } from "seedkernel-wasm/net";

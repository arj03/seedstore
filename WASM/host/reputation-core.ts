// The reputation handler's request framing (assembly/reputation/index.ts ABI), in one
// place. The module is now a PURE TRANSFORM — the caller holds per-peer accumulators
// (serve, miss, last) and passes them in each request, receiving updated accumulators
// back. This enforces the PROTOCOL.md contract: WASM modules are restartable transforms
// (any timeout kills the instance), so callers cannot depend on module memory state.
// Only the confined guest frames requests now (repScore/repObserve, via a bare-name
// host.call): the module is private to the app's slot, so a host-side reading goes
// through the guest's own Op.SCORE. This module is imported by the host AND stitched into
// the Tier-2 guest (scripts/build-guest.mjs), so the two agree on the wire layout by
// construction, not by a hand-kept mirror.

import { writeU64BE, readU64BE } from "./util.js";

// Op bytes of the installed reputation handler (assembly/reputation/index.ts).
export const REP_OBSERVE = 1, REP_SCORE = 2;

/** SCORE request: read a peer's decayed reciprocity standing at time `tMs` (§13).
 *  Input: [op u8][serve f64 LE][miss f64 LE][last u64 BE][now u64 BE]
 *  Output: [score f64 LE] */
export function encodeScoreReq(serve: number, miss: number, lastMs: number, nowMs: number): Uint8Array {
  const req = new Uint8Array(1 + 8 + 8 + 8 + 8);
  req[0] = REP_SCORE;
  new DataView(req.buffer, req.byteOffset + 1, 8).setFloat64(0, serve, true);
  new DataView(req.buffer, req.byteOffset + 9, 8).setFloat64(0, miss, true);
  writeU64BE(req, 17, lastMs);
  writeU64BE(req, 25, nowMs);
  return req;
}

/** Decode SCORE response: just a score f64 LE. */
export function decodeScoreResp(buf: Uint8Array): number {
  if (buf.length < 8) return 0;
  return new DataView(buf.buffer, buf.byteOffset, 8).getFloat64(0, true);
}

/** OBSERVE request: record a witnessed pass/fail for a peer at time `tMs` (§8).
 *  Input: [op u8][serve f64 LE][miss f64 LE][last u64 BE][now u64 BE][result u8]
 *  Output: [serve f64 LE][miss f64 LE][last u64 BE][score f64 LE] */
export function encodeObserveReq(serve: number, miss: number, lastMs: number, nowMs: number, pass: boolean): Uint8Array {
  const req = new Uint8Array(1 + 8 + 8 + 8 + 8 + 1);
  req[0] = REP_OBSERVE;
  new DataView(req.buffer, req.byteOffset + 1, 8).setFloat64(0, serve, true);
  new DataView(req.buffer, req.byteOffset + 9, 8).setFloat64(0, miss, true);
  writeU64BE(req, 17, lastMs);
  writeU64BE(req, 25, nowMs);
  req[33] = pass ? 1 : 0;
  return req;
}

/** Decode OBSERVE response: updated accumulators and score. */
export interface ObserveResp {
  serve: number;
  miss: number;
  last: number;
  score: number;
}
export function decodeObserveResp(buf: Uint8Array): ObserveResp {
  if (buf.length < 32) return { serve: 0, miss: 0, last: 0, score: 0 };
  return {
    serve: new DataView(buf.buffer, buf.byteOffset, 8).getFloat64(0, true),
    miss: new DataView(buf.buffer, buf.byteOffset + 8, 8).getFloat64(0, true),
    last: readU64BE(buf, 16),
    score: new DataView(buf.buffer, buf.byteOffset + 24, 8).getFloat64(0, true),
  };
}

// Eviction mirrors assembly/reputation/index.ts's HALF_LIFE_MS/threshold (§13.1) as a
// housekeeping heuristic — callers hold the state now, so this is no longer wire format,
// and the two copies are not required to match bit-for-bit, only in spirit ("~16 weeks").
const PRUNE_HALF_LIFE_MS = 7 * 24 * 3600 * 1000;
const PRUNE_LN2 = 0.6931471805599453;
const PRUNE_MASS_THRESHOLD = 1 / 65536;

/** Evict every peer from `map` whose reciprocity mass, decayed forward to `now`, has
 *  fallen below 2^-16 of a single observation (≈16 half-lives ≈16 weeks for a once-seen
 *  peer) — bounds the caller's peer set the way the old module's prunePeers bounded its
 *  own arrays, now that the state lives outside the WASM memory ceiling that used to
 *  contain it. Call only when about to grow the set with a peer not already in it —
 *  re-observing a known peer should cost nothing extra. */
export function pruneStalePeers(map: Map<string, { serve: number; miss: number; last: number }>, now: number): void {
  for (const [key, rep] of map) {
    const dt = now - rep.last;
    const factor = dt > 0 ? Math.exp(-PRUNE_LN2 * dt / PRUNE_HALF_LIFE_MS) : 1;
    if ((rep.serve + rep.miss) * factor <= PRUNE_MASS_THRESHOLD) map.delete(key);
  }
}

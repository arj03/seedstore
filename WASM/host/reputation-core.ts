// The reputation handler's request framing (assembly/reputation/index.ts ABI), in
// one place. The module is a PURE TRANSFORM — the caller holds per-peer
// accumulators (serve, miss, last) and passes them in each request, since WASM
// modules are restartable (any timeout kills the instance). Imported by the host
// AND stitched into the Tier-2 guest, so the two agree on the wire layout by construction.

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

// Eviction mirrors assembly/reputation/index.ts's HALF_LIFE_MS/threshold (§13.1)
// as a housekeeping heuristic — not wire format, so the two need only match in
// spirit ("~16 weeks").
const PRUNE_HALF_LIFE_MS = 7 * 24 * 3600 * 1000;
const PRUNE_LN2 = 0.6931471805599453;
const PRUNE_MASS_THRESHOLD = 1 / 65536;

/** Evict every peer from `map` whose reciprocity mass, decayed to `now`, has
 *  fallen below 2^-16 of a single observation (~16 weeks for a once-seen peer).
 *  Call only when adding a peer not already in the set. */
export function pruneStalePeers(map: Map<string, { serve: number; miss: number; last: number }>, now: number): void {
  for (const [key, rep] of map) {
    const dt = now - rep.last;
    const factor = dt > 0 ? Math.exp(-PRUNE_LN2 * dt / PRUNE_HALF_LIFE_MS) : 1;
    if ((rep.serve + rep.miss) * factor <= PRUNE_MASS_THRESHOLD) map.delete(key);
  }
}

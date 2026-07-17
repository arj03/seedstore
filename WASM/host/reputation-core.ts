// The reputation handler's request framing (assembly/reputation/index.ts ABI), in one
// place. A reputation MODULE_CALL is [op u8][peerPk 32][t u64 BE] (+ a pass byte for
// OBSERVE). Both sides frame it: the host (StorageNode.score, via KernelHost.callHandler)
// and the confined guest (repScore/repObserve, via CAP_MODULE_CALL). This module is
// imported by the host AND stitched into the Tier-2 guest (scripts/build-guest.mjs), so
// the two agree on the wire layout by construction, not by a hand-kept mirror.

import { writeU64BE } from "./util.js";

// Op bytes of the installed reputation handler (assembly/reputation/index.ts).
export const REP_OBSERVE = 1, REP_SCORE = 2;

/** SCORE request: read a peer's decayed reciprocity standing at time `tMs` (§13). */
export function encodeScoreReq(peerPk: Uint8Array, tMs: number): Uint8Array {
  const req = new Uint8Array(41);
  req[0] = REP_SCORE;
  req.set(peerPk, 1);
  writeU64BE(req, 33, tMs);
  return req;
}

/** OBSERVE request: record a witnessed pass/fail for a peer at time `tMs` (§8). */
export function encodeObserveReq(peerPk: Uint8Array, tMs: number, pass: boolean): Uint8Array {
  const req = new Uint8Array(42);
  req[0] = REP_OBSERVE;
  req.set(peerPk, 1);
  writeU64BE(req, 33, tMs);
  req[41] = pass ? 1 : 0;
  return req;
}

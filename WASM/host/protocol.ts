// Control-plane message catalog (README §18) for the storage RPC carried over
// net.send. Each message is a small typed request/response; the bulk block
// bytes ride the bulk plane (§3) as unsigned, hash-verified frames, except for
// FETCH responses which return the (small, §27) block over the same channel and
// are still validated by genesis_hash(bytes) == block_id by the reader (§4.2).

import { writeU32BE, readU32BE, concatBytes } from "./util.js";

export const MsgType = {
  HAVE: 1,   // disc.have / disc.want (§5)
  OFFER: 2,  // block.offer → block.accept/decline (§6)
  FETCH: 3,  // block.fetch_req → block.data (§7, also the §8 verification-fetch)
  STORE: 4,  // the push after accept (§6 step 4). In the base bulk plane this is
             // an unsigned, hash-verified frame (§3); here it is an awaited
             // request so placement is deterministic. A dedicated bulk channel
             // (§22) is the throughput upgrade.
} as const;

// ── HAVE (disc.have/want, §5) ──────────────────────────────────────────────
// "I want these block_ids" / "of those, here is what I hold." A have/want only
// ever names ids the asker already holds — there is no list-all (§5.2).
export function encodeHaveReq(ids: Uint8Array[]): Uint8Array {
  const head = new Uint8Array(4);
  writeU32BE(head, 0, ids.length);
  return concatBytes([head, ...ids]);
}
export function decodeHaveReq(buf: Uint8Array): Uint8Array[] {
  const count = readU32BE(buf, 0);
  const out: Uint8Array[] = [];
  for (let i = 0; i < count; i++) out.push(buf.slice(4 + i * 32, 4 + (i + 1) * 32));
  return out;
}
export function encodeHaveRes(held: boolean[]): Uint8Array {
  const out = new Uint8Array(held.length);
  for (let i = 0; i < held.length; i++) out[i] = held[i] ? 1 : 0;
  return out;
}
export function decodeHaveRes(buf: Uint8Array): boolean[] {
  return Array.from(buf, (b) => b === 1);
}

// ── OFFER (block.offer, §6) ────────────────────────────────────────────────
// Carries block_id, size, and the signed chunk descriptor so the holder can
// verify it and enforce the no-two-blocks-of-a-chunk-same-holder rule (§6).
export interface Offer {
  blockId: Uint8Array;
  size: number;
  descriptor: Uint8Array | null; // signed descriptor env; null for a bare replica (manifest)
}
export function encodeOffer(o: Offer): Uint8Array {
  const head = new Uint8Array(32 + 4 + 4);
  head.set(o.blockId, 0);
  writeU32BE(head, 32, o.size);
  const desc = o.descriptor ?? new Uint8Array(0);
  writeU32BE(head, 36, desc.length);
  return concatBytes([head, desc]);
}
export function decodeOffer(buf: Uint8Array): Offer {
  const blockId = buf.slice(0, 32);
  const size = readU32BE(buf, 32);
  const dlen = readU32BE(buf, 36);
  const descriptor = dlen > 0 ? buf.slice(40, 40 + dlen) : null;
  return { blockId, size, descriptor };
}
export const OFFER_ACCEPT = new Uint8Array([1]);
export const OFFER_DECLINE = new Uint8Array([0]);

// ── STORE (the push, §6 step 4) ─────────────────────────────────────────────
export interface StoreReq {
  blockId: Uint8Array;
  descriptor: Uint8Array | null;
  bytes: Uint8Array;
}
export function encodeStore(s: StoreReq): Uint8Array {
  const head = new Uint8Array(32 + 4);
  head.set(s.blockId, 0);
  const desc = s.descriptor ?? new Uint8Array(0);
  writeU32BE(head, 32, desc.length);
  return concatBytes([head, desc, s.bytes]);
}
export function decodeStore(buf: Uint8Array): StoreReq {
  const blockId = buf.slice(0, 32);
  const dlen = readU32BE(buf, 32);
  const descriptor = dlen > 0 ? buf.slice(36, 36 + dlen) : null;
  const bytes = buf.slice(36 + dlen);
  return { blockId, descriptor, bytes };
}
export const STORE_OK = new Uint8Array([1]);
export const STORE_FAIL = new Uint8Array([0]);

// ── FETCH (block.fetch_req / block.data, §7, §8) ────────────────────────────
export function encodeFetchReq(blockId: Uint8Array): Uint8Array {
  return blockId.slice();
}
export function encodeFetchRes(bytes: Uint8Array | null): Uint8Array {
  if (!bytes) return new Uint8Array([0]);
  const out = new Uint8Array(1 + bytes.length);
  out[0] = 1;
  out.set(bytes, 1);
  return out;
}
export function decodeFetchRes(buf: Uint8Array): Uint8Array | null {
  if (buf.length < 1 || buf[0] !== 1) return null;
  return buf.slice(1);
}

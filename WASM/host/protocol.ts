// Control-plane message catalog (README §18) for the storage RPC carried over
// net.send. Each message is a small typed request/response; the bulk block
// bytes ride the bulk plane (§3) as unsigned, hash-verified frames, except for
// FETCH responses which return the (small, §27) blocks over the same channel and
// are still validated by genesis_hash(bytes) == block_id by the reader (§4.2).
//
// OFFER and FETCH are *batched*: one OFFER lists every block headed to a peer and
// the holder replies a per-block verdict (quota + the §6 sibling rule
// evaluated over the whole batch); one FETCH names every block wanted from a peer
// and the holder returns them together. That collapses N per-block control round
// trips (and N QuickJS holder invocations) into one per peer. STORE stays
// per-block — its bytes are the bandwidth, and it is the binding admission point
// (content-address + sibling + quota are re-checked there, §4.2/§6/§14), so the
// batched OFFER is an advisory pre-check, never the enforcement.

import { writeU32BE, readU32BE, concatBytes } from "./util.js";

export const MsgType = {
  HAVE: 1,   // disc.have / disc.want (§5)
  OFFER: 2,  // block.offer (batched) → accept-mask (§6)
  FETCH: 3,  // block.fetch_req (batched) → block.data[] (§7, also the §8 verification-fetch)
  STORE: 4,  // the push after accept (§6 step 4). In the base bulk plane this is
             // an unsigned, hash-verified frame (§3); here it is an awaited
             // request so placement is deterministic. A dedicated bulk channel
             // (§22) is the throughput upgrade.
} as const;

// ── the response mask shared by HAVE, OFFER, and STORE ──────────────────────
// All three replies are the same shape: one byte per batch entry. HAVE's is
// "held" (1/0), OFFER's is a VERDICT_* code, STORE's is a VERDICT_* code —
// one codec, three uses. A verdict ≠ 1 is a decline; codes 2–4 carry advisory
// diagnostics (quota, sibling, descriptor-rejected) that turn the initiator's
// error from a guessing essay into an exact report.
export function encodeMask(bits: (boolean | number)[]): Uint8Array {
  const out = new Uint8Array(bits.length);
  for (let i = 0; i < bits.length; i++) {
    const v = bits[i];
    out[i] = typeof v === "boolean" ? (v ? 1 : 0) : v;
  }
  return out;
}
export function decodeMask(buf: Uint8Array): number[] {
  return Array.from(buf);
}

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
  const need = 4 + count * 32;
  if (buf.length < need) throw new Error("protocol: decodeHaveReq truncated");
  const out: Uint8Array[] = [];
  for (let i = 0; i < count; i++) out.push(buf.slice(4 + i * 32, 4 + (i + 1) * 32));
  return out;
}
// The HAVE response ("of those, here is what I hold") is a plain held-mask —
// encodeMask / decodeMask above.

// ── OFFER (block.offer, §6) ────────────────────────────────────────────────
// Each entry carries block_id and the signed chunk descriptor so the holder can
// verify it and enforce the no-two-blocks-of-a-chunk-same-holder rule (§6). A batch
// is a count followed by the self-delimiting entries; the response is one accept
// byte per entry.
//
// The descriptor is MANDATORY — §4.3's "every peer that accepts a block first
// verifies its descriptor" is only true if there is no way to offer a block without
// one. A descriptor-less entry is a malformed message, rejected by the decoder, not
// a block admitted on quota alone.
//
// There is no size field: a block is exactly `descriptor.blockSize` bytes (padding
// guarantees it, and the replicated manifest chunk signs blockSize = its ciphertext
// length), so a size on the wire would be an unauthenticated restatement of signed
// geometry — free to disagree with it. The holder charges its §14 quota from the
// descriptor instead.
export interface Offer {
  blockId: Uint8Array;
  descriptor: Uint8Array; // signed chunk-descriptor envelope (§4.3) — never absent
}
function encodeOfferEntry(o: Offer): Uint8Array {
  const head = new Uint8Array(32 + 4);
  head.set(o.blockId, 0);
  writeU32BE(head, 32, o.descriptor.length);
  return concatBytes([head, o.descriptor]);
}
export function encodeOfferBatch(offers: Offer[]): Uint8Array {
  const head = new Uint8Array(4);
  writeU32BE(head, 0, offers.length);
  return concatBytes([head, ...offers.map(encodeOfferEntry)]);
}
export function decodeOfferBatch(buf: Uint8Array): Offer[] {
  const count = readU32BE(buf, 0);
  if (buf.length < 4) throw new Error("protocol: decodeOfferBatch truncated header");
  const out: Offer[] = [];
  let o = 4;
  for (let i = 0; i < count; i++) {
    if (o + 36 > buf.length) throw new Error("protocol: decodeOfferBatch truncated entry");
    const blockId = buf.slice(o, o + 32);
    const dlen = readU32BE(buf, o + 32);
    if (dlen === 0) throw new Error("protocol: decodeOfferBatch missing descriptor");
    if (o + 36 + dlen > buf.length) throw new Error("protocol: decodeOfferBatch truncated descriptor");
    out.push({ blockId, descriptor: buf.slice(o + 36, o + 36 + dlen) });
    o += 36 + dlen;
  }
  return out;
}
// The OFFER response verdict codes (§18): one byte per entry.
//  1 = accepted. 0 = declined. Diagnostic codes > 1 are advisory — a holder
//  may lie, so the reason is never policy (no new trust surface), but the error
//  a failed PUT throws becomes exact instead of an essay of guesses.
export const VERDICT_DECLINED   = 0;
export const VERDICT_ACCEPTED   = 1;
export const VERDICT_QUOTA      = 2; // §14 quota exhausted
export const VERDICT_SIBLING    = 3; // §6 sibling already held
export const VERDICT_DESCRIPTOR = 4; // descriptor verify failed (§4.3)

// ── STORE (the push, §6 step 4) ─────────────────────────────────────────────
// Batched per holder: every block headed to a peer streams in one message, and
// the holder replies a per-block verdict. Each entry carries its own
// descriptor + bytes (different chunks → different descriptors in one batch). This
// is the upload twin of the batched FETCH download — one streamed transfer + one
// ack instead of a request/response per block. STORE is still the BINDING
// admission point: the holder hash-verifies (§4.2) and admits (§6/§14) EVERY block
// in the batch (acceptStore), so batching changes only the framing, not the gate.
// The byte length here is framing (the entry is self-delimiting); the holder still
// checks it against the descriptor's signed blockSize before admitting.
export interface StoreReq {
  blockId: Uint8Array;
  descriptor: Uint8Array; // signed chunk-descriptor envelope (§4.3) — never absent, as for OFFER
  bytes: Uint8Array;
}
export function encodeStoreBatch(stores: StoreReq[]): Uint8Array {
  const head = new Uint8Array(4);
  writeU32BE(head, 0, stores.length);
  const parts: Uint8Array[] = [head];
  for (const s of stores) {
    const h = new Uint8Array(32 + 4 + 4);
    h.set(s.blockId, 0);
    writeU32BE(h, 32, s.descriptor.length);
    writeU32BE(h, 36, s.bytes.length);
    parts.push(h, s.descriptor, s.bytes);
  }
  return concatBytes(parts);
}
export function decodeStoreBatch(buf: Uint8Array): StoreReq[] {
  const count = readU32BE(buf, 0);
  if (buf.length < 4) throw new Error("protocol: decodeStoreBatch truncated header");
  const out: StoreReq[] = [];
  let o = 4;
  for (let i = 0; i < count; i++) {
    if (o + 40 > buf.length) throw new Error("protocol: decodeStoreBatch truncated entry");
    const blockId = buf.slice(o, o + 32);
    const dlen = readU32BE(buf, o + 32);
    const blen = readU32BE(buf, o + 36);
    if (dlen === 0) throw new Error("protocol: decodeStoreBatch missing descriptor");
    if (o + 40 + dlen + blen > buf.length) throw new Error("protocol: decodeStoreBatch truncated data");
    const descriptor = buf.slice(o + 40, o + 40 + dlen);
    const bytes = buf.slice(o + 40 + dlen, o + 40 + dlen + blen);
    out.push({ blockId, descriptor, bytes });
    o += 40 + dlen + blen;
  }
  return out;
}
// The STORE response is a per-block verdict — encodeMask / decodeMask above.

// ── FETCH (block.fetch_req / block.data, §7, §8) ────────────────────────────
// A batch names every block wanted from one peer; the response returns them in
// request order, each tagged by a found byte the reader acts on directly. Each
// returned block is still hash-verified by the reader (§4.2) — the holder is
// never trusted to have served the right bytes.
//
// The found byte has three states, so "didn't serve" and "couldn't fit" are distinct
// on the wire and the reader need not infer cap-truncation from the response's shape:
//   1 PRESENT     — the block follows as [len u32][bytes].
//   0 ABSENT      — a genuine miss; the reader falls to another holder.
//   2 UNANSWERED  — the holder has the block but its own per-response byte cap
//                   (maxMessageBytes, per-node operator policy, so caps diverge) left
//                   no room for it. The reader re-requests exactly these as a fresh
//                   FETCH, never treating them as misses.
export const FETCH_ABSENT = 0, FETCH_PRESENT = 1, FETCH_UNANSWERED = 2;

/** One FETCH response entry: the block bytes if PRESENT, null for a genuine miss
 *  (ABSENT), or the FETCH_UNANSWERED marker when the holder has the block but its
 *  response cap left no room (re-ask). serveFetch produces these; runFetchTasks acts
 *  on them. */
export type FetchEntry = Uint8Array | null | typeof FETCH_UNANSWERED;

export function encodeFetchBatchReq(ids: Uint8Array[]): Uint8Array {
  const head = new Uint8Array(4);
  writeU32BE(head, 0, ids.length);
  return concatBytes([head, ...ids]);
}
export function decodeFetchBatchReq(buf: Uint8Array): Uint8Array[] {
  const count = readU32BE(buf, 0);
  const need = 4 + count * 32;
  if (buf.length < need) throw new Error("protocol: decodeFetchBatchReq truncated");
  const out: Uint8Array[] = [];
  for (let i = 0; i < count; i++) out.push(buf.slice(4 + i * 32, 4 + (i + 1) * 32));
  return out;
}
export function encodeFetchBatchRes(blocks: FetchEntry[]): Uint8Array {
  const head = new Uint8Array(4);
  writeU32BE(head, 0, blocks.length);
  const parts: Uint8Array[] = [head];
  for (const b of blocks) {
    if (b === FETCH_UNANSWERED) { parts.push(new Uint8Array([FETCH_UNANSWERED])); continue; }
    if (!b) { parts.push(new Uint8Array([FETCH_ABSENT])); continue; }
    const h = new Uint8Array(5);
    h[0] = FETCH_PRESENT;
    writeU32BE(h, 1, b.length);
    parts.push(h, b);
  }
  return concatBytes(parts);
}
export function decodeFetchBatchRes(buf: Uint8Array): FetchEntry[] {
  const count = readU32BE(buf, 0);
  if (buf.length < 4) throw new Error("protocol: decodeFetchBatchRes truncated header");
  const out: FetchEntry[] = [];
  let o = 4;
  for (let i = 0; i < count; i++) {
    if (o >= buf.length) throw new Error("protocol: decodeFetchBatchRes truncated found");
    const found = buf[o]; o += 1;
    if (found === FETCH_UNANSWERED) { out.push(FETCH_UNANSWERED); continue; }
    if (found !== FETCH_PRESENT) { out.push(null); continue; }
    if (o + 4 > buf.length) throw new Error("protocol: decodeFetchBatchRes truncated len");
    const len = readU32BE(buf, o); o += 4;
    if (o + len > buf.length) throw new Error("protocol: decodeFetchBatchRes truncated block");
    out.push(buf.slice(o, o + len)); o += len;
  }
  return out;
}

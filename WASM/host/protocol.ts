// Control-plane message catalog (README §18) for the storage RPC carried over
// net.send.
//
// OFFER and FETCH are *batched*: one OFFER lists every block headed to a peer,
// answered with a per-block verdict; one FETCH names every block wanted from a
// peer, returned together — collapsing N round trips into one per peer. STORE
// stays per-block and is the BINDING admission point (re-checked there, §4.2/§6/
// §14); the batched OFFER is only an advisory pre-check.

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

// ── the initiator's LOCAL op names (the host's loopback vocabulary) ──────────
// The storage protocol has one entrypoint, `handle`, reached two ways (seedkernel
// §12.2): a peer's inbound frame carries `[peer 32][MsgType u8][payload]`; the
// host's own loopback carries `[zero 32][opLen u8][opName][payload]` — the caller
// id tells the two framings apart. The op is a NAME, not a number, so a generic
// caller (the seedkernel CLI's `--op`) and StorageNode both address it without
// agreeing on a tag byte.
export const Op = {
  PUT: "put",               // whole-file: [plaintext ..] → the PutResult envelope
  PUT_START: "putStart",    // open the stream → [windowBytes u32]
  PUT_WINDOW: "putWindow",  // feed one window of plaintext
  PUT_FINISH: "putFinish",  // seal the stream → the PutResult envelope
  GET: "get",               // whole-file: [K 32][root ..] → plaintext
  GET_START: "getStart",    // open the stream: [K 32][root ..] → [fileSize u64]
  GET_NEXT: "getNext",      // the next window of plaintext
  REPAIR: "repair",         // one repair pass → [replaced u32]
  REQUEST: "request",       // one control-plane message: [peer 32][type u8][payload] → [ok u8][resp]
  SCORE: "score",           // this node's decayed standing for a peer: [peer 32] → [score f64 LE]
  WARM: "warm",             // JIT warm-up, no result
  STATS: "stats",           // request counters, read-and-cleared: → `RequestStats` (below)
} as const;

// ── the STATS op wire format (§18) ──────────────────────────────────────────
// The request counters live in the guest (the host has no inbound seam of its
// own). One fixed record per MsgType, in `STATS_TYPES` order:
//   [sent u32][sentPeak u32][recv u32][recvBytes u32][recvMs f64 LE]
// `sent`/`sentPeak` are this node's issued requests + peak in-flight; `recv*` is
// what it answered as a holder.
export const STATS_TYPES = [MsgType.HAVE, MsgType.OFFER, MsgType.FETCH, MsgType.STORE] as const;
export const STATS_RECORD_BYTES = 24;

export interface RequestStats {
  sent: number;       // requests issued
  sentPeak: number;   // peak concurrent requests of this type (sender-side window/fan-out)
  recv: number;       // requests answered (holder side)
  recvBytes: number;  // payload bytes of those
  recvMs: number;     // total processing time inside the guest's `handle`, ms
}

export function decodeStats(buf: Uint8Array): Map<number, RequestStats> {
  const out = new Map<number, RequestStats>();
  for (let i = 0; i < STATS_TYPES.length; i++) {
    const t = STATS_TYPES[i];
    const o = i * STATS_RECORD_BYTES;
    out.set(t, {
      sent: readU32BE(buf, o),
      sentPeak: readU32BE(buf, o + 4),
      recv: readU32BE(buf, o + 8),
      recvBytes: readU32BE(buf, o + 12),
      recvMs: new DataView(buf.buffer, buf.byteOffset + o + 16, 8).getFloat64(0, true),
    });
  }
  return out;
}

// ── the response mask shared by HAVE, OFFER, and STORE ──────────────────────
// All three replies are the same shape: one byte per batch entry (HAVE: held
// 1/0; OFFER/STORE: a VERDICT_* code). A verdict ≠ 1 is a decline; codes 2-5
// carry advisory diagnostics for an exact initiator error message.
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
// verify it and enforce the sibling rule (§6). A batch is a count + self-delimiting
// entries; response is one accept byte per entry.
//
// The descriptor is MANDATORY — a descriptor-less entry is a malformed message,
// rejected by the decoder, never a block admitted on quota alone. No size field
// either: a block is exactly `descriptor.blockSize` bytes, so a wire size would be
// an unauthenticated restatement of signed geometry.
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
// The holder ADMITTED the block and then failed to commit it (full disk, backend
// error, realm OOM) — distinct from VERDICT_QUOTA since one is a policy number to
// raise and the other a broken holder to inspect.
export const VERDICT_ERROR      = 5;

// ── STORE (the push, §6 step 4) ─────────────────────────────────────────────
// Batched per holder: every block headed to a peer streams in one message,
// answered with a per-block verdict — the upload twin of batched FETCH. Still
// the BINDING admission point: the holder hash-verifies (§4.2) and admits (§6/
// §14) EVERY block, so batching changes only the framing, not the gate.
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
// request order, each tagged by a found byte. Each block is still hash-verified
// by the reader (§4.2) — the holder is never trusted to have served the right bytes.
//
// The found byte has three states, so "didn't serve" and "couldn't fit" are distinct:
//   1 PRESENT     — the block follows as [len u32][bytes].
//   0 ABSENT      — a genuine miss; the reader falls to another holder.
//   2 UNANSWERED  — the holder has it but its own response byte cap left no room;
//                   the reader re-requests it fresh, never as a miss.
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

// The holder's durable record (SPEC §12): one `<block id hex>.rec` per block,
//   [descriptor length u32 BE][descriptor][ciphertext]
// Written by the guest holder (stitched in by scripts/build-guest.mjs) and read back
// host-side by store-view.ts, so the layout has one definition.

import { readU32BE, writeU32BE, toHex, fromHex } from "./util.js";
import { GROUP_MAX, groupBytes, groupName } from "./descriptor-core.js";

export const STORE_REC = ".rec";
export const STORE_REC_HEAD = 4;

/** What a holder keeps for one block: the ciphertext and the signed descriptor
 *  envelope its chunk travels under (§4.3). The descriptor is stored verbatim
 *  so a repairer that lacks the file's index still has the chunk's shape. */
export interface StoredBlock {
  bytes: Uint8Array;
  /** The author-signed chunk-descriptor envelope (wire bytes). Every block has one:
   *  the §18 placement messages make it mandatory, an index chunk's blocks included. */
  descriptor: Uint8Array;
}

/** The record's head; the descriptor and ciphertext follow it. */
export function storeRecordHead(descriptorLength: number): Uint8Array {
  const head = new Uint8Array(STORE_REC_HEAD);
  writeU32BE(head, 0, descriptorLength);
  return head;
}

// Beside a record that changed tier, `<block id hex>.tag`: [tier u8][author public key
// 32][group], the §14 tier, and the author and group whose allowance the block counts
// against (§13.2). A record without one is committed, under its descriptor's.
export const STORE_TAG = ".tag";
export const TIER_COMMITTED = 0, TIER_CACHE = 1;
export const STORE_TAG_MAX = 1 + 32 + GROUP_MAX;

export function encodeStoreTag(tier: number, author: Uint8Array, group: string): Uint8Array {
  const name = groupBytes(group);
  const tag = new Uint8Array(1 + 32 + name.length);
  tag[0] = tier;
  tag.set(author.subarray(0, 32), 1);
  tag.set(name, 33);
  return tag;
}

/** The tag's tier, author and group, or null for a missing or malformed tag. */
export function decodeStoreTag(tag: Uint8Array | null): { tier: number; author: Uint8Array; group: string } | null {
  if (!tag || tag.length < 34 || tag.length > STORE_TAG_MAX || (tag[0] !== TIER_COMMITTED && tag[0] !== TIER_CACHE)) return null;
  let group: string;
  try { group = groupName(tag.subarray(33)); } catch { return null; }
  return { tier: tag[0], author: tag.subarray(1, 33), group };
}

/** Views into `rec`, or null for a record too short to hold its own descriptor. */
export function decodeStoreRecord(rec: Uint8Array | null): StoredBlock | null {
  if (!rec || rec.length < STORE_REC_HEAD) return null;
  const dlen = readU32BE(rec, 0);
  if (dlen === 0 || dlen > rec.length - STORE_REC_HEAD) return null;
  return { descriptor: rec.subarray(STORE_REC_HEAD, STORE_REC_HEAD + dlen), bytes: rec.subarray(STORE_REC_HEAD + dlen) };
}

// `store.idx`: the holder's index, saved so a restart reads it instead of every record. The
// listing decides what is held; a row only says what a record charges, which its id fixes,
// so a row whose record is gone is ignored and a record with no row is read. Layout:
// [version u8][authors u32][author 32]… [groups u32]{[len u8][group]}…
// [rows u32]{[block id 32][size u32][author index u32][group index u32]}…
export const STORE_INDEX = "store.idx";
const INDEX_VERSION = 1, INDEX_ROW = 32 + 12;

/** `id` is the block id's bytes, kept once known so a save need not decode the hex again. */
export interface IndexEntry { size: number; author: string; group: string; id?: Uint8Array }

export function encodeStoreIndex(rows: Iterable<[string, IndexEntry]>): Uint8Array {
  const authors = new Map<string, number>(), groups = new Map<string, number>(), list: [string, IndexEntry][] = [];
  let groupLen = 0;
  for (const row of rows) {
    const e = row[1];
    if (!authors.has(e.author)) authors.set(e.author, authors.size);
    if (!groups.has(e.group)) { groups.set(e.group, groups.size); groupLen += 1 + e.group.length; }
    list.push(row);
  }
  const out = new Uint8Array(1 + 4 + authors.size * 32 + 4 + groupLen + 4 + list.length * INDEX_ROW);
  let o = 0;
  out[o++] = INDEX_VERSION;
  writeU32BE(out, o, authors.size); o += 4;
  for (const a of authors.keys()) { out.set(fromHex(a), o); o += 32; }
  writeU32BE(out, o, groups.size); o += 4;
  for (const g of groups.keys()) { const b = groupBytes(g); out[o++] = b.length; out.set(b, o); o += b.length; }
  writeU32BE(out, o, list.length); o += 4;
  for (const [h, e] of list) {
    out.set(e.id ?? (e.id = fromHex(h)), o);
    writeU32BE(out, o + 32, e.size);
    writeU32BE(out, o + 36, authors.get(e.author)!);
    writeU32BE(out, o + 40, groups.get(e.group)!);
    o += INDEX_ROW;
  }
  return out;
}

/** Block hex → what its record charges, or null for a missing, torn or foreign index. */
export function decodeStoreIndex(buf: Uint8Array | null): Map<string, IndexEntry> | null {
  if (!buf || buf.length < 13 || buf[0] !== INDEX_VERSION) return null;
  try {
    let o = 1;
    const take = (n: number) => { if (o + n > buf.length) throw new Error("store index: torn"); const at = o; o += n; return at; };
    const na = readU32BE(buf, take(4)), authors: string[] = [];
    for (let i = 0; i < na; i++) { const at = take(32); authors.push(toHex(buf.subarray(at, at + 32))); }
    const ng = readU32BE(buf, take(4)), groups: string[] = [];
    for (let i = 0; i < ng; i++) { const len = buf[take(1)], at = take(len); groups.push(groupName(buf.subarray(at, at + len))); }
    const n = readU32BE(buf, take(4));
    if (o + n * INDEX_ROW !== buf.length) return null;
    const out = new Map<string, IndexEntry>();
    for (let i = 0; i < n; i++, o += INDEX_ROW) {
      const ai = readU32BE(buf, o + 36), gi = readU32BE(buf, o + 40);
      if (ai >= na || gi >= ng) return null;
      const id = buf.slice(o, o + 32);
      out.set(toHex(id), { size: readU32BE(buf, o + 32), author: authors[ai], group: groups[gi], id });
    }
    return out;
  } catch { return null; }
}

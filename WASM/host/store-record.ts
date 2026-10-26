// The holder's durable record (SPEC §12): one `<block id hex>.rec` per block,
//   [descriptor length u32 BE][descriptor][ciphertext]
// Written by the guest holder (stitched in by scripts/build-guest.mjs) and read back
// host-side by store-view.ts, so the layout has one definition.

import { readU32BE, writeU32BE } from "./util.js";
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

// Beside each record, `<block id hex>.tag`: [tier u8][author public key 32][group], the
// §14 tier, and the author and group whose allowance the block counts against (§13.2).
// It is written first, so a record without one never committed and is not held.
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

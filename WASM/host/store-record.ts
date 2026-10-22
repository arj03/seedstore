// The holder's durable record (SPEC §12): one `<block id hex>.rec` per block,
//   [descriptor length u32 BE][descriptor][ciphertext]
// Written by the guest holder (stitched in by scripts/build-guest.mjs) and read back
// host-side by store-view.ts, so the layout has one definition.

import { readU32BE, writeU32BE } from "./util.js";

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

/** Views into `rec`, or null for a record too short to hold its own descriptor. */
export function decodeStoreRecord(rec: Uint8Array | null): StoredBlock | null {
  if (!rec || rec.length < STORE_REC_HEAD) return null;
  const dlen = readU32BE(rec, 0);
  if (dlen === 0 || dlen > rec.length - STORE_REC_HEAD) return null;
  return { descriptor: rec.subarray(STORE_REC_HEAD, STORE_REC_HEAD + dlen), bytes: rec.subarray(STORE_REC_HEAD + dlen) };
}

// store.local backend (README §12). The donated blob store: opaque
// (block_id → ciphertext) pairs plus the small signed chunk descriptor that
// travels with every block (§4.3). The protocol is identical across hosts;
// only the backend differs — a directory on a server, OPFS/IndexedDB in a
// browser, or this in-memory map for tests and ephemeral nodes.
//
// A holder learns nothing about what it stores beyond the chunk shape: ids are
// hashes of random-key ciphertext (§4.4), and the value is ciphertext.

import { toHex, fromHex } from "./util.js";

/** What a holder keeps for one block: the ciphertext and the signed descriptor
 *  envelope its chunk travels under (§4.3). The descriptor is stored verbatim
 *  so a repairer that lacks the manifest still has the chunk's shape. */
export interface StoredBlock {
  bytes: Uint8Array;
  /** The author-signed chunk-descriptor envelope (wire bytes), or null if the
   *  caller stored a bare block (e.g. a replicated manifest block). */
  descriptor: Uint8Array | null;
}

export interface StoreStat {
  quota: number;
  used: number;
  free: number;
}

/** The donated blob store. All ids are 32-byte block_ids; keys are their hex. */
export interface BlobStore {
  put(id: Uint8Array, bytes: Uint8Array, descriptor: Uint8Array | null): void;
  get(id: Uint8Array): StoredBlock | null;
  has(id: Uint8Array): boolean;
  delete(id: Uint8Array): boolean;
  /** All stored ids (optionally restricted to a hex prefix). */
  list(prefix?: string): Uint8Array[];
  stat(): StoreStat;
}

/** In-memory store. Quota is a byte budget; put past it throws so the caller
 *  (admission control, §14) refuses the offer rather than over-committing. */
export class MemoryBlobStore implements BlobStore {
  private map = new Map<string, StoredBlock>();
  private bytesUsed = 0;
  constructor(public quota = 64 * 1024 * 1024) {}

  put(id: Uint8Array, bytes: Uint8Array, descriptor: Uint8Array | null): void {
    const key = toHex(id);
    const prev = this.map.get(key);
    const prevSize = prev ? prev.bytes.length : 0;
    const next = this.bytesUsed - prevSize + bytes.length;
    if (next > this.quota) throw new Error("store.local: quota exceeded");
    this.map.set(key, { bytes: bytes.slice(), descriptor: descriptor ? descriptor.slice() : null });
    this.bytesUsed = next;
  }
  get(id: Uint8Array): StoredBlock | null {
    const v = this.map.get(toHex(id));
    if (!v) return null;
    return { bytes: v.bytes.slice(), descriptor: v.descriptor ? v.descriptor.slice() : null };
  }
  has(id: Uint8Array): boolean { return this.map.has(toHex(id)); }
  delete(id: Uint8Array): boolean {
    const key = toHex(id);
    const v = this.map.get(key);
    if (!v) return false;
    this.bytesUsed -= v.bytes.length;
    return this.map.delete(key);
  }
  list(prefix?: string): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (const key of this.map.keys()) {
      if (prefix && !key.startsWith(prefix)) continue;
      out.push(fromHex(key));
    }
    return out;
  }
  stat(): StoreStat {
    return { quota: this.quota, used: this.bytesUsed, free: Math.max(0, this.quota - this.bytesUsed) };
  }
}

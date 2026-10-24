// The host's READ VIEW of what this node's holder has stored (SPEC §12).
//
// The confined guest holder owns store.local outright (admission, quota, the
// `<hex>.rec` layout — store-record.ts). This module implements NONE of that policy —
// no put, no delete — only reads the layout back for a host-side caller (tests, demo
// counts, operator scripts).
// Reads the backend live rather than caching, since the guest writes out of band.

import { toHex, fromHex } from "./util.js";
import { STORE_REC as REC, decodeStoreRecord, type StoredBlock } from "./store-record.js";
import type { Fs } from "seedkernel-wasm/fs";

export type { StoredBlock };

/** A read-only view of the holder's blobs. All ids are 32-byte block_ids; keys are
 *  their hex. There is no write half by design — see the header. Synchronous, as the
 *  `fs` seam it reads through is (seedkernel services/fs.ts). */
export interface BlobView {
  get(id: Uint8Array): StoredBlock | null;
  has(id: Uint8Array): boolean;
  /** All stored ids (optionally restricted to a hex prefix). */
  list(prefix?: string): Uint8Array[];
  /** Committed-tier bytes on the backend (§14): every `.rec`. What the holder
   *  charges against its quota — but this view only
   *  reports it; the quota itself is the node's (operator) policy and the guest's
   *  to enforce. */
  usedBytes(): number;
}

/** The read view over the host's flat-key `fs` service: a node directory on
 *  a server, an in-RAM MemoryFs for tests and the browser. */
export class FsBlobView implements BlobView {
  constructor(private readonly fs: Fs) {}

  get(id: Uint8Array): StoredBlock | null {
    return decodeStoreRecord(this.fs.get(toHex(id) + REC));
  }

  has(id: Uint8Array): boolean {
    return this.fs.size(toHex(id) + REC) >= 0;
  }

  list(prefix?: string): Uint8Array[] {
    const ids = new Set<string>();
    for (const key of this.fs.list()) {
      if (!key.endsWith(REC)) continue;
      const hex = key.slice(0, -REC.length);
      if (hex.length !== 64) continue;
      if (prefix && !hex.startsWith(prefix)) continue;
      ids.add(hex);
    }
    return [...ids].map(fromHex);
  }

  usedBytes(): number {
    return this.fs.list().filter((key) => key.endsWith(REC)).reduce((used, key) => used + Math.max(0, this.fs.size(key)), 0);
  }
}

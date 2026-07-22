// The host's READ VIEW of what this node's holder has stored (README §12).
//
// The confined guest holder owns store.local outright: it decides what to admit
// (§4.3 descriptor check, §6 sibling rule, §14 quota) and writes the
// `<hex>.blk` / `<hex>.dsc` layout itself through the raw-byte `fs.*` capability
// (host/tier2-guest.orchestration.js). This module deliberately implements NONE of
// that policy — no put, no delete, no quota budget. It only *reads* the layout back
// out, so a host-side caller (a test, the demo's per-holder counts, an operator
// script) can see what landed.
//
// One implementation of the quota rule, in the guest, is the whole point: a second
// host-side copy could only ever agree with it by being maintained byte-for-byte in
// step, and could not see the guest's own writes without re-reading the fs anyway.
//
// Everything here reads the backend live rather than caching an index, since the
// guest writes out of band as far as this view is concerned.

import { toHex, fromHex } from "./util.js";
import type { Fs } from "seedkernel-wasm/fs";

const BLK = ".blk"; // ciphertext
const DSC = ".dsc"; // author-signed chunk descriptor envelope (§4.3)

/** What a holder keeps for one block: the ciphertext and the signed descriptor
 *  envelope its chunk travels under (§4.3). The descriptor is stored verbatim
 *  so a repairer that lacks the manifest still has the chunk's shape. */
export interface StoredBlock {
  bytes: Uint8Array;
  /** The author-signed chunk-descriptor envelope (wire bytes). Anything the guest
   *  holder admits over the wire has one — the §18 placement messages make it
   *  mandatory, the replicated manifest block included — so null here means only
   *  that this block was planted into the fs directly (tests, tooling). */
  descriptor: Uint8Array | null;
}

/** A read-only view of the holder's blobs. All ids are 32-byte block_ids; keys are
 *  their hex. There is no write half by design — see the header. */
export interface BlobView {
  get(id: Uint8Array): StoredBlock | null;
  has(id: Uint8Array): boolean;
  /** All stored ids (optionally restricted to a hex prefix). */
  list(prefix?: string): Uint8Array[];
  /** Committed-tier bytes on the backend (§14): every `<hex>.blk` plus its `.dsc`
   *  sidecar. What the holder charges against its quota — but this view only
   *  reports it; the quota itself is the node's (operator) policy and the guest's
   *  to enforce. */
  usedBytes(): number;
}

/** The read view over the kernel's raw-byte `fs.*` capability: a node directory on
 *  a server, OPFS/IndexedDB in a browser, an in-RAM MemoryFs for tests. */
export class FsBlobView implements BlobView {
  constructor(private readonly fs: Fs) {}

  get(id: Uint8Array): StoredBlock | null {
    const hex = toHex(id);
    const bytes = this.fs.get(hex + BLK);
    if (!bytes) return null;
    const descriptor = this.fs.get(hex + DSC);
    return { bytes, descriptor: descriptor ?? null };
  }

  has(id: Uint8Array): boolean { return this.fs.size(toHex(id) + BLK) >= 0; }

  list(prefix?: string): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (const key of this.fs.list()) {
      if (!key.endsWith(BLK)) continue;
      const hex = key.slice(0, -BLK.length);
      if (hex.length !== 64) continue;
      if (prefix && !hex.startsWith(prefix)) continue;
      out.push(fromHex(hex));
    }
    return out;
  }

  usedBytes(): number {
    let used = 0;
    for (const key of this.fs.list()) {
      if (key.endsWith(BLK) || key.endsWith(DSC)) {
        const sz = this.fs.size(key);
        if (sz > 0) used += sz;
      }
    }
    return used;
  }
}

// The host's READ VIEW of what this node's holder has stored (README §12).
//
// The confined guest holder owns store.local outright (admission, quota, the
// `<hex>.blk`/`<hex>.dsc` layout — host/tier2-guest.orchestration.js). This
// module implements NONE of that policy — no put, no delete — only reads the
// layout back for a host-side caller (tests, demo counts, operator scripts).
// Reads the backend live rather than caching, since the guest writes out of band.

import { toHex, fromHex } from "./util.js";
import type { Fs } from "seedkernel-wasm/fs";

const BLK = ".blk"; // ciphertext
const DSC = ".dsc"; // author-signed chunk descriptor envelope (§4.3)

/** What a holder keeps for one block: the ciphertext and the signed descriptor
 *  envelope its chunk travels under (§4.3). The descriptor is stored verbatim
 *  so a repairer that lacks the file's index still has the chunk's shape. */
export interface StoredBlock {
  bytes: Uint8Array;
  /** The author-signed chunk-descriptor envelope (wire bytes). Anything the guest
   *  holder admits over the wire has one — the §18 placement messages make it
   *  mandatory, an index chunk's blocks included — so null here means only that
   *  this block was planted into the fs directly (tests, tooling). */
  descriptor: Uint8Array | null;
}

/** A read-only view of the holder's blobs. All ids are 32-byte block_ids; keys are
 *  their hex. There is no write half by design — see the header.
 *
 *  Every method is async, because the `fs` seam it reads through is async
 *  (seedkernel core/fs.ts): a synchronous `get` is a shape no browser backend can
 *  implement — IndexedDB is asynchronous by construction. An in-RAM backend
 *  resolves in a microtask; a caller that needs one await. */
export interface BlobView {
  get(id: Uint8Array): Promise<StoredBlock | null>;
  has(id: Uint8Array): Promise<boolean>;
  /** All stored ids (optionally restricted to a hex prefix). */
  list(prefix?: string): Promise<Uint8Array[]>;
  /** Committed-tier bytes on the backend (§14): every `<hex>.blk` plus its `.dsc`
   *  sidecar. What the holder charges against its quota — but this view only
   *  reports it; the quota itself is the node's (operator) policy and the guest's
   *  to enforce. */
  usedBytes(): Promise<number>;
}

/** The read view over the kernel's flat-key `fs` service: a node directory on
 *  a server, OPFS/IndexedDB in a browser, an in-RAM MemoryFs for tests. */
export class FsBlobView implements BlobView {
  constructor(private readonly fs: Fs) {}

  async get(id: Uint8Array): Promise<StoredBlock | null> {
    const hex = toHex(id);
    const bytes = await this.fs.get(hex + BLK);
    if (!bytes) return null;
    const descriptor = await this.fs.get(hex + DSC);
    return { bytes, descriptor: descriptor ?? null };
  }

  async has(id: Uint8Array): Promise<boolean> { return (await this.fs.size(toHex(id) + BLK)) >= 0; }

  async list(prefix?: string): Promise<Uint8Array[]> {
    const out: Uint8Array[] = [];
    for (const key of await this.fs.list()) {
      if (!key.endsWith(BLK)) continue;
      const hex = key.slice(0, -BLK.length);
      if (hex.length !== 64) continue;
      if (prefix && !hex.startsWith(prefix)) continue;
      out.push(fromHex(hex));
    }
    return out;
  }

  async usedBytes(): Promise<number> {
    let used = 0;
    for (const key of await this.fs.list()) {
      if (key.endsWith(BLK) || key.endsWith(DSC)) {
        const sz = await this.fs.size(key);
        if (sz > 0) used += sz;
      }
    }
    return used;
  }
}

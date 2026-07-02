// store.local backend over the kernel's raw-byte `fs.*` capability (README §12;
// the runtime split). FsBlobStore is pure *policy* — content-addressing, the
// descriptor sidecar, and the quota budget — layered over an opaque key → bytes Fs
// the seedkernel runtime provides (a node directory here, OPFS/IndexedDB in the
// browser).
//
// It is a LIVE view over the fs: the confined guest holder writes blocks through
// `fs.*` directly (the runtime split — host/tier2-guest.js), so has/list/get/stat
// read the backend rather than an in-memory index, which would otherwise miss those
// out-of-band writes. (Its own put/delete remain for callers that drive the store
// directly, e.g. the FsBlobStore unit tests.)
//
// Keys: the ciphertext lives under `<hex>.blk` and its author-signed chunk
// descriptor (§4.3) under the sibling `<hex>.dsc` — each its own flat fs key. Quota
// is a byte budget over the ciphertext + descriptor (committed tier, §14); a put
// past it throws so admission control refuses rather than over-commits.

import { toHex, fromHex } from "./util.js";
import { DEFAULT_QUOTA_BYTES, type BlobStore, type StoredBlock, type StoreStat } from "./store-local.js";
import type { Fs } from "seedkernel-wasm/fs";

const BLK = ".blk"; // ciphertext
const DSC = ".dsc"; // author-signed chunk descriptor envelope (§4.3)

export class FsBlobStore implements BlobStore {
  constructor(
    private readonly fs: Fs,
    public quota = DEFAULT_QUOTA_BYTES,
  ) {}

  put(id: Uint8Array, bytes: Uint8Array, descriptor: Uint8Array | null): void {
    const hex = toHex(id);
    // Quota over the committed ciphertext + descriptor sidecar (§14), computed live
    // (the guest holder also writes through fs.* out of band).
    const prevBlk = Math.max(0, this.fs.size(hex + BLK));
    const prevDsc = Math.max(0, this.fs.size(hex + DSC));
    const next = this.usedBytes() - prevBlk - prevDsc + bytes.length + (descriptor?.length ?? 0);
    if (next > this.quota) throw new Error("store.local: quota exceeded");
    this.fs.put(hex + BLK, bytes);
    if (descriptor) this.fs.put(hex + DSC, descriptor);
    else if (prevDsc > 0) this.fs.delete(hex + DSC); // overwriting a described block with a bare one
  }

  get(id: Uint8Array): StoredBlock | null {
    const hex = toHex(id);
    const bytes = this.fs.get(hex + BLK);
    if (!bytes) return null;
    const descriptor = this.fs.get(hex + DSC);
    return { bytes, descriptor: descriptor ?? null };
  }

  has(id: Uint8Array): boolean { return this.fs.has(toHex(id) + BLK); }

  delete(id: Uint8Array): boolean {
    const hex = toHex(id);
    if (!this.fs.has(hex + BLK)) return false;
    this.fs.delete(hex + BLK);
    this.fs.delete(hex + DSC);
    return true;
  }

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

  stat(): StoreStat {
    const used = this.usedBytes();
    return { quota: this.quota, used, free: Math.max(0, this.quota - used) };
  }

  /** Live committed-tier byte count: every `<hex>.blk` ciphertext + `.dsc`
   *  descriptor sidecar on the backend (§14). */
  private usedBytes(): number {
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

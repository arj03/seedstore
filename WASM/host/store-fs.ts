// store.local backend over the kernel's raw-byte `fs.*` capability (README §12;
// the runtime split). FsBlobStore is now pure *policy* — content-
// addressing, the descriptor sidecar, and the quota budget — layered over an
// opaque key → bytes Fs the seedkernel runtime provides (a node directory here,
// OPFS/IndexedDB in the browser). It keeps the same BlobStore interface, so no
// storage module above it changes; only the bytes-on-the-backend seam moved into
// the kernel, where raw file I/O belongs.
//
// Keys: the ciphertext lives under `<hex>.blk` and its author-signed chunk
// descriptor (§4.3) under the sibling `<hex>.dsc` — each its own flat fs key.
// The block→descriptor pairing and per-block sizes are held in an in-memory
// index rebuilt by listing the fs at open, so has/list/stat never hit the
// backend. Quota is a byte budget over the ciphertext (committed tier, §14); a
// put past it throws so admission control refuses rather than over-commits,
// matching MemoryBlobStore.

import { toHex, fromHex } from "./util.js";
import type { BlobStore, StoredBlock, StoreStat } from "./store-local.js";
import type { Fs } from "seedkernel-wasm/fs";

const BLK = ".blk"; // ciphertext
const DSC = ".dsc"; // author-signed chunk descriptor envelope (§4.3)

export class FsBlobStore implements BlobStore {
  private readonly index = new Map<string, number>(); // hex → ciphertext byte length
  private bytesUsed = 0;

  constructor(
    private readonly fs: Fs,
    public quota = 64 * 1024 * 1024,
  ) {
    for (const key of this.fs.list()) {
      if (!key.endsWith(BLK)) continue;
      const hex = key.slice(0, -BLK.length);
      if (hex.length !== 64) continue;
      const sz = this.fs.size(key);
      if (sz < 0) continue;
      this.index.set(hex, sz);
      this.bytesUsed += sz;
    }
  }

  put(id: Uint8Array, bytes: Uint8Array, descriptor: Uint8Array | null): void {
    const hex = toHex(id);
    const prev = this.index.get(hex) ?? 0;
    const next = this.bytesUsed - prev + bytes.length;
    if (next > this.quota) throw new Error("store.local: quota exceeded");
    this.fs.put(hex + BLK, bytes);
    if (descriptor) this.fs.put(hex + DSC, descriptor);
    else if (prev) this.fs.delete(hex + DSC); // overwriting a described block with a bare one
    this.index.set(hex, bytes.length);
    this.bytesUsed = next;
  }

  get(id: Uint8Array): StoredBlock | null {
    const hex = toHex(id);
    const bytes = this.fs.get(hex + BLK);
    if (!bytes) return null;
    const descriptor = this.fs.get(hex + DSC);
    return { bytes, descriptor: descriptor ?? null };
  }

  has(id: Uint8Array): boolean { return this.index.has(toHex(id)); }

  delete(id: Uint8Array): boolean {
    const hex = toHex(id);
    const sz = this.index.get(hex);
    if (sz === undefined) return false;
    this.fs.delete(hex + BLK);
    this.fs.delete(hex + DSC);
    this.index.delete(hex);
    this.bytesUsed -= sz;
    return true;
  }

  list(prefix?: string): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (const hex of this.index.keys()) {
      if (prefix && !hex.startsWith(prefix)) continue;
      out.push(fromHex(hex));
    }
    return out;
  }

  stat(): StoreStat {
    return { quota: this.quota, used: this.bytesUsed, free: Math.max(0, this.quota - this.bytesUsed) };
  }
}

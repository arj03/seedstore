// Canonical kernel names for the storage bridges, handlers, and capability ids
// (README §16, §17, §19). All are derived the same deterministic way the
// kernel derives its own bootstrap names, so every node in a deployment agrees
// on them without coordination.

/** Anything that can derive a kernel name from a canonical string. KernelHost
 *  satisfies this via deriveBootstrapName (SHA-3-256 over a fixed prefix). */
export interface NameDeriver {
  deriveBootstrapName(canonical: string): Uint8Array;
}

export interface StorageNames {
  // no-cap crypto host services (§16)
  cryptoHash: Uint8Array;
  // cap-gated I/O bridges (§16)
  storeLocal: Uint8Array;
  netSend: Uint8Array;
  clockNow: Uint8Array;
  rand: Uint8Array;
  // app handlers (§17)
  codec: Uint8Array;
  reputation: Uint8Array;
  // capability ids declared by handlers at install time (§2, §8)
  capStore: Uint8Array;
  capNet: Uint8Array;
  capClock: Uint8Array;
  capRand: Uint8Array;
}

export function storageNames(d: NameDeriver): StorageNames {
  return {
    cryptoHash: d.deriveBootstrapName("seedstore.crypto.hash"),
    storeLocal: d.deriveBootstrapName("seedstore.store.local"),
    netSend: d.deriveBootstrapName("seedstore.net.send"),
    clockNow: d.deriveBootstrapName("seedstore.clock.now"),
    rand: d.deriveBootstrapName("seedstore.rand"),
    codec: d.deriveBootstrapName("seedstore.codec"),
    reputation: d.deriveBootstrapName("seedstore.reputation"),
    capStore: d.deriveBootstrapName("seedstore.cap.store"),
    capNet: d.deriveBootstrapName("seedstore.cap.net"),
    capClock: d.deriveBootstrapName("seedstore.cap.clock"),
    capRand: d.deriveBootstrapName("seedstore.cap.rand"),
  };
}

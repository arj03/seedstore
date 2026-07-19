// Canonical kernel names for the two installed handlers (README §17, §19). Both
// are derived the same deterministic way the kernel derives its own bootstrap
// names, so every node in a deployment agrees on them without coordination.

/** Anything that can derive a kernel name from a canonical string. KernelHost
 *  satisfies this via deriveBootstrapName (literal-ASCII "seedkernel.bootstrap.v1:"
 *  + canonical — plain, not genesis-hash-derived; seedkernel §5.1). */
export interface NameDeriver {
  deriveBootstrapName(canonical: string): Uint8Array;
}

export interface StorageNames {
  // app handlers (§17)
  codec: Uint8Array;
  reputation: Uint8Array;
}

export function storageNames(d: NameDeriver): StorageNames {
  return {
    codec: d.deriveBootstrapName("seedstore.codec"),
    reputation: d.deriveBootstrapName("seedstore.reputation"),
  };
}

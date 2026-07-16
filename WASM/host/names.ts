// Canonical kernel names for the crypto.hash service and the two installed
// handlers (README §16, §17, §19). All are derived the same deterministic way the
// kernel derives its own bootstrap names, so every node in a deployment agrees
// on them without coordination.

/** Anything that can derive a kernel name from a canonical string. KernelHost
 *  satisfies this via deriveBootstrapName (literal-ASCII "seedkernel.bootstrap.v1:"
 *  + canonical — plain, not genesis-hash-derived; seedkernel §5.1). */
export interface NameDeriver {
  deriveBootstrapName(canonical: string): Uint8Array;
}

export interface StorageNames {
  // no-cap crypto host service the installed codec WASM calls (§16)
  cryptoHash: Uint8Array;
  // app handlers (§17)
  codec: Uint8Array;
  reputation: Uint8Array;
}

export function storageNames(d: NameDeriver): StorageNames {
  return {
    cryptoHash: d.deriveBootstrapName("seedstore.crypto.hash"),
    codec: d.deriveBootstrapName("seedstore.codec"),
    reputation: d.deriveBootstrapName("seedstore.reputation"),
  };
}

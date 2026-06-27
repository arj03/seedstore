// Storage host services (README §16). The node installs the codec + reputation
// handlers and runs the whole protocol as a confined guest (host/storage-node.ts);
// the guest reaches net/fs/clock/rand through seedkernel's generic capability
// bridge, not through storage-specific bridges. The one storage-named service still
// wired onto the kernel is crypto.hash — the no-cap content-hash the installed
// `codec` WASM calls for its block-id op (§4.2, §16). Hashing performs no I/O, so
// like signature.signer it needs no capability, which is what keeps `codec` pure.

import type { KernelHost, Handler } from "seedkernel-wasm";
import type { Crypto } from "./crypto.js";
import type { StorageNames } from "./names.js";

export interface BridgeBackends {
  crypto: Crypto;
}

/** Wire the storage host services onto a KernelHost for one node. Currently just
 *  crypto.hash (no capability); the backend is owned by the caller (StorageNode). */
export function registerStorageBridges(
  host: KernelHost,
  names: StorageNames,
  backends: BridgeBackends,
): void {
  // ── crypto.hash — no capability (§16) ──────────────────────────────────
  const hashHandler: Handler = (_n, payload) => backends.crypto.hash(payload);
  host.register(names.cryptoHash, hashHandler);
}

// A small helper to stand up a fully-connected cohort of storage nodes on one
// Network — used by the tests and the browser demo. A real deployment grows its
// cohort by introduction or a rendezvous point (§5.1); this just wires every
// node to every other so placement has somewhere to go.

import type { Sodium } from "./sodium.js";
import type { Network } from "seedkernel-wasm/net";
import type { StorageConfig } from "./core.js";
import type { WasmBytes } from "./node.js";
import { StorageNode } from "./storage-node.js";

export interface CohortOptions {
  count: number;
  network: Network;
  sodium: Sodium;
  wasm: WasmBytes;
  config?: Partial<StorageConfig>;
  quota?: number;
  timeoutMs?: number;
  /** Shared signing scope for the cohort (README §16). Omit for the in-process default
   *  (`STORAGE_SIGN_SCOPE`); pass `storageSignScope(bundleAuthor)` when these nodes must
   *  verify descriptors a shell running that bundle signs (the cross-path tests). */
  signScope?: Uint8Array;
}

/** Create `count` storage nodes on `network` and connect them into one cohort. */
export async function createConnectedCohort(opts: CohortOptions): Promise<StorageNode[]> {
  const nodes: StorageNode[] = [];
  for (let i = 0; i < opts.count; i++) {
    nodes.push(await StorageNode.create({
      network: opts.network,
      sodium: opts.sodium,
      codecBytes: opts.wasm.codecBytes,
      reputationBytes: opts.wasm.reputationBytes,
      guestSource: opts.wasm.guestSource,
      config: opts.config,
      quota: opts.quota,
      timeoutMs: opts.timeoutMs,
      signScope: opts.signScope,
    }));
  }
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) StorageNode.connect(nodes[i], nodes[j]);
  }
  return nodes;
}

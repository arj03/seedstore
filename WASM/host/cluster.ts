// A small helper to stand up a fully-connected cohort of storage nodes on one
// Network — used by the tests and the browser demo. A real deployment grows its
// cohort by introduction or a rendezvous point (§5.1); this just wires every
// node to every other so placement has somewhere to go.

import type { Sodium } from "./sodium.js";
import type { Network } from "seedkernel-wasm/net";
import type { StorageConfig } from "./core.js";
import { StorageNode } from "./storage-node.js";

export interface CohortOptions {
  count: number;
  network: Network;
  sodium: Sodium;
  /** The loaded seedstore bundle, as `loadWasmBytes()` returns it — one signed blob,
   *  the ONE install path. Every node in the cohort loads the same bundle, so they all
   *  derive the same author scope and interoperate. */
  wasm: { bundleBlob: Uint8Array };
  config?: Partial<StorageConfig>;
  quota?: number;
  timeoutMs?: number;
}

/** Create `count` storage nodes on `network` and connect them into one cohort. */
export async function createConnectedCohort(opts: CohortOptions): Promise<StorageNode[]> {
  const nodes: StorageNode[] = [];
  for (let i = 0; i < opts.count; i++) {
    nodes.push(await StorageNode.create({
      network: opts.network,
      sodium: opts.sodium,
      bundleBlob: opts.wasm.bundleBlob,
      config: opts.config,
      quota: opts.quota,
      timeoutMs: opts.timeoutMs,
    }));
  }
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) StorageNode.connect(nodes[i], nodes[j]);
  }
  return nodes;
}

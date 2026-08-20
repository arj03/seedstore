// A small helper to stand up a fully-connected cohort of storage nodes on one
// LoopbackNetwork — used by the tests and the browser demo. A real deployment
// grows its cohort by introduction or a rendezvous point (§5.1); this just wires
// every node to every other so placement has somewhere to go.
//
// The transport is now a signed bundle driven over the ChannelFactory seam: each
// node binds its own loopback port (via its view of the shared fabric) and every
// node dials every other (StorageNode.connect → addPeerAddr + ready). The
// in-process fabric runs the REAL transport — AKE, record layer, routing — over
// microtask-delivered channel pairs, so these cohorts exercise the shipped stack.

import type { Sodium } from "./sodium.js";
import type { StorageConfig } from "./core.js";
import { StorageNode } from "./storage-node.js";
import { LoopbackNetwork } from "./loopback.js";
import { toHex } from "./util.js";

export interface CohortOptions {
  count: number;
  /** The in-process fabric (with online/offline control) the cohort shares. */
  network: LoopbackNetwork;
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
    const identity = (() => {
      const kp = opts.sodium.crypto_sign_keypair();
      return { publicKey: kp.publicKey, privateKey: kp.privateKey };
    })();
    const peerId = toHex(identity.publicKey);
    nodes.push(await StorageNode.create({
      sodium: opts.sodium,
      bundleBlob: opts.wasm.bundleBlob,
      identity,
      config: opts.config,
      quota: opts.quota,
      timeoutMs: opts.timeoutMs,
      // Each node dials/listens through its own view of the shared fabric.
      channels: opts.network.view(peerId),
      listen: { host: "127.0.0.1", port: 0 },
    }));
  }
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) await StorageNode.connect(nodes[i], nodes[j]);
  }
  return nodes;
}

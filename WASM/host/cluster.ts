// A small helper to stand up a fully-connected cohort of storage nodes on one
// LoopbackNetwork — used by the tests and the browser demo. A real deployment
// grows its cohort by introduction or a rendezvous point (§5.1); this just wires
// every node to every other so placement has somewhere to go. The fabric runs
// the real transport (AKE, record layer, routing) over microtask-delivered pairs.

import { generateKeyPair, type Sodium } from "./sodium.js";
import type { StorageConfig } from "./core.js";
import { StorageNode, type WasmBytes } from "./storage-node.js";
import { bootStorageNode, type StandUp } from "./runtime.js";
import { LoopbackNetwork } from "./loopback.js";
import { toHex } from "./util.js";

export interface CohortOptions {
  count: number;
  /** The in-process fabric (with offline control) the cohort shares. */
  network: LoopbackNetwork;
  /** What stands each node up (runtime.ts): a page's host, shared by its nodes, or an
   *  in-memory host of each node's own (node.ts). */
  standUp: StandUp;
  sodium: Sodium;
  /** The loaded seedstore bundle, as `loadWasmBytes()` returns it — one signed blob,
   *  the ONE install path. Every node in the cohort loads the same bundle, so they all
   *  derive the same author scope and interoperate. */
  wasm: WasmBytes;
  config?: Partial<StorageConfig>;
  quota?: number;
  timeoutMs?: number;
  guestDeadlineMs?: number;
  /** Silence the host transport driver's link-down diagnostic for every node in the cohort
   *  (seedkernel `TransportHostOptions.suppressLinkLog`). A cohort is stood up and torn
   *  down wholesale here, so each teardown prints a `truncated` line at every peer that
   *  had a link to the node going away — hundreds across a suite, burying the assertions.
   *  Left OFF by default, because in a real deployment that line is the point. */
  suppressLinkLog?: boolean;
}

/** Create `count` storage nodes on `network` and connect them into one cohort. */
export async function createConnectedCohort(opts: CohortOptions): Promise<StorageNode[]> {
  const nodes = await Promise.all(Array.from({ length: opts.count }, () => {
    const identity = generateKeyPair(opts.sodium);
    const peerId = toHex(identity.publicKey);
    return bootStorageNode(opts.standUp, {
      sodium: opts.sodium,
      bundleBlob: opts.wasm.bundleBlob,
      identity,
      // A directory of its own, for nodes that share a host.
      dir: peerId,
      config: opts.config,
      quota: opts.quota,
      timeoutMs: opts.timeoutMs,
      guestDeadlineMs: opts.guestDeadlineMs,
      // Each node dials/listens through its own view of the shared fabric.
      channels: opts.network.view(peerId),
      listen: [{ label: "tcp", host: "127.0.0.1", port: 0 }],
      suppressLinkLog: opts.suppressLinkLog,
    });
  }));
  // Every pair, a round at a time with each node in one pair per round (the circle method):
  // n − 1 rounds of concurrent connects rather than n(n−1)/2 in a row. One pair per node per
  // round keeps a node from taking several handshakes at once from the fabric's one address,
  // which the transport's per-source half-open cap would refuse.
  const ring: (StorageNode | null)[] = nodes.length % 2 ? [...nodes, null] : [...nodes];
  for (let r = 0; r < ring.length - 1; r++) {
    await Promise.all(Array.from({ length: ring.length / 2 }, (_, i) => {
      const a = ring[i], b = ring[ring.length - 1 - i];
      return a && b ? StorageNode.connect(a, b) : undefined;
    }));
    ring.splice(1, 0, ring.pop()!);
  }
  return nodes;
}

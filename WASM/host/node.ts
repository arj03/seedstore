// Node entry point — reads the signed seedstore bundle (.skb) from disk and loads it
// onto a seedkernel node, with libsodium for what storage computes host-side. Use this
// on Node; for the browser see ./browser.ts.

import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { platformHost, type PlatformHost } from "seedkernel-wasm/platform";
import { browserPlatform, type BrowserPlatformOptions } from "seedkernel-wasm/platform-web";

import { loadSodium, generateKeyPair } from "./sodium.js";
import { StorageNode, type StorageNodeOptions, type WasmBytes } from "./storage-node.js";
import { bootStorageNode, type StandUp, type StorageRuntimeOptions } from "./runtime.js";
import { createConnectedCohort as cohortOn, type CohortOptions } from "./cluster.js";
import { LoopbackNetwork } from "./loopback.js";
import { toHex } from "./util.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const buildDir = join(__dirname, "..");

/** Read the signed seedstore bundle (bundle/seedstore.skb) from the build tree. */
export async function loadWasmBytes(dir = buildDir): Promise<WasmBytes> {
  const bundleBlob = new Uint8Array(
    await readFile(join(dir, "..", "bundle", "seedstore.skb")),
  );
  return { bundleBlob };
}

let hostBlob: Uint8Array | undefined;
/** A seedkernel host in this process, on the package's host blob, with no sockets or
 *  datagrams of its own (its nodes take the channels they are given) and its own engine
 *  instances, as a separate machine has. Its store is memory unless `files` names another
 *  (seedkernel-wasm/fs-node `nodeRawFiles` for disk). A node serving from disk on the
 *  machine's own sockets takes seedkernel-wasm/shell-node `bootNodeShell` instead. */
export function inProcessHost(files?: BrowserPlatformOptions["files"]): PlatformHost {
  hostBlob ??= new Uint8Array(readFileSync(createRequire(import.meta.url).resolve("seedkernel-wasm/host.skb")));
  return platformHost(browserPlatform({ hostBlob, files }));
}

/** A node on an in-memory host of its own: what an in-process cohort stands each node up
 *  with. */
export const inProcessStandUp: StandUp = (cfg) => inProcessHost().standUp(cfg);

/** Create `count` storage nodes on `network` and connect them into one cohort, each on
 *  an in-memory host of its own unless `standUp` says otherwise. */
export function createConnectedCohort(
  opts: Omit<CohortOptions, "standUp"> & { standUp?: StandUp },
): Promise<StorageNode[]> {
  return cohortOn({ ...opts, standUp: opts.standUp ?? inProcessStandUp });
}

/** One storage node, loading the bundle + libsodium for you: onto `runtime` when one is
 *  passed, else onto a node stood up here (`standUp`, an in-memory host by default). */
export async function createStorageNode(
  opts: Omit<StorageNodeOptions, "bundleBlob" | "sodium" | "runtime"> & Partial<StorageRuntimeOptions> & {
    runtime?: StorageNodeOptions["runtime"];
    standUp?: StandUp;
    wasm?: WasmBytes;
    /** The build tree the bundle is read from (`loadWasmBytes`). */
    wasmDir?: string;
    /** An in-process fabric to join: the node binds its own loopback port and dials
     *  through it (tests, single-process demos). */
    network?: LoopbackNetwork;
  },
): Promise<StorageNode> {
  const sodium = await loadSodium();
  const { bundleBlob } = opts.wasm ?? (await loadWasmBytes(opts.wasmDir));
  if (opts.runtime) return StorageNode.create({ ...opts, runtime: opts.runtime, bundleBlob, sodium });
  const identity = opts.identity ?? generateKeyPair(sodium);
  const net = opts.network
    ? { channels: opts.network.view(toHex(identity.publicKey)), listen: [{ label: "tcp", host: "127.0.0.1", port: 0 }] }
    : {};
  return bootStorageNode(opts.standUp ?? inProcessStandUp, { ...opts, ...net, identity, bundleBlob, sodium });
}

export {
  StorageNode, LoopbackNetwork, loadSodium, generateKeyPair,
};
export { storageRuntime, bootStorageNode } from "./runtime.js";
export type { StandUp, StorageRuntimeOptions } from "./runtime.js";
export type { StorageNodeOptions, StorageRuntime, PutResult, WasmBytes } from "./storage-node.js";
// The host's door into the signed transport: peers and cohort readiness live in that
// guest, so they are calls to the id it claims rather than methods on the socket driver.
export { netAddr, netPeer, netRelay, netRelayState, netContact, netReady, netPeers, netRoutes } from "./storage-node.js";
export type { StorageConfig, Identity } from "./core.js";
export { defaultConfig, PRODUCTION_BLOCK_SIZE, TEST_BLOCK_SIZE, STORAGE_APP, STORAGE_PROTO } from "./core.js";
export { toHex, fromHex } from "./util.js";

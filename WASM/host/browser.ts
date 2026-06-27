// Browser entry point — fetches the four WASM modules and boots a StorageNode
// against a caller-provided sumo libsodium. The page readies libsodium and
// passes it in; the BlobStore backend would be OPFS/IndexedDB in a real browser
// node (here the default in-memory store is used, which is also a valid
// eviction-aware cache, §12). Browser nodes run the same protocol as
// long-running peers, differing only in backend and default quota (§1, §8).

import type { Sodium } from "./sodium.js";
import { StorageNode, type StorageNodeOptions } from "./storage-node.js";
import type { WasmBytes } from "./node.js";

/** Fetch the four WASM modules + the guest program relative to the page. */
export async function loadWasmBytes(baseUrl: string | URL = "./"): Promise<WasmBytes> {
  const base = typeof baseUrl === "string" ? baseUrl : baseUrl.href;
  const get = async (name: string) => new Uint8Array(await (await fetch(base + name)).arrayBuffer());
  const text = async (name: string) => (await fetch(base + name)).text();
  const [kernelBytes, bootstrapBytes, codecBytes, reputationBytes, guestSource] = await Promise.all([
    get("kernel.wasm"), get("bootstrap.wasm"), get("codec.wasm"), get("reputation.wasm"),
    text("tier2-guest.js"),
  ]);
  return { kernelBytes, bootstrapBytes, codecBytes, reputationBytes, guestSource };
}

/** Boot one storage node in the browser. Pass a readied sumo libsodium. */
export async function createStorageNode(
  opts: Omit<StorageNodeOptions, keyof WasmBytes> & { wasm?: WasmBytes; baseUrl?: string | URL },
): Promise<StorageNode> {
  const sodium = opts.sodium as Sodium;
  await sodium.ready;
  const wasm = opts.wasm ?? (await loadWasmBytes(opts.baseUrl));
  return StorageNode.create({ ...opts, ...wasm });
}

export { StorageNode } from "./storage-node.js";
export { LoopbackNetwork } from "seedkernel-wasm/net";
export { createConnectedCohort } from "./cluster.js";
export type { StorageNodeOptions } from "./storage-node.js";
export type { StorageConfig, Identity } from "./core.js";
export { defaultConfig } from "./core.js";

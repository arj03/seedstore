// Browser entry point — fetches the two WASM modules and boots a StorageNode
// against a caller-provided sumo libsodium. The page readies libsodium and
// passes it in; the `fs` backend the holder stores into would be OPFS/IndexedDB in a
// real browser node (here the default in-memory one is used, which is also a valid
// eviction-aware cache, §12). Browser nodes run the same protocol as
// long-running peers, differing only in backend and default quota (§1, §8).

import type { Sodium } from "./sodium.js";
import { StorageNode, type StorageNodeOptions } from "./storage-node.js";
import type { WasmBytes } from "./node.js";

/** Fetch the two WASM modules + the guest program relative to the page. */
export async function loadWasmBytes(baseUrl: string | URL = "./"): Promise<WasmBytes> {
  const base = typeof baseUrl === "string" ? baseUrl : baseUrl.href;
  // no-store: the wasm modules and guest are versioned together with the host JS, so a
  // stale HTTP-cached copy (e.g. tier2-guest.js after a rebuild) would silently shadow
  // a fresh host — a "no entrypoint 'x'" mismatch that a normal reload won't clear.
  const get = async (name: string) => new Uint8Array(await (await fetch(base + name, { cache: "no-store" })).arrayBuffer());
  const text = async (name: string) => (await fetch(base + name, { cache: "no-store" })).text();
  const [codecBytes, reputationBytes, guestSource] = await Promise.all([
    get("codec.wasm"), get("reputation.wasm"),
    text("tier2-guest.js"),
  ]);
  return { codecBytes, reputationBytes, guestSource };
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
// A browser node joining a cohort of bundle-running holders (a loader/shell) must
// verify descriptors under that bundle's author scope, not the zero-author default —
// see p2p.html. Re-export the scope derivation so the page can pass `signScope`.
export { STORAGE_APP, STORAGE_SIGN_SCOPE, storageSignScope } from "./manifest.js";

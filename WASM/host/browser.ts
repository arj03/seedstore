// Browser entry point — fetches the seedstore bundle (.skb) and boots a StorageNode
// against a caller-provided sumo libsodium. The page readies libsodium and
// passes it in. Browser nodes run the same protocol as long-running peers,
// differing only in backend and default quota (§1, §8).
//
// With the §12.9 move, the ONE install path is the signed bundle — the
// raw `codecBytes`/`reputationBytes`/`guestSource` splits are gone.
// A browser node fetches the single `seedstore.skb` and the shared shell
// loads + verifies + installs it.

import type { Sodium } from "./sodium.js";
import { StorageNode, type StorageNodeOptions } from "./storage-node.js";

export interface WasmBytes {
  bundleBlob: Uint8Array;
}

/** Fetch the signed seedstore bundle relative to the page. One fetch replaces
 *  the old three (codec.wasm + reputation.wasm + tier2-guest.js). */
export async function loadWasmBytes(baseUrl: string | URL = "./"): Promise<WasmBytes> {
  const base = typeof baseUrl === "string" ? baseUrl : baseUrl.href;
  // no-store: the bundle is versioned together with the host JS, so a stale
  // HTTP-cached copy would silently shadow a fresh host.
  const bundleBlob = new Uint8Array(
    await (await fetch(base + "seedstore.skb", { cache: "no-store" })).arrayBuffer(),
  );
  return { bundleBlob };
}

/** Boot one storage node in the browser. Pass a readied sumo libsodium. */
export async function createStorageNode(
  opts: Omit<StorageNodeOptions, "bundleBlob" | "sodium"> & { sodium: Sodium; wasm?: WasmBytes; baseUrl?: string | URL },
): Promise<StorageNode> {
  const sodium = opts.sodium as Sodium;
  await sodium.ready;
  const wasm = opts.wasm ?? (await loadWasmBytes(opts.baseUrl));
  return StorageNode.create({ ...opts, bundleBlob: wasm.bundleBlob, sodium });
}

export { StorageNode } from "./storage-node.js";
export { LoopbackNetwork } from "seedkernel-wasm/net";
export { createConnectedCohort } from "./cluster.js";
export type { StorageNodeOptions } from "./storage-node.js";
export type { StorageConfig, Identity } from "./core.js";
export { defaultConfig } from "./core.js";
// A browser node joining a cohort of bundle-running holders must verify
// descriptors under that bundle's author scope. Re-export the scope derivation
// so the page can compute `storageSignScope(bundleAuthor)`.
export { STORAGE_APP, storageSignScope } from "./manifest.js";

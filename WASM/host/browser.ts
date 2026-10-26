// Browser entry point — fetches the seedstore bundle (.skb) and loads it onto a node the
// page's seedkernel host stood up (seedkernel-wasm/platform-web `browserHost`, then
// `storageRuntime`). The page readies its own libsodium for what storage computes
// host-side. Browser nodes run the same protocol as long-running peers, differing only in
// backend and default quota (§1, §12).

import { StorageNode, type StorageNodeOptions, type WasmBytes } from "./storage-node.js";

/** Fetch the signed seedstore bundle relative to the page: one blob carrying
 *  codec.wasm, reputation.wasm and the guest. */
export async function loadWasmBytes(baseUrl: string | URL = "./"): Promise<WasmBytes> {
  const base = typeof baseUrl === "string" ? baseUrl : baseUrl.href;
  const url = base + "seedstore.skb";
  // no-store: the bundle is versioned together with the host JS, so a stale
  // HTTP-cached copy would silently shadow a fresh host.
  const r = await fetch(url, { cache: "no-store" });
  // Without this a 404's HTML body reaches the verifier and surfaces as the
  // baffling "bundle: no manifest in the blob".
  if (!r.ok) throw new Error(`could not fetch ${url} — HTTP ${r.status} ${r.statusText}`);
  const bundleBlob = new Uint8Array(await r.arrayBuffer());
  return { bundleBlob };
}

/** Load the seedstore bundle onto the page's node (`opts.runtime`), fetching the bundle
 *  when it is not passed. */
export async function createStorageNode(
  opts: Omit<StorageNodeOptions, "bundleBlob"> & { wasm?: WasmBytes; baseUrl?: string | URL },
): Promise<StorageNode> {
  const wasm = opts.wasm ?? (await loadWasmBytes(opts.baseUrl));
  return StorageNode.create({ ...opts, bundleBlob: wasm.bundleBlob });
}

export { StorageNode } from "./storage-node.js";
export { LoopbackNetwork } from "./loopback.js";
export { createConnectedCohort } from "./cluster.js";
export { storageRuntime, bootStorageNode } from "./runtime.js";
export type { StorageNodeOptions, WasmBytes } from "./storage-node.js";
export type { Groups } from "./protocol.js";
export { netAddr, netPeer, netRelay, netRelayState, netContact, netReady, netPeers, netRoutes } from "./storage-node.js";
export type { StorageConfig, Identity } from "./core.js";
export { defaultConfig, STORAGE_APP, STORAGE_PROTO } from "./core.js";

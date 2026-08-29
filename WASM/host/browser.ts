// Browser entry point — fetches the seedstore bundle (.skb) and boots a StorageNode
// against the caller-provided core libsodium. The page readies libsodium and
// passes it in. Browser nodes run the same protocol as long-running peers,
// differing only in backend and default quota (§1, §8).

import type { Sodium } from "./sodium.js";
import { StorageNode, type StorageNodeOptions } from "./storage-node.js";
import { LoopbackNetwork } from "./loopback.js";
import { toHex } from "./util.js";

export interface WasmBytes {
  bundleBlob: Uint8Array;
}

/** Fetch the signed seedstore bundle relative to the page. One fetch replaces
 *  the old three (codec.wasm + reputation.wasm + tier2-guest.js). */
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

/** Boot one storage node in the browser. Pass a readied core libsodium. */
export async function createStorageNode(
  opts: Omit<StorageNodeOptions, "bundleBlob" | "sodium"> & {
    sodium: Sodium; wasm?: WasmBytes; baseUrl?: string | URL;
    /** An in-process fabric to join: each node binds its own loopback port and
     *  dials through it (the in-page cohort). Browser WebSocket/WebRTC callers
     *  instead pass a prebuilt runtime whose ChannelFactory was installed at boot. */
    network?: LoopbackNetwork;
  },
): Promise<StorageNode> {
  const sodium = opts.sodium as Sodium;
  await sodium.ready;
  const wasm = opts.wasm ?? (await loadWasmBytes(opts.baseUrl));
  const { network, ...rest } = opts;
  // The in-process fabric needs the identity BEFORE the node boots (its view is
  // keyed by peer id), so mint one here when the caller left it to the node. Only
  // on the build-your-own-runtime path: a prebuilt `runtime` already has both a
  // socket seam and the identity it registered under.
  let o = rest;
  if (network && !o.runtime) {
    const identity = o.identity ?? (() => { const kp = sodium.crypto_sign_keypair(); return { publicKey: kp.publicKey, privateKey: kp.privateKey }; })();
    o = { ...o, identity, channels: network.view(toHex(identity.publicKey)), listen: { host: "127.0.0.1", port: 0 } };
  }
  return StorageNode.create({ ...o, bundleBlob: wasm.bundleBlob, sodium });
}

export { StorageNode } from "./storage-node.js";
export { LoopbackNetwork } from "./loopback.js";
export { createConnectedCohort } from "./cluster.js";
export type { StorageNodeOptions } from "./storage-node.js";
export { netAddr, netContact, netReady, netPeers } from "./storage-node.js";
export type { StorageConfig, Identity } from "./core.js";
export { defaultConfig } from "./core.js";
// A browser node joining a cohort of bundle-running holders must verify
// descriptors under that bundle's author scope. Re-export the scope derivation
// so the page can compute `storageSignScope(bundleAuthor)`.
export { STORAGE_APP, STORAGE_PROTO, storageSignScope } from "./manifest.js";

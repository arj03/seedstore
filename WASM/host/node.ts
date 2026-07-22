// Node entry point — reads the signed seedstore bundle (.skb) from disk and
// boots a StorageNode against the sumo libsodium. Use this on Node / Bun / Deno;
// for the browser see ./browser.ts.
//
// With the §12.9 move, the ONE install path is the signed bundle. The raw
// `codecBytes`/`reputationBytes`/`guestSource` splits are gone — a Node node
// reads the single `seedstore.skb` and the shared shell loads + verifies + installs it.

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadSodium, generateKeyPair } from "./sodium.js";
import { StorageNode, type StorageNodeOptions } from "./storage-node.js";
import { LoopbackNetwork } from "seedkernel-wasm/net";

const __dirname = dirname(fileURLToPath(import.meta.url));
const buildDir = join(__dirname, "..");

export interface WasmBytes {
  /** The signed seedstore bundle blob (bundle/seedstore.skb). One file carries
   *   everything: manifest + codec.wasm + reputation.wasm + guest.js. */
  bundleBlob: Uint8Array;
}

/** Read the signed seedstore bundle from the build tree. */
export async function loadWasmBytes(dir = buildDir): Promise<WasmBytes> {
  const bundleBlob = new Uint8Array(
    await readFile(join(dir, "..", "bundle", "seedstore.skb")),
  );
  return { bundleBlob };
}

/** Boot one storage node, loading the bundle + libsodium for you. */
export async function createStorageNode(
  opts: Omit<StorageNodeOptions, "bundleBlob" | "sodium"> & { wasm?: WasmBytes; dir?: string },
): Promise<StorageNode> {
  const sodium = await loadSodium();
  const wasm = opts.wasm ?? (await loadWasmBytes(opts.dir));
  return StorageNode.create({ ...opts, bundleBlob: wasm.bundleBlob, sodium });
}

export {
  StorageNode, LoopbackNetwork, loadSodium, generateKeyPair,
};
export { createConnectedCohort } from "./cluster.js";
export type { StorageNodeOptions, PutResult } from "./storage-node.js";
export type { StorageConfig, Identity } from "./core.js";
export { defaultConfig, PRODUCTION_BLOCK_SIZE } from "./core.js";
export { STORAGE_APP, storageSignScope } from "./manifest.js";
export { toHex, fromHex } from "./util.js";

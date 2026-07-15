// Node entry point — reads the four WASM modules from disk and boots a
// StorageNode against the sumo libsodium. Use this on Node / Bun / Deno; for
// the browser see ./browser.ts. The kernel + bootstrap come from the sibling
// seedkernel build (copied in by scripts/copy-kernel.mjs); the codec +
// reputation are this project's own build output.

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadSodium, generateKeyPair } from "./sodium.js";
import { StorageNode, type StorageNodeOptions } from "./storage-node.js";
import { LoopbackNetwork } from "seedkernel-wasm/net";

const __dirname = dirname(fileURLToPath(import.meta.url));
const buildDir = join(__dirname, "..");

export interface WasmBytes {
  kernelBytes: Uint8Array;
  bootstrapBytes: Uint8Array;
  codecBytes: Uint8Array;
  reputationBytes: Uint8Array;
  /** The stitched guest program text (build/host/tier2-guest.js). It carries the
   *  whole protocol; StorageNode runs it but never reads disk, so the loader hands
   *  it the text (browser.js fetches it instead). */
  guestSource: string;
}

/** Read the four WASM modules + the guest program from the build directory. */
export async function loadWasmBytes(dir = buildDir): Promise<WasmBytes> {
  const [kernelBytes, bootstrapBytes, codecBytes, reputationBytes, guestSource] = await Promise.all([
    readFile(join(dir, "kernel.wasm")),
    readFile(join(dir, "bootstrap.wasm")),
    readFile(join(dir, "codec.wasm")),
    readFile(join(dir, "reputation.wasm")),
    readFile(join(dir, "host", "tier2-guest.js"), "utf8"),
  ]);
  return {
    kernelBytes: new Uint8Array(kernelBytes),
    bootstrapBytes: new Uint8Array(bootstrapBytes),
    codecBytes: new Uint8Array(codecBytes),
    reputationBytes: new Uint8Array(reputationBytes),
    guestSource,
  };
}

/** Boot one storage node, loading WASM + libsodium for you. */
export async function createStorageNode(
  opts: Omit<StorageNodeOptions, keyof WasmBytes | "sodium"> & { wasm?: WasmBytes; dir?: string },
): Promise<StorageNode> {
  const sodium = await loadSodium();
  const wasm = opts.wasm ?? (await loadWasmBytes(opts.dir));
  return StorageNode.create({ ...opts, ...wasm, sodium });
}

export {
  StorageNode, LoopbackNetwork, loadSodium, generateKeyPair,
};
export { createConnectedCohort } from "./cluster.js";
export type { StorageNodeOptions, PutResult } from "./storage-node.js";
export type { StorageConfig, Identity } from "./core.js";
export { defaultConfig, PRODUCTION_BLOCK_SIZE } from "./core.js";
export { STORAGE_APP, STORAGE_SIGN_SCOPE, storageSignScope } from "./manifest.js";
// Byte helpers, re-exported so scripts driving a node (scripts/p2p-cli.mjs) don't
// re-declare their own hex pair.
export { toHex, fromHex } from "./util.js";

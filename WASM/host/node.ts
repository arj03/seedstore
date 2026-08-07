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
import { LoopbackNetwork } from "./loopback.js";
import { toHex } from "./util.js";

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
  opts: Omit<StorageNodeOptions, "bundleBlob" | "sodium"> & {
    wasm?: WasmBytes; dir?: string;
    /** An in-process fabric to join: each node binds its own loopback port and
     *  dials through it (tests, single-process demos). Absent, the node has no
     *  socket seam — a pure client, or a host-managed-transport (WS/RTC) node. */
    network?: LoopbackNetwork;
  },
): Promise<StorageNode> {
  const sodium = await loadSodium();
  const wasm = opts.wasm ?? (await loadWasmBytes(opts.dir));
  const { network, ...rest } = opts;
  let o = rest;
  if (network) {
    const identity = o.identity ?? generateKeyPair(sodium);
    o = { ...o, identity, channels: network.view(toHex(identity.publicKey)), listen: { host: "127.0.0.1", port: 0 } };
  }
  return StorageNode.create({ ...o, bundleBlob: wasm.bundleBlob, sodium });
}

export {
  StorageNode, LoopbackNetwork, loadSodium, generateKeyPair,
};
export { createConnectedCohort } from "./cluster.js";
export type { StorageNodeOptions, PutResult } from "./storage-node.js";
export type { StorageConfig, Identity } from "./core.js";
export { defaultConfig, PRODUCTION_BLOCK_SIZE } from "./core.js";
export { STORAGE_APP, STORAGE_PROTO, storageSignScope } from "./manifest.js";
export { toHex, fromHex } from "./util.js";

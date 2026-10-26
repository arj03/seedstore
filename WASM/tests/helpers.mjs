// Shared test scaffolding: the one libsodium, the wasm paths, and the store
// helpers a test reaches around the protocol with. A bundle's modules are
// private to its slot (seedkernel §4), so nothing outside the guest can hold
// or call them directly.

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { concatBytes } from "../build/host/util.js";
import { parseSignedDescriptor } from "../build/host/descriptor-core.js";
import { STORE_REC, STORE_TAG, TIER_COMMITTED, encodeStoreTag, storeRecordHead } from "../build/host/store-record.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
export const root = join(__dirname, "..");

// Storage's own libsodium, one instance for the whole suite (host/sodium.ts).
const { loadSodium, generateKeyPair } = await import(new URL("../build/host/sodium.js", import.meta.url));
const sodium = await loadSodium();

export const paths = {
  codec: join(root, "build/codec.wasm"),
  reputation: join(root, "build/reputation.wasm"),
};

export async function ensureSodium() {
  await sodium.ready;
  return sodium;
}

export function newKey() {
  return generateKeyPair(sodium);
}

/** Count block-ids with ≥1 *live* holder — an online cohort node whose store
 *  holds the id. On the loopback this is the redundancy an audit would measure
 *  (reachable + serves), without a protocol round trip: a test can read every
 *  node's store directly. */
export function liveBlockCount(nodes, net, ids) {
  let live = 0;
  for (const id of ids) {
    for (const n of nodes) {
      if (net.isOnline(n.peerId) && n.store.has(id)) { live++; break; }
    }
  }
  return live;
}

/** Plant a block straight into a node's store, bypassing the protocol —
 *  for tests that need a holder to already have something. Writes the guest's
 *  `<hex>.tag` and `<hex>.rec` (host/store-record.ts) directly, since admission is the
 *  guest holder's alone.
 *
 *  Seed BEFORE the holder is otherwise exercised: the guest rebuilds its §14
 *  byte total from the fs lazily, so a later plant is invisible to it until
 *  the realm is rebuilt. */
export function plantBlock(fs, idHex, bytes, descriptor, tier = TIER_COMMITTED) {
  // A test that only reads the bytes back may plant a stand-in descriptor: charge it to "cohort".
  let group = "cohort";
  try { group = parseSignedDescriptor(descriptor).descriptor.group; } catch { /* a stand-in */ }
  fs.put(idHex + STORE_TAG, encodeStoreTag(tier, descriptor.subarray(0, 32), group));
  fs.put(idHex + STORE_REC, concatBytes([storeRecordHead(descriptor.length), descriptor, bytes]));
}

/** Put `nodes` in one group, `name`, after they booted without a roster. */
export async function joinGroup(nodes, name = "cohort") {
  const groups = { [name]: nodes.map((n) => n.peerId) };
  await Promise.all(nodes.map((n) => n.setGroups(groups)));
}

/** Poll `check` until it holds or `ms` passes, and answer whether it held. A repair lands a
 *  moment after the pass that asked for it, on the repairing node's own wake. */
export async function eventually(check, ms = 5000) {
  const t0 = Date.now();
  while (!(await check())) {
    if (Date.now() - t0 > ms) return false;
    await new Promise((r) => setTimeout(r, 50));
  }
  return true;
}

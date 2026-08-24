// Shared test scaffolding: the one libsodium, the wasm paths, and the store
// helpers a test reaches around the protocol with. A bundle's modules are
// private to its slot (seedkernel §4), so nothing outside the guest can hold
// or call them directly.

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadCrypto } from "seedkernel-wasm";

// One core libsodium instance for the whole stack (§16).
const sodium = await loadCrypto();

const __dirname = dirname(fileURLToPath(import.meta.url));
export const root = join(__dirname, "..");

export const paths = {
  codec: join(root, "build/codec.wasm"),
  reputation: join(root, "build/reputation.wasm"),
};

export async function ensureSodium() {
  await sodium.ready;
  return sodium;
}

export function newKey() {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

/** Count block-ids with ≥1 *live* holder — an online cohort node whose store
 *  holds the id. On the loopback this is the redundancy the old
 *  cohort.liveBlockCount measured (reachable + serves), without a protocol round
 *  trip: a test can read every node's store directly. */
export async function liveBlockCount(nodes, net, ids) {
  let live = 0;
  for (const id of ids) {
    for (const n of nodes) {
      if (net.isOnline(n.peerId) && (await n.store.has(id))) { live++; break; }
    }
  }
  return live;
}

/** Plant a block straight into a node's store.local, bypassing the protocol —
 *  for tests that need a holder to already have something. Writes the
 *  `<hex>.blk`/`.dsc` layout directly, since admission is the guest holder's alone.
 *
 *  Seed BEFORE the holder is otherwise exercised: the guest rebuilds its §14
 *  byte total from the fs lazily, so a later plant is invisible to it until
 *  the realm is rebuilt. */
export async function plantBlock(fs, idHex, bytes, descriptor = null) {
  await fs.put(idHex + ".blk", bytes);
  if (descriptor) await fs.put(idHex + ".dsc", descriptor);
}

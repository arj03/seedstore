// Shared test scaffolding: the one libsodium, the wasm paths, and the store helpers
// a test reaches around the protocol with. There is no module-table helper any more —
// a bundle's modules are private to its slot (seedkernel §4), so nothing outside the
// guest can hold or call them, and no signature wrapper either: authenticity is the
// transport's job (the AKE channel).

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadCrypto } from "seedkernel-wasm";

// One libsodium for the whole stack: the sumo instance the host bundles (§16).
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

/** Plant a block straight into a node's store.local, bypassing the protocol — for
 *  tests that need a holder to already have something (a FETCH to serve, a block to
 *  repair around). There is no host-side write path any more: admission and the quota
 *  are the confined guest holder's alone, so a test writes the `<hex>.blk`/`.dsc`
 *  layout on the fs the guest serves, exactly as the guest itself would.
 *
 *  Seed BEFORE the holder is otherwise exercised: the guest rebuilds its byte total
 *  from the fs lazily, so a plant after it has started counting is invisible to its
 *  §14 accounting until the realm is rebuilt. */
export async function plantBlock(fs, idHex, bytes, descriptor = null) {
  await fs.put(idHex + ".blk", bytes);
  if (descriptor) await fs.put(idHex + ".dsc", descriptor);
}

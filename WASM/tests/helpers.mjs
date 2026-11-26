// Shared test scaffolding: the one libsodium, the wasm paths, and the store
// helpers a test reaches around the protocol with. A bundle's modules are
// private to its slot (seedkernel §4), so nothing outside the guest can hold
// or call them directly.

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { concatBytes } from "../build/host/util.js";
import { AUTH_TAG_LEN, blockHashInput, chunkNonce, parseSignedDescriptor } from "../build/host/descriptor-core.js";
import { Crypto } from "../build/host/crypto.js";
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

/** The guest's block ids and chunk sealing, as the host computes them (`crypto/sha256`,
 *  `crypto/aes256gcm/*`), for tests that check what the guest stored (§4.2, §4.4). */
export const oracle = {
  /** SHA-256 of `bytes`. A block's id is `blockId`, not this. */
  hash: (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest()),
  /** A block's id, bound to the descriptor's author (§4.2). */
  blockId: (authorPk, bytes) => oracle.hash(blockHashInput(authorPk, bytes)),
  /** A padded chunk sealed under K, its tag split off for the descriptor (§4.4). */
  encrypt(K, level, index, message) {
    const c = createCipheriv("aes-256-gcm", K, chunkNonce(level, index));
    const ciphertext = new Uint8Array(Buffer.concat([c.update(message), c.final()]));
    return { ciphertext, authTag: new Uint8Array(c.getAuthTag()) };
  },
  /** The chunk's plaintext, or null when the tag does not verify. */
  decrypt(K, level, index, ciphertext, authTag) {
    if (authTag.length !== AUTH_TAG_LEN) return null;
    const d = createDecipheriv("aes-256-gcm", K, chunkNonce(level, index));
    d.setAuthTag(authTag);
    try {
      return new Uint8Array(Buffer.concat([d.update(ciphertext), d.final()]));
    } catch {
      return null;
    }
  },
};

/** Storage's host `Crypto` (key sharing) with the guest's oracle beside it. */
export function testCrypto(s = sodium) {
  return Object.assign(new Crypto(s), oracle);
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
 *  `<hex>.rec` and, for a cache block, `<hex>.tag` (host/store-record.ts) directly, since
 *  admission is the guest holder's alone.
 *
 *  Seed BEFORE the holder is otherwise exercised: the guest rebuilds its §14
 *  byte total from the fs lazily, so a later plant is invisible to it until
 *  the realm is rebuilt. */
export function plantBlock(fs, idHex, bytes, descriptor, tier = TIER_COMMITTED) {
  // A test that only reads the bytes back may plant a stand-in descriptor, which cannot name
  // its group: tag it, charged to "cohort".
  let group;
  try { group = parseSignedDescriptor(descriptor).descriptor.group; } catch { /* a stand-in */ }
  if (group === undefined || tier !== TIER_COMMITTED) fs.put(idHex + STORE_TAG, encodeStoreTag(tier, descriptor.subarray(0, 32), group ?? "cohort"));
  fs.put(idHex + STORE_REC, concatBytes([storeRecordHead(descriptor.length), descriptor, bytes]));
}

/** Put `nodes` in one group, `name`, after they booted without groups. */
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

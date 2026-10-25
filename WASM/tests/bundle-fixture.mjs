// Build a signed seedstore bundle file on disk for the shell tests (shell-run +
// holder-guest). The bundle *content* is assembled by scripts/storage-bundle.mjs
// — the same code scripts/build-bundle.mjs uses — so the fixture and the real
// producer are byte-identical and cannot drift.

import { writeStorageBundle, authorKeysFor } from "../scripts/storage-bundle.mjs";

/** @param path   where to write the bundle blob (seedkernel §12.4 — one file).
 *  @param build  absolute path to seedstore's build/ dir (holds the codec wasm + the staged guest).
 *  @param version optional manifest freshness mark (seedkernel §12.4); defaults to 1.
 *  @returns the hybrid author id (32 bytes) the bundle was signed under — the key-set
 *           hash, which is what a policy `authors` entry and every host name pin. */
export async function buildBundle(path, author, build, version = 1) {
  const keys = authorKeysFor(author.privateKey);
  return writeStorageBundle({ path, sk: keys.ed.privateKey, build, version }).author;
}

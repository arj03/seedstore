// Build a signed seedstore bundle directory on disk for the shell tests (shell-run
// + holder-guest). The bundle *content* is assembled by scripts/storage-bundle.mjs
// — the same code scripts/build-bundle.mjs uses — so the fixture and the real
// producer are byte-identical and cannot drift. The module kernel names are derived
// deterministically, so they match what a shell's own host (and the guest's
// APP.codecName/repName) resolve to.

import { join } from "node:path";

import { loadKernelHost } from "seedkernel-wasm";
import { writeStorageBundle } from "../scripts/storage-bundle.mjs";

/** @param build absolute path to seedstore's build/ dir (holds kernel/codec wasm + the staged guest).
 *  @param version optional manifest freshness mark (README §12.4); defaults to 1. */
export async function buildBundle(dir, author, sodium, build, version = 1) {
  const { host } = await loadKernelHost(join(build, "kernel.wasm"), join(build, "signature.wasm"));
  writeStorageBundle({ dir, host, sodium, sk: author.privateKey, pk: author.publicKey, build, version });
}

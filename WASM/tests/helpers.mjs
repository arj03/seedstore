// Shared test scaffolding: load a KernelHost (from the sibling seedkernel
// build) with the installer wired, plus install helpers. Mirrors seedkernel's
// tests/run.mjs makeHost/buildInstall. There is no signature wrapper any more —
// authenticity is the transport's job (the AKE channel), so the kernel carries
// no per-message signing (seedkernel "Drop the whole envelope + signing").

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { KernelHost, referencePolicy, loadSodium } from "seedkernel-wasm";

// One libsodium for the whole stack: the sumo instance the kernel bundles (§16).
const sodium = await loadSodium();

const __dirname = dirname(fileURLToPath(import.meta.url));
export const root = join(__dirname, "..");

export const paths = {
  kernel: join(root, "build/kernel.wasm"),
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

/** A KernelHost with the module registry + an allow-all reference policy (any
 *  author may bind a name) — the trusted single-deployment posture of a reference
 *  node. No signature wrapper: authenticity is the transport's job now. */
export async function loadHost() {
  await sodium.ready;
  const kernel = readFileSync(paths.kernel);
  const host = await KernelHost.load(kernel, sodium);
  host.registerInstaller();
  host.setApproveInstall(referencePolicy(host, () => true));
  return { host };
}

/** Count block-ids with ≥1 *live* holder — an online cohort node whose store
 *  holds the id. On the loopback this is the redundancy the old
 *  cohort.liveBlockCount measured (reachable + serves), without a protocol round
 *  trip: a test can read every node's store directly. */
export function liveBlockCount(nodes, net, ids) {
  return ids.filter((id) => nodes.some((n) => net.isOnline(n.peerId) && n.store.has(id))).length;
}

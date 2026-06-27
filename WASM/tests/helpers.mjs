// Shared test scaffolding: load a KernelHost (from the sibling seedkernel
// build) with the signature wrapper + installer wired, plus install helpers.
// Mirrors seedkernel's tests/run.mjs makeHost/buildInstall.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { KernelHost, referencePolicy, CURRENT_VERSION, loadSodium } from "seedkernel-wasm";

// One libsodium for the whole stack: the sumo instance the kernel bundles (§16).
const sodium = await loadSodium();

const __dirname = dirname(fileURLToPath(import.meta.url));
export const root = join(__dirname, "..");
export const kernelRoot = join(root, "..", "..", "seedkernel", "WASM");

export const paths = {
  kernel: join(root, "build/kernel.wasm"),
  bootstrap: join(root, "build/bootstrap.wasm"),
  codec: join(root, "build/codec.wasm"),
  reputation: join(root, "build/reputation.wasm"),
  forwarder: join(kernelRoot, "build/forwarder.wasm"),
};

export async function ensureSodium() {
  await sodium.ready;
  return sodium;
}

export function newKey() {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export { CURRENT_VERSION };

/** A KernelHost with signature + installer + an allow-all reference policy
 *  (first install + capability acknowledgement both granted) — the trusted
 *  single-deployment posture of a reference node. */
export async function loadHost() {
  await sodium.ready;
  const kernel = readFileSync(paths.kernel);
  const boot = readFileSync(paths.bootstrap);
  const host = await KernelHost.load(kernel, boot, sodium);
  const signatureName = host.deriveBootstrapName("signature");
  const installName = host.deriveBootstrapName("install");
  const lookupName = host.deriveBootstrapName("installer.lookup");
  const capsOfName = host.deriveBootstrapName("installer.caps_of");
  host.registerSignature(signatureName);
  host.registerInstaller(installName, lookupName, capsOfName);
  host.setApproveInstall(referencePolicy(host, () => true, () => true));
  return { host, installName };
}

let seqCounter = 0;
/** Monotonic seq per signer for §4.4 replay protection. */
export function makeSeq() {
  const counters = new Map();
  return (pk) => {
    const k = [...pk].join(",");
    const next = (counters.get(k) ?? 0) + 1;
    counters.set(k, next);
    return next;
  };
}

/** Install a WASM handler under targetName, signed by (sk, pk), declaring caps.
 *  Returns true if the kernel slot is now registered. */
export function installWasm(host, installName, sk, pk, seq, targetName, caps, wasmBytes) {
  const payload = host.encodeInstallPayload(seq, targetName, caps, null, wasmBytes);
  host.dispatch(host.wrapAndEncode(sk, pk, CURRENT_VERSION, installName, payload));
  return host.isRegistered(targetName);
}

export const wasmBytes = {
  forwarder: () => new Uint8Array(readFileSync(paths.forwarder)),
  codec: () => new Uint8Array(readFileSync(paths.codec)),
  reputation: () => new Uint8Array(readFileSync(paths.reputation)),
};

/** Count block-ids with ≥1 *live* holder — an online cohort node whose store
 *  holds the id. On the loopback this is the redundancy the old
 *  cohort.liveBlockCount measured (reachable + serves), without a protocol round
 *  trip: a test can read every node's store directly. */
export function liveBlockCount(nodes, net, ids) {
  return ids.filter((id) => nodes.some((n) => net.isOnline(n.peerId) && n.store.has(id))).length;
}

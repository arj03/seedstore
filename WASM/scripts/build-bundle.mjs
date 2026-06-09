// Build the seedstore app bundle (the runtime split): the signed
// content a generic seedkernel-shell loads to *become* a storage node —
// codec.wasm + reputation.wasm + tier2-guest.js + a signed manifest declaring the
// op catalog and required caps. The shell verifies + governs + installs it; this
// script is the offline producer that holds the author key.
//
//   node scripts/build-bundle.mjs            (writes ./bundle, signs with ./seedstore-author.key)
//
// Output (a directory the shell loads with --bundle):
//   bundle/manifest.bundle   signed manifest envelope
//   bundle/codec.wasm  bundle/reputation.wasm  bundle/tier2-guest.js
//   bundle/codec.install  bundle/reputation.install   author-signed install envelopes
//
// Run `npm run build` first so build/ holds the compiled host + wasm.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadKernelHost, loadSodium, CURRENT_VERSION } from "seedkernel-wasm";
import { signManifest } from "seedkernel-wasm/bundle";
import { CAP } from "seedkernel-wasm/cap-bridge";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const build = join(root, "build");
const out = join(root, "bundle");

const { storageNames } = await import(new URL("../build/host/names.js", import.meta.url));
const { defaultConfig } = await import(new URL("../build/host/core.js", import.meta.url));
const { toHex, fromHex } = await import(new URL("../build/host/util.js", import.meta.url));

const sodium = await loadSodium();
const host = await loadKernelHost(join(build, "kernel.wasm"), join(build, "bootstrap.wasm"));
// Needed to sign install envelopes (wrapAndEncode); this host is offline scaffolding.
host.registerSignature(host.deriveBootstrapName("signature"));

// Author identity: the key the bundle is signed with (and that installs are
// signed with). A deployment's policy lists this public key as an allowed author.
const keyPath = join(root, "seedstore-author.key");
let sk, pk;
if (existsSync(keyPath)) {
  sk = fromHex(readFileSync(keyPath, "utf8").trim());
  pk = sk.slice(32);
} else {
  const kp = sodium.crypto_sign_keypair();
  sk = kp.privateKey; pk = kp.publicKey;
  writeFileSync(keyPath, toHex(sk), { mode: 0o600 });
  console.log(`  minted author key → ${keyPath}`);
}

const names = storageNames(host);
const installName = host.deriveBootstrapName("install");

// The two pure handlers (§17): no declared caps. Each install is signed by the
// author so the shell can dispatch it verbatim through its policy gate.
const modSpecs = [
  { name: "codec", file: "codec.wasm", kernelName: names.codec },
  { name: "reputation", file: "reputation.wasm", kernelName: names.reputation },
];

mkdirSync(out, { recursive: true });

let seq = 0;
const modules = modSpecs.map((m) => {
  const wasm = new Uint8Array(readFileSync(join(build, m.file)));
  const payload = host.encodeInstallPayload(++seq, m.kernelName, [], null, wasm);
  const install = host.wrapAndEncode(sk, pk, CURRENT_VERSION, installName, payload);
  writeFileSync(join(out, m.file), wasm);
  writeFileSync(join(out, `${m.name}.install`), install);
  console.log(`  ${m.name}: install bytesHash ${toHex(host.genesisHash(payload))}`); // for the operator's policy.modules
  return {
    name: m.name, file: m.file, hash: toHex(host.genesisHash(wasm)),
    install: `${m.name}.install`, kernelName: toHex(m.kernelName),
  };
});

// The zero-authority orchestration guest (raw; the host injects the op preamble).
const guestText = readFileSync(join(root, "host", "tier2-guest.js"), "utf8");
writeFileSync(join(out, "tier2-guest.js"), guestText);

const cfg = defaultConfig();
const manifest = {
  app: "seedstore",
  version: "1",
  modules,
  guest: { file: "tier2-guest.js", hash: toHex(host.genesisHash(new TextEncoder().encode(guestText))) },
  // The runtime's generic seam (seedkernel cap-bridge). The shell builds the
  // guest's CAP_* preamble from its own copy; this is here for the manifest to be
  // self-describing.
  ops: { ...CAP },
  // Capabilities the guest reaches through the generic cap-bridge. crypto/clock
  // are no-cap primitives; net + fs (store) are the gated ones.
  caps: [names.capStore, names.capNet, names.capClock, names.capRand].map(toHex),
  // App constants the shell injects into the guest as `const APP = …`: the
  // storage dial + the codec/reputation kernel names the guest module-calls.
  config: {
    k: cfg.k, m: cfg.m, blockSize: cfg.blockSize,
    replicas: cfg.replicas, lowWater: cfg.lowWater, smallMaxBlocks: cfg.smallMaxBlocks,
    // The holder's byte budget (§14): a serving shell admits/stores under this,
    // the same default a StorageNode uses. A deployment tunes it per node.
    quota: 64 * 1024 * 1024,
    codecName: toHex(names.codec), repName: toHex(names.reputation),
  },
};

writeFileSync(join(out, "manifest.bundle"), signManifest(sodium, sk, pk, manifest));

console.log(`  author ${toHex(pk)}`);
console.log(`  wrote ${out} (app ${manifest.app} v${manifest.version}, ${modules.length} modules, ${Object.keys(CAP).length} ops)`);

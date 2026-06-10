// Build the seedstore app bundle (the runtime split): the signed
// content a generic seedkernel-shell loads to *become* a storage node —
// codec.wasm + reputation.wasm + tier2-guest.js + a signed manifest declaring the
// op catalog and required caps. The shell verifies + governs + installs it; this
// script is the offline producer that holds the author key. The bundle *content*
// (modules/guest/ops/caps/config) is assembled in scripts/storage-bundle.mjs, the
// one place the test fixture also uses, so the two can never drift.
//
//   node scripts/build-bundle.mjs            (writes ./bundle, signs with ./seedstore-author.key)
//
// Output (a directory the shell loads with --bundle):
//   bundle/manifest.bundle   signed manifest envelope
//   bundle/codec.wasm  bundle/reputation.wasm  bundle/tier2-guest.js
//   bundle/codec.install  bundle/reputation.install   author-signed install envelopes
//
// Run `npm run build` first so build/ holds the compiled host + wasm.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadKernelHost, loadSodium } from "seedkernel-wasm";
import { CAP } from "seedkernel-wasm/cap-bridge";
import { writeStorageBundle } from "./storage-bundle.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const build = join(root, "build");
const out = join(root, "bundle");

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

const manifest = writeStorageBundle({ dir: out, host, sodium, sk, pk, build, log: console.log });

console.log(`  author ${toHex(pk)}`);
console.log(`  wrote ${out} (app ${manifest.app} v${manifest.version}, ${manifest.modules.length} modules, `
  + `${Object.keys(CAP).length} ops, caps ${manifest.caps.join("+")})`);

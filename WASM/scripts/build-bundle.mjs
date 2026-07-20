// Build the seedstore app bundle (the runtime split): the signed
// content a generic seedkernel-shell loads to *become* a storage node —
// codec.wasm + reputation.wasm + tier2-guest.js + a signed manifest declaring the
// required caps. The shell verifies + governs + installs it; this script is the
// offline producer that holds the author key. The bundle *content*
// (modules/guest/caps/config) is assembled in scripts/storage-bundle.mjs, the
// one place the test fixture also uses, so the two can never drift.
//
//   node scripts/build-bundle.mjs            (writes ./bundle, signs with ./seedstore-author.key)
//
// Output (a directory the shell loads with --bundle):
//   bundle/manifest.bundle   signed manifest envelope
//   bundle/codec.wasm  bundle/reputation.wasm  bundle/tier2-guest.js
// The signed manifest commits to each module's hash; the shell verifies the bytes
// against it and installs them directly (seedkernel §12.4).
//
// Run `npm run build` first so build/ holds the compiled host + wasm.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createKernelHost, loadSodium } from "seedkernel-wasm";
import { verifyManifest } from "seedkernel-wasm/bundle";
import { writeStorageBundle } from "./storage-bundle.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const build = join(root, "build");
const out = join(root, "bundle");

const { toHex, fromHex } = await import(new URL("../build/host/util.js", import.meta.url));

const sodium = await loadSodium();
const host = await createKernelHost();
// This host is offline scaffolding — used only to derive the module kernel names and
// hash the module bytes (genesisHash) the manifest commits to; it signs nothing.

// Author identity: the key the bundle is signed with (and that installs are
// signed with). A deployment's policy lists this public key as an allowed author.
const keyPath = join(root, "seedstore-author.key");
const versionPath = join(root, "seedstore-author.version");
let sk, pk, mintedKey = false;
if (existsSync(keyPath)) {
  sk = fromHex(readFileSync(keyPath, "utf8").trim());
  pk = sk.slice(32);
} else {
  const kp = sodium.crypto_sign_keypair();
  sk = kp.privateKey; pk = kp.publicKey;
  writeFileSync(keyPath, toHex(sk), { mode: 0o600 });
  mintedKey = true;
  console.log(`  minted author key → ${keyPath}`);
}

// Freshness (README §12.4): the manifest `version` is a monotonic integer the shell
// enforces as a high-water mark, so a redeploy must bump it or a deployed shell refuses it
// as a downgrade. Persist the mark NEXT TO THE AUTHOR KEY — the key is what defines the
// (author, app) namespace the version is monotonic within, and it persists where bundle/ is
// gitignored + rebuilt. Deriving the mark from bundle/manifest.bundle (as before) silently
// restarts at 1 after a `git clean`, a fresh checkout, or a build on a second machine — and
// every deployed shell then correctly rejects the next publish as a downgrade. The key +
// version file travel together (both out of git); copy one to another machine, copy both.
const prevManifest = join(out, "manifest.bundle");
let prevVersion = 0;
if (existsSync(versionPath)) {
  const v = Number(readFileSync(versionPath, "utf8").trim());
  if (Number.isInteger(v) && v > 0) prevVersion = v;
} else if (existsSync(prevManifest)) {
  // Older tree with no version file yet: seed the mark from the last built bundle.
  try {
    const prev = verifyManifest(sodium, new Uint8Array(readFileSync(prevManifest)));
    if (prev && Number.isInteger(prev.manifest.version)) prevVersion = prev.manifest.version;
  } catch { /* unreadable / pre-integer version → treat as none */ }
} else if (!mintedKey) {
  // The dangerous case: a persisted key (an established namespace) but no record of how far
  // its version has been published. Warn loudly rather than quietly restart at 1.
  console.warn(
    `  ⚠ author key exists but no version high-water mark (${versionPath}) and no prior bundle in ${out} — ` +
    `restarting version at 1.\n` +
    `    If you have already published under this author, a deployed shell will REFUSE this bundle as a ` +
    `downgrade (README §12.4). Put the real last-published version number in ${versionPath} and re-run.`);
}
const version = prevVersion + 1;

const manifest = writeStorageBundle({ dir: out, host, sodium, sk, pk, build, version, log: console.log });

// Record the new high-water mark beside the key, so the next publish counts on from here
// even if bundle/ is wiped.
writeFileSync(versionPath, `${manifest.version}\n`);

console.log(`  author ${toHex(pk)}`);
console.log(`  wrote ${out} (app ${manifest.app} v${manifest.version}, ${manifest.modules.length} modules, `
  + `caps ${manifest.caps.join("+")})`);

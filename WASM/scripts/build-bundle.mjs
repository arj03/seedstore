// Build the seedstore app bundle: the signed content a generic seedkernel-shell
// loads to *become* a storage node — codec.wasm + reputation.wasm +
// tier2-guest.js + a signed manifest declaring the guest's required services.
// This script is the offline producer holding the author key; bundle content is assembled in
// scripts/storage-bundle.mjs (shared with the test fixture, so they can't drift).
//
//   node scripts/build-bundle.mjs   (writes ./bundle, signs with ./seedstore-author.key)
//
// Output: bundle/seedstore.skb — manifest, guest and modules under one signature
// (seedkernel §12.4). Run `npm run build` first.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadCrypto } from "seedkernel-wasm";
import { writeStorageBundle } from "./storage-bundle.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const build = join(root, "build");
const out = join(root, "bundle");
const bundlePath = join(out, "seedstore.skb");

const { toHex, fromHex } = await import(new URL("../build/host/util.js", import.meta.url));

const sodium = await loadCrypto();
// The host's crypto, which mints the author key and reads back a prior bundle;
// storage-bundle.mjs signs with it too. No seedkernel host is needed.

// Author identity: the key the bundle is signed with (and that installs are
// signed with). Policy pins the derived key-set id (seedkernel §12.4), not this Ed25519 key.
const keyPath = join(root, "seedstore-author.key");
const versionPath = join(root, "seedstore-author.version");
let sk, mintedKey = false;
if (existsSync(keyPath)) {
  sk = fromHex(readFileSync(keyPath, "utf8").trim());
} else {
  const kp = sodium.crypto_sign_keypair();
  sk = kp.privateKey;
  writeFileSync(keyPath, toHex(sk), { mode: 0o600 });
  mintedKey = true;
  console.log(`  minted author key → ${keyPath}`);
}

// Freshness (seedkernel §12.4): manifest `version` is a monotonic high-water mark a
// deployed shell enforces. Persisted NEXT TO THE AUTHOR KEY (not derived from
// bundle/, which is gitignored and gets wiped) so it survives a `git clean` or a
// build on a second machine. Key + version file travel together.
let prevVersion = 0;
if (existsSync(versionPath)) {
  const v = Number(readFileSync(versionPath, "utf8").trim());
  if (Number.isInteger(v) && v > 0) prevVersion = v;
} else if (!mintedKey) {
  // The dangerous case: a persisted key (an established namespace) but no record of how far
  // its version has been published. Warn loudly rather than quietly restart at 1.
  console.warn(
    `  ⚠ author key exists but no version high-water mark (${versionPath}) — ` +
    `restarting version at 1.\n` +
    `    If you have already published under this author, a deployed shell will REFUSE this bundle as a ` +
    `downgrade (seedkernel §12.4). Put the real last-published version number in ${versionPath} and re-run.`);
}
const version = prevVersion + 1;

const { manifest, author } = writeStorageBundle({ path: bundlePath, sk, build, version });

// Record the new high-water mark beside the key, so the next publish counts on from here
// even if bundle/ is wiped.
writeFileSync(versionPath, `${manifest.version}\n`);

// The pinned id is the derived author id (the key-set hash, seedkernel §12.4) — a manifest is
// signed by both halves of the key set, so the Ed25519 key is not what policy lists.
// It is carried on the writeStorageBundle value, not re-derived here.
console.log(`  author ${toHex(author)} (hybrid 0x02)`);
console.log(`  wrote ${bundlePath} (app ${manifest.app} v${manifest.version}, ${manifest.modules.length} modules, `
  + `requires ${manifest.guest.requires.join("+") || "nothing"})`);

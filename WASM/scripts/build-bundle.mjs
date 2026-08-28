// Build the seedstore app bundle: the signed content a generic seedkernel-shell
// loads to *become* a storage node — codec.wasm + reputation.wasm +
// tier2-guest.js + a signed manifest declaring the guest's required services.
// This script is
// the offline producer holding the author key; bundle content is assembled in
// scripts/storage-bundle.mjs (shared with the test fixture, so they can't drift).
//
//   node scripts/build-bundle.mjs   (writes ./bundle, signs with ./seedstore-author.key)
//
// Output: bundle/seedstore.skb — the signed manifest + all modules packed into
// one blob (seedkernel §12.4). Run `npm run build` first.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadCrypto } from "seedkernel-wasm";
import { verifyBundle } from "seedkernel-wasm/bundle";
import { writeStorageBundle } from "./storage-bundle.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const build = join(root, "build");
const out = join(root, "bundle");
const bundlePath = join(out, "seedstore.skb");

const { toHex, fromHex } = await import(new URL("../build/host/util.js", import.meta.url));

const sodium = await loadCrypto();
// Bundle *content* is assembled below from sodium alone: it hashes the module bytes
// (genesisHash) the manifest commits to and signs the manifest. No kernel host is needed —
// hashing is a free `genesisHash(sodium, …)` in the bundle module now, and a module's
// name is its bare manifest name — reached by the guest on the seam, slot-local, with
// no bind name or global namespace (seedkernel §5.1).

// Author identity: the key the bundle is signed with (and that installs are
// signed with). Policy pins the derived key-set id (§12.4), not this Ed25519 key.
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

// Freshness (README §12.4): manifest `version` is a monotonic high-water mark a
// deployed shell enforces. Persisted NEXT TO THE AUTHOR KEY (not derived from
// bundle/, which is gitignored and gets wiped) so it survives a `git clean` or a
// build on a second machine. Key + version file travel together.
let prevVersion = 0;
if (existsSync(versionPath)) {
  const v = Number(readFileSync(versionPath, "utf8").trim());
  if (Number.isInteger(v) && v > 0) prevVersion = v;
} else if (existsSync(bundlePath)) {
  // Older tree with no version file yet: seed the mark from the last built bundle.
  try {
    const prev = verifyBundle(sodium, new Uint8Array(readFileSync(bundlePath)));
    if (Number.isInteger(prev.manifest.version)) prevVersion = prev.manifest.version;
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

const { manifest, author } = writeStorageBundle({ path: bundlePath, sodium, sk, build, version, log: console.log });

// Record the new high-water mark beside the key, so the next publish counts on from here
// even if bundle/ is wiped.
writeFileSync(versionPath, `${manifest.version}\n`);

// The pinned id is the derived author id (the key-set hash, §12.4) — a manifest is
// signed by both halves of the key set, so the Ed25519 key is not what policy lists.
// It is carried on the writeStorageBundle value, not re-derived here.
console.log(`  author ${toHex(author)} (hybrid 0x02)`);
console.log(`  wrote ${bundlePath} (app ${manifest.app} v${manifest.version}, ${manifest.modules.length} modules, `
  + `requires ${manifest.guest.requires.join("+")}, calls ${(manifest.guest.calls ?? []).join("+") || "nothing"})`);

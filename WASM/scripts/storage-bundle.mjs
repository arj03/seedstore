// The single source of truth for a seedstore app bundle's *content* — shared by
// the offline producer (scripts/build-bundle.mjs) and the test fixture
// (tests/bundle-fixture.mjs) so the two can never drift. Writes one signed blob
// holding each module's wasm, the guest, and the signed manifest envelope; the
// manifest commits to every module's genesisHash (seedkernel §12.4, §5.1).
//
// Three deliberate choices:
//   • `requires` declares fine-grained authority NAMES, not capability domains —
//     the shell enforces them as the exact set a guest's host.call may reach.
//   • `abi` is read from the runtime constant (seedkernel §12.2), never a
//     literal, so a seam change fails this build, not a node's first request.
//   • `quota` and anything runtime-derived (e.g. the signing scope) are absent
//     from the signed config — both are host-applied facts, never author content.

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";

import { signManifest, hybridAuthorKeysFromSeed, packBundle, genesisHash, MANIFEST_FILE, GUEST_FILE, moduleFile }
  from "seedkernel-wasm/bundle";
import { GUEST_ABI_VERSION } from "seedkernel-wasm/guest-seam";
import { defaultConfig, PRODUCTION_BLOCK_SIZE } from "../build/host/core.js";
import { STORAGE_PROTO } from "../build/host/manifest.js";
import { toHex } from "../build/host/util.js";

// The app name — the manifest `app` and the `app` component of the signing scope
// (README §16). The shell scopes the guest's SIGN/VERIFY ops to (author, app);
// the host-side mirror derives the byte-identical scope from the same app name.
const APP_NAME = "seedstore";

/**
 * The author's full key set: Ed25519 + ML-DSA-65, both from the ONE seed an
 * operator stores, so the pinned id (`hybridAuthorId`) is stable across
 * rebuilds. A thin call on seedkernel's `hybridAuthorKeysFromSeed` so this
 * bundle derives it the same way the runtime and other apps do.
 *
 * @param {any}    sodium  loaded libsodium with the ML-DSA-65 signer mixed in
 * @param {Uint8Array} edSk  the author's 64-byte Ed25519 secret key (seed‖pk)
 */
export function authorKeysFor(sodium, edSk) {
  return hybridAuthorKeysFromSeed(sodium, edSk.slice(0, 32));
}

// The grants the storage guest reaches, EXACTLY (`guest.requires`): a `host.call`
// naming a grant outside this list is refused at the bridge. Two kinds: the
// host's own authorities (`node/sign`/`node/verify` scoped to this bundle's
// (author, app), `node/identity`, `node/random`, `fs/*`, the clock), and the one
// local service name `_net` — the network is a bundle (the transport) claiming
// that id, reached via one cross-realm call (§12.10), carrying no privilege.
//
// Pure transforms (BLAKE2b, XChaCha20, and this bundle's own codec/reputation
// modules) are not grants — ungated on the `crypto/` prefix (seedkernel §12.1)
// and never listed here.
const STORAGE_REQUIRES = [
  "node/sign", "node/verify", "node/identity", "node/random",
  "_net",
  "fs/get", "fs/put", "fs/list", "fs/size",
  "clock/now",
];

/**
 * Write a complete signed seedstore bundle to `path` (one blob, seedkernel §12.4).
 * The manifest is signed under suite `0x02` (hybrid Ed25519 + ML-DSA-65): the
 * author's PQ half is derived from the same seed (see `authorKeysFor`), so the
 * pinned author id is the key-set hash and the bundle is post-quantum by default.
 * @param {object} o
 * @param {string} o.path     output bundle file (e.g. ./bundle/seedstore.skb)
 * @param {any}    o.sodium   loaded libsodium (hashes the module bytes; signs the manifest)
 * @param {Uint8Array} o.sk   author secret key — the Ed25519 half (signs the manifest)
 * @param {Uint8Array} o.pk   author public key
 * @param {string} o.build    seedstore build/ dir (holds the codec wasm + staged guest)
 * @param {number} [o.version] monotonic-per-(author,app) freshness mark (README §12.4);
 *                             the shell refuses a load below its high-water mark. Integer.
 * @param {(s:string)=>void} [o.log]  optional progress logger
 * @returns the manifest object that was signed (for logging/inspection).
 */
export function writeStorageBundle({ path, sodium, sk, pk, build, version = 1, log = () => {} }) {
  if (!Number.isInteger(version)) throw new Error("writeStorageBundle: version must be an integer");
  // The loader derives each module's kernel name from `(app, name)` (seedkernel
  // §5.1), so there is no bind name to state here.
  const modSpecs = ["codec", "reputation"];
  const files = {};

  // The two pure handlers (§17); the manifest commits to each module's genesisHash.
  const modules = modSpecs.map((name) => {
    const wasm = new Uint8Array(readFileSync(join(build, moduleFile(name))));
    files[moduleFile(name)] = wasm;
    const hash = toHex(genesisHash(sodium, wasm));
    log(`  ${name}: bytesHash ${hash}`);
    return { name, hash };
  });

  // Ship the comment-stripped guest (scripts/minify.mjs, `node --check`-gated) to
  // keep the signed bundle small; the content hash below covers these exact bytes.
  const guestText = readFileSync(join(build, "host-min", "tier2-guest.js"), "utf8");
  files[GUEST_FILE] = new TextEncoder().encode(guestText);

  // Must carry PRODUCTION geometry — defaultConfig()'s bare blockSize is
  // test-scale (256 bytes); leaking that in here once chunked a 10 MB file into
  // ~41k blocks. PRODUCTION_BLOCK_SIZE keeps this site and the CLI from drifting.
  const cfg = defaultConfig(undefined, undefined, PRODUCTION_BLOCK_SIZE);
  const manifest = {
    app: APP_NAME,
    // Monotonic freshness mark per (author, app): the shell refuses a downgrade
    // below its high-water mark (README §12.4). Bump on every publish.
    version,
    // The wire protocol this app serves (seedkernel §12.10), read from the same
    // STORAGE_PROTO constant the guest names in every request (NET_PROTO), so
    // sender and receiver can't drift apart.
    protocols: [STORAGE_PROTO],
    modules,
    guest: {
      hash: toHex(genesisHash(sodium, files[GUEST_FILE])),
      // Read from the runtime, not a literal, so a seam change breaks this
      // build rather than surfacing as a wrong answer at the first host.call.
      abi: GUEST_ABI_VERSION,
      requires: [...STORAGE_REQUIRES],
      // The AUTHOR's config, injected as `const APP = …` exactly as signed. The
      // shell merges nothing into it; LOCAL (operator settings) arrives beside
      // it and the guest's CFG picks precedence. No `quota` here — LOCAL-only.
      config: {
        k: cfg.k, m: cfg.m, blockSize: cfg.blockSize,
        maxMessageBytes: cfg.maxMessageBytes,
        fanoutWindow: cfg.fanoutWindow,
        windowTargetBytes: cfg.windowTargetBytes,
      },
    },
  };

  files[MANIFEST_FILE] = signManifest(sodium, authorKeysFor(sodium, sk), manifest);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, packBundle(files));
  return manifest;
}

// The single source of truth for a seedstore app bundle's *content* — shared by
// the offline producer (scripts/build-bundle.mjs) and the test fixture
// (tests/bundle-fixture.mjs) so the two can never drift. Writes one signed blob:
// the manifest, the guest and each module's wasm, all under one hybrid signature
// (seedkernel §12.4, §5.1).
//
// Two deliberate choices:
//   • `requires` declares SERVICES, not method names — the unit a manifest grants
//     is `node`/`fs` (and a local service id), never `node/sign` or `fs/get`.
//     The host gates a `host.call` by the method's SERVICE (seedkernel §12.2).
//   • `quota` and anything runtime-derived (e.g. the signing scope) are absent
//     from the signed config — both are host-applied facts, never author content.

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";

import { authorBundle, hybridAuthorKeysFromSeed }
  from "seedkernel-wasm/bundle-author";
import { TRANSPORT_SERVICE } from "seedkernel-wasm/transport-bundle";
import { defaultConfig, normaliseConfig, PRODUCTION_BLOCK_SIZE } from "../build/host/core.js";
import { STORAGE_PROTO } from "../build/host/descriptor.js";

// The app label — the manifest `app`, and the whole of the signing scope (README
// §16). The host scopes the guest's SIGN/VERIFY ops to this label, whoever signed the
// bundle; the host-side mirror derives the byte-identical scope from the same label.
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

// Everything the storage guest reaches, EXACTLY (`guest.requires`): a `host.call`
// naming a host method is refused unless the method's SERVICE is in this list, and a
// local service id is callable only when it is listed here.
//   • `node` — sign/verify scoped to this bundle's app label.
//   • `fs` — this app's own keyspace.
//   • the network — a bundle (the transport) claiming `_net` under its own `services`
//     list, reached over the same `host.call` by one cross-realm call (§12.10).
//
// Pure transforms (BLAKE2b, ChaCha20-Poly1305, entropy, and this bundle's own
// codec/reputation modules) are not grants and are never listed here; time is the
// realm's own `Date.now()`.
const STORAGE_REQUIRES = [
  "node",
  "fs",
  TRANSPORT_SERVICE,
];

/**
 * Write a complete signed seedstore bundle to `path` (one blob, seedkernel §12.4).
 * The bundle is signed under suite `0x02` (hybrid Ed25519 + ML-DSA-65): the
 * author's PQ half is derived from the same seed (see `authorKeysFor`), so the
 * pinned author id is the key-set hash and the bundle is post-quantum by default.
 * @param {object} o
 * @param {string} o.path     output bundle file (e.g. ./bundle/seedstore.skb)
 * @param {any}    o.sodium   loaded libsodium with the ML-DSA-65 signer (signs the bundle)
 * @param {Uint8Array} o.sk   author secret key — the Ed25519 half, whose seed derives both
 * @param {string} o.build    seedstore build/ dir (holds the codec wasm + staged guest)
 * @param {number} [o.version] monotonic-per-(author,app) freshness mark (README §12.4);
 *                             the host refuses a load below its high-water mark. Integer.
 * @returns {{blob: Uint8Array, manifest: object, author: Uint8Array}} the signed blob,
 *  the manifest that was signed, and the derived author id — the key-set hash a policy
 *  `authors` entry pins, on the value rather than re-derived by the caller.
 */
export function writeStorageBundle({ path, sodium, sk, build, version = 1 }) {
  if (!Number.isInteger(version)) throw new Error("writeStorageBundle: version must be an integer");
  // A module's name is its bare manifest name — the seam argument the guest
  // passes; there is no bind name or global namespace (seedkernel §5, §12.4).
  const modSpecs = ["codec", "reputation"];

  // The two pure modules (§17), as the build writes them.
  const modules = modSpecs.map((name) => ({
    name, wasm: new Uint8Array(readFileSync(join(build, `${name}.wasm`))),
  }));

  // Ship the comment-stripped guest (scripts/minify.mjs, `node --check`-gated) to
  // keep the signed bundle small; the signature covers these exact bytes (the guest
  // is authored as TEXT — what verification decodes back, bundle.ts).
  const guestSource = readFileSync(join(build, "host-min", "tier2-guest.js"), "utf8");

  // This is a DEPLOYED config, so it carries production geometry; one named constant
  // keeps this site and the CLI from drifting apart. normaliseConfig then fills the
  // derived windowTargetBytes the SAME way boot does — without it the key copies
  // `undefined`, which the signed manifest silently DROPS, so what is signed omits a
  // field the author just declared (and authorBundle refuses: a non-JSON value
  // cannot be signed).
  const cfg = normaliseConfig(defaultConfig(PRODUCTION_BLOCK_SIZE));

  const { blob, manifest, author } = authorBundle(sodium, authorKeysFor(sodium, sk), {
    app: APP_NAME,
    // Monotonic freshness mark per (author, app): the host refuses a downgrade
    // below its high-water mark (README §12.4). Bump on every publish.
    version,
    // The wire protocol this app serves (seedkernel §12.10), read from the same
    // STORAGE_PROTO constant the guest names in every request (NET_PROTO), so
    // sender and receiver can't drift apart.
    protocols: [STORAGE_PROTO],
    modules,
    guestSource,
    guestRequires: [...STORAGE_REQUIRES],
    // The AUTHOR's config, injected as `const APP = …` exactly as signed. The
    // host merges nothing into it; LOCAL (operator settings) arrives beside
    // it and the guest's CFG picks precedence. No `quota` here — LOCAL-only.
    guestConfig: {
      k: cfg.k, m: cfg.m, blockSize: cfg.blockSize,
      maxMessageBytes: cfg.maxMessageBytes,
      fanoutWindow: cfg.fanoutWindow,
      windowTargetBytes: cfg.windowTargetBytes,
    },
  });

  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, blob);
  return { blob, manifest, author };
}

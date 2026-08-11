// The single source of truth for a seedstore app bundle's *content* — shared by
// the offline producer (scripts/build-bundle.mjs) and the test fixture
// (tests/bundle-fixture.mjs) so the two can never drift (the `caps` field used to).
// Given a kernel host + author key + the build dir, it writes the bundle: one signed
// blob holding each module's wasm, the guest, and the signed manifest envelope. The
// manifest commits to every module's genesisHash, so the shell installs the verified
// bytes at the kernel name it derives from the signed `(app, name)` pair — the manifest
// declares no bind name (seedkernel §12.4, §5.1).
//
// Three deliberate choices live here, once:
//   • `requires` declares the fine-grained authority *names* (seedkernel
//     AUTHORITY_CALLS keys), not capability domains. The shell enforces them as the
//     exact set a guest's host.call may reach, and wires only the matching backends.
//     Storage reaches the node identity/signing/random, net send/peers, fs
//     get/put/list/size and the clock — nothing more. (There is no `ops` catalog in
//     the manifest — the guest's ABI is the shared name-addressed preamble, not
//     signed content; the grant is `requires`.) It lives
//     inside `guest`, where the authority it grants does.
//   • `abi` names the guest seam this program was written against (seedkernel §12.2).
//     Not a version of the bundle or of storage — of the HOST contract the guest calls
//     through — so it is the constant the runtime exports, never a literal here: a seam
//     change must fail this build, not this node's first request.
//   • `quota` is absent from the signed config. It is OPERATOR policy, supplied at
//     boot (seedkernel ShellOptions.config), never baked into author-signed content.
//   • Nothing the RUNTIME derives is in the config, and nothing runtime-derived is
//     injected at all (seedkernel §12.4): the signing scope in particular is not a
//     fact the guest ever holds — `node/sign`/`node/verify` apply it host-side.
//     Baking it here would be a build-time copy of a load-time fact, and a
//     copy that drifts fails as signatures that verify nowhere.

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
 * The author's full key set: the Ed25519 half and the ML-DSA-65 half, both from the ONE
 * seed an operator stores, so the pinned id (seedkernel `hybridAuthorId`, a hash over
 * both public keys) is stable across rebuilds of the same key.
 *
 * A thin call on seedkernel's `hybridAuthorKeysFromSeed` rather than a local derivation:
 * the runtime's own transport author, the chat demo and this bundle must all derive the
 * same way, and a copy that drifted would not fail a build — it would publish under a
 * different author id and match nobody's policy pin.
 *
 * @param {any}    sodium  loaded libsodium, with the ML-DSA-65 signer mixed in
 *                         (seedkernel `loadSodium` supplies it; `signManifest`
 *                         throws without it, so a build that cannot sign PQ fails loud)
 * @param {Uint8Array} edSk  the author's 64-byte Ed25519 secret key (seed‖pk)
 */
export function authorKeysFor(sodium, edSk) {
  return hybridAuthorKeysFromSeed(sodium, edSk.slice(0, 32));
}

// The authorities the storage guest reaches, EXACTLY (seedkernel AUTHORITY_CALLS
// keys — `guest.requires`, the fine-grained cap list). Declaring them is exactly
// what the shell enforces: a `host.call` naming an authority outside this list is
// refused at the bridge, name by name.
//
// `node/sign` + `node/verify` (signing AND verification, both scoped to this
// bundle's (author, app) — the guest checks a peer's descriptor signature without
// ever reconstructing the host-owned prefix), `node/identity` and `node/random`
// (identity and entropy). The pure transforms —
// BLAKE2b, XChaCha20 — are not grants at all: they live under the
// ungated `crypto/` prefix, because a function of a guest's own arguments grants
// nothing. This bundle's own `codec`/`reputation` module names are the same story:
// bare names on the same seam, reaching modules installed and verified with this
// bundle, so they are ungated like `crypto` (seedkernel §12.1) and never appear
// in `requires`.
const STORAGE_REQUIRES = [
  "node/sign", "node/verify", "node/identity", "node/random",
  "net/send", "net/peers",
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
  // The two modules by logical name. That name is all the manifest carries: the loader
  // derives the kernel name each binds at from `(app, name)` (seedkernel §5.1), so there
  // is no bind name to state here and none to drift from what the runtime does.
  const modSpecs = ["codec", "reputation"];
  // Files inside the bundle blob, keyed by the names §12.4 derives — a module lives in
  // `<name>.wasm` and the guest in `guest.js`, so the manifest names no filenames.
  const files = {};

  // The two pure handlers (§17). The manifest commits to each module's genesisHash;
  // the shell verifies the bytes against it and installs them at the name it derives
  // from the signed `(app, name)` pair, re-checking author + module hash under the same
  // policy gate (seedkernel §12.4).
  const modules = modSpecs.map((name) => {
    // The build dir still stages each module as <name>.wasm, which is also its name
    // inside the bundle.
    const wasm = new Uint8Array(readFileSync(join(build, moduleFile(name))));
    files[moduleFile(name)] = wasm;
    // hash = genesisHash(wasm): the `bytes_hash` a policy.modules allowlist matches
    // (seedkernel §7.1) and the manifest module `hash` the loader checks the bytes against.
    // Hashing lives in the bundle module now (a free `genesisHash(sodium, …)`), not on the
    // host — the kernel table touches no crypto.
    const hash = toHex(genesisHash(sodium, wasm));
    log(`  ${name}: bytesHash ${hash}`);
    return { name, hash };
  });

  // The zero-authority orchestration guest, shipped *minified* (the shell injects
  // the op preamble and runs it as source). We ship the comment-stripped copy to
  // keep the signed bundle small; the minifier (scripts/minify.mjs) gates every
  // file through `node --check`, so it is valid JS, just without the doc comments.
  // The content hash below covers exactly these bytes, so shipped == verified.
  const guestText = readFileSync(join(build, "host-min", "tier2-guest.js"), "utf8");
  files[GUEST_FILE] = new TextEncoder().encode(guestText);

  // The signed config must carry PRODUCTION geometry: defaultConfig()'s bare blockSize is
  // test-scale (256 BYTES — sized so unit tests exercise multi-block chunking on tiny
  // payloads), and when it leaked in here unchanged, a loader-initiated `--put` chunked a
  // 10 MB file into ~41k blocks. PRODUCTION_BLOCK_SIZE is the one named deployment geometry
  // (why 256 KiB: see its doc in core.ts), so this site and the CLI can't drift apart.
  const cfg = defaultConfig(undefined, undefined, PRODUCTION_BLOCK_SIZE);
  const manifest = {
    app: APP_NAME,
    // A monotonic integer freshness mark per (author, app): the shell enforces it as a
    // high-water mark and refuses a downgrade (README §12.4). Bump it on every publish.
    version,
    // The wire protocol this app serves (seedkernel §12.10) — the claim, signed with
    // everything else here. The load that admits this bundle routes the id to it, so a
    // node that installed storage IS a storage node; there is no second operator act
    // between landing the code and answering a peer. Read from STORAGE_PROTO, the same
    // constant the guest frames its net/send with (NET_PROTO), so the id a sender writes
    // and the id a receiver routes by cannot drift.
    protocols: [STORAGE_PROTO],
    modules,
    // Everything about the guest — its content hash, its authority, and its config — in
    // one place (seedkernel §12.4). The guest is required by the format — every app is
    // a guest — and storage's holds the whole authority the bundle has.
    guest: {
      hash: toHex(genesisHash(sodium, files[GUEST_FILE])),
      // Which host seam this guest was written against (seedkernel §12.2). Read from the
      // runtime rather than written as a literal, so a seam change breaks the build here
      // instead of surfacing as a wrong answer at the first `host.call`.
      abi: GUEST_ABI_VERSION,
      // The enforced capability grant — the fine-grained authority names
      // (seedkernel AUTHORITY_CALLS), EXACTLY what the guest's host.call reaches.
      // The guest's ABI is the shared name-addressed preamble the shell injects at
      // load, not a signed catalog.
      requires: [...STORAGE_REQUIRES],
      // App constants the shell injects as `const APP = …`: the storage geometry.
      // NB: no `quota` — that is operator policy supplied at boot, not author-signed
      // content — and nothing the runtime derives (see the header note): the signing
      // scope is not injected at all, `node/sign`/`node/verify` apply it host-side.
      config: {
        k: cfg.k, m: cfg.m, blockSize: cfg.blockSize,
        // The APP injection is TOTAL: the guest reads APP and never guesses a default, so
        // the signed config must carry every value the guest reads (except `quota`, which
        // is operator policy merged at boot — see above — and the §4.1 durability math,
        // which is derived: the replica count + low-water mark from each chunk's own signed
        // descriptor). Transport/operator knobs pinned
        // here: a holder bounds one FETCH response by ITS maxMessageBytes (serveFetch), so
        // the cohort agrees on it deliberately, and the fan-out/window knobs match core.ts's
        // defaults. Operator config can still override any of these at boot (the shell
        // merges over the signed config), and a mismatched client degrades to tail
        // re-requests instead of failing (runFetchTasks).
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

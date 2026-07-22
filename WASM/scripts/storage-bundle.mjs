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
//   • `caps` declares capability *domains* (cap-bridge CAP_DOMAINS keys), not op
//     numbers. The shell expands them to the enforced op set + wires only the
//     matching backends. Storage reaches all five. (There is no `ops` catalog in
//     the manifest — the guest's ABI is the injected CAP_* preamble, not signed
//     content; the grant is `caps`.) It lives inside `guest`, where the authority it
//     grants does.
//   • `quota` is absent from the signed config. It is OPERATOR policy, supplied at
//     boot (seedkernel ShellOptions.config), never baked into author-signed content.
//   • Nothing the RUNTIME derives is in the config. The codec/reputation kernel names
//     and the guest signing prefix all reach the guest as `BUNDLE` (seedkernel
//     cap-bridge bundlePreamble), derived at admission from the manifest this script
//     signs. Baking them here would be a build-time copy of a load-time fact, and a
//     copy that drifts fails as signatures that verify nowhere.

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";

import { signManifest, packBundle, genesisHash, MANIFEST_FILE, GUEST_FILE, moduleFile }
  from "seedkernel-wasm/bundle";
import { defaultConfig, PRODUCTION_BLOCK_SIZE } from "../build/host/core.js";
import { toHex } from "../build/host/util.js";

// The app name — the manifest `app` and the `app` component of the signing scope
// (README §16). The shell scopes the guest's SIGN op to (author, app); build here the
// byte-identical scope so the guest's injected verify prefix agrees with it.
const APP_NAME = "seedstore";

// The capability domains the storage guest reaches (cap-bridge CAP_DOMAINS keys).
// Storage uses all of them; declaring them is exactly what the shell enforces.
const STORAGE_CAPS = ["crypto", "net", "fs", "module", "clock"];

/**
 * Write a complete signed seedstore bundle to `path` (one blob, seedkernel §12.4).
 * @param {object} o
 * @param {string} o.path     output bundle file (e.g. ./bundle/seedstore.skb)
 * @param {any}    o.sodium   loaded libsodium (hashes the module bytes; signs the manifest)
 * @param {Uint8Array} o.sk   author secret key (signs the manifest)
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
    modules,
    // Everything about the guest — its content hash, its authority, and its config — in
    // one place (seedkernel §12.4). A bundle with no `guest` is a bundle with no
    // authority; storage has one, so it declares both.
    guest: {
      hash: toHex(genesisHash(sodium, files[GUEST_FILE])),
      // The enforced capability grant (domains, not op numbers). The guest's op ABI
      // is the CAP_* preamble the shell injects at load, not a signed catalog.
      caps: [...STORAGE_CAPS],
      // App constants the shell injects as `const APP = …`: the storage geometry.
      // NB: no `quota` — that is operator policy supplied at boot, not author-signed
      // content — and nothing the runtime derives (see the header note): the kernel
      // names and the signing prefix arrive as `BUNDLE`.
      config: {
        k: cfg.k, m: cfg.m, blockSize: cfg.blockSize,
        // The APP injection is TOTAL: the guest reads APP and never guesses a default, so
        // the signed config must carry every value the guest reads (except `quota`, which
        // is operator policy merged at boot — see above — and the §4.1 durability math,
        // which is derived: smallMaxBlocks from k/m, and the replica count + low-water
        // mark from each chunk's own signed descriptor). Transport/operator knobs pinned
        // here: a holder bounds one FETCH response by ITS maxMessageBytes (serveFetch), so
        // the cohort agrees on it deliberately, and the fan-out/window knobs match core.ts's
        // defaults. Operator config can still override any of these at boot (the shell
        // merges over the signed config), and a mismatched client degrades to tail
        // re-requests instead of failing (runFetchTasks).
        maxMessageBytes: cfg.maxMessageBytes,
        putWindow: cfg.putWindow, getWindow: cfg.getWindow,
        windowTargetBytes: cfg.windowTargetBytes,
      },
    },
  };

  files[MANIFEST_FILE] = signManifest(sodium, sk, pk, manifest);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, packBundle(files));
  return manifest;
}

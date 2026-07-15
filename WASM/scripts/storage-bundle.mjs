// The single source of truth for a seedstore app bundle's *content* — shared by
// the offline producer (scripts/build-bundle.mjs) and the test fixture
// (tests/bundle-fixture.mjs) so the two can never drift (the `caps` field used to).
// Given a kernel host + author key + the build dir, it writes the whole bundle
// directory: each module's wasm + its author-signed install envelope, the guest,
// and the signed manifest.
//
// Two deliberate choices live here, once:
//   • `caps` declares capability *domains* (cap-bridge CAP_DOMAINS keys), not op
//     numbers. The shell expands them to the enforced op set + wires only the
//     matching backends; `ops` is just the ABI catalog. Storage reaches all five.
//   • `quota` is absent from the signed config. It is OPERATOR policy, supplied at
//     boot (seedkernel ShellOptions.config), never baked into author-signed content.

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

import { CURRENT_VERSION } from "seedkernel-wasm";
import { signManifest } from "seedkernel-wasm/bundle";
import { CAP, guestSignScope } from "seedkernel-wasm/cap-bridge";
import { storageNames } from "../build/host/names.js";
import { defaultConfig, PRODUCTION_BLOCK_SIZE } from "../build/host/core.js";
import { guestSignPrefix } from "../build/host/manifest.js";
import { toHex } from "../build/host/util.js";

// The app name — the manifest `app` and the `app` component of the signing scope
// (README §16). The shell scopes the guest's SIGN op to (author, app); build here the
// byte-identical scope so the guest's injected verify prefix agrees with it.
const APP_NAME = "seedstore";

// The capability domains the storage guest reaches (cap-bridge CAP_DOMAINS keys).
// Storage uses all of them; declaring them is exactly what the shell enforces.
const STORAGE_CAPS = ["crypto", "net", "fs", "module", "clock"];

/**
 * Write a complete signed seedstore bundle into `dir`.
 * @param {object} o
 * @param {string} o.dir      output directory for the bundle
 * @param {any}    o.host     a loaded KernelHost with the signature handler registered
 * @param {any}    o.sodium   loaded libsodium
 * @param {Uint8Array} o.sk   author secret key (signs the manifest + installs)
 * @param {Uint8Array} o.pk   author public key
 * @param {string} o.build    seedstore build/ dir (holds kernel/codec wasm + staged guest)
 * @param {number} [o.version] monotonic-per-(author,app) freshness mark (README §13.4);
 *                             the shell refuses a load below its high-water mark. Integer.
 * @param {(s:string)=>void} [o.log]  optional progress logger
 * @returns the manifest object that was signed (for logging/inspection).
 */
export function writeStorageBundle({ dir, host, sodium, sk, pk, build, version = 1, log = () => {} }) {
  if (!Number.isInteger(version)) throw new Error("writeStorageBundle: version must be an integer");
  const names = storageNames(host);
  const installName = host.deriveBootstrapName("install");
  const modSpecs = [
    { name: "codec", file: "codec.wasm", kernelName: names.codec },
    { name: "reputation", file: "reputation.wasm", kernelName: names.reputation },
  ];
  mkdirSync(dir, { recursive: true });

  // The two pure handlers (§17): no declared caps. Each install is author-signed so
  // the shell can dispatch it verbatim through its policy gate.
  let seq = 0;
  const modules = modSpecs.map((m) => {
    const wasm = new Uint8Array(readFileSync(join(build, m.file)));
    const payload = host.encodeInstallPayload(++seq, m.kernelName, [], wasm);
    const install = host.wrapAndEncode(sk, pk, CURRENT_VERSION, installName, payload);
    writeFileSync(join(dir, m.file), wasm);
    writeFileSync(join(dir, `${m.name}.install`), install);
    log(`  ${m.name}: install bytesHash ${toHex(host.genesisHash(payload))}`); // for policy.modules
    return {
      name: m.name, file: m.file, hash: toHex(host.genesisHash(wasm)),
      install: `${m.name}.install`, kernelName: toHex(m.kernelName),
    };
  });

  // The zero-authority orchestration guest, shipped *minified* (the shell injects
  // the op preamble and runs it as source). We ship the comment-stripped copy to
  // keep the signed bundle small; the minifier (scripts/minify.mjs) gates every
  // file through `node --check`, so it is valid JS, just without the doc comments.
  // The content hash below covers exactly these bytes, so shipped == verified.
  const guestText = readFileSync(join(build, "host-min", "tier2-guest.js"), "utf8");
  writeFileSync(join(dir, "tier2-guest.js"), guestText);

  // The signed config must carry PRODUCTION geometry: defaultConfig()'s bare blockSize is
  // test-scale (256 BYTES — sized so unit tests exercise multi-block chunking on tiny
  // payloads), and when it leaked in here unchanged, a loader-initiated `--put` chunked a
  // 10 MB file into ~41k blocks. PRODUCTION_BLOCK_SIZE is the one named deployment geometry
  // (why 256 KiB: see its doc in core.ts), so this site and the CLI can't drift apart.
  const cfg = defaultConfig(undefined, undefined, PRODUCTION_BLOCK_SIZE);
  const manifest = {
    app: APP_NAME,
    // A monotonic integer freshness mark per (author, app): the shell enforces it as a
    // high-water mark and refuses a downgrade (README §13.4). Bump it on every publish.
    version,
    modules,
    guest: { file: "tier2-guest.js", hash: toHex(host.genesisHash(new TextEncoder().encode(guestText))) },
    // `ops` documents the seam ABI (the full catalog the guest was built against);
    // the shell enforces via `caps`, not this.
    ops: { ...CAP },
    // The enforced capability grant (domains, not op numbers).
    caps: [...STORAGE_CAPS],
    // App constants the shell injects as `const APP = …`: the storage geometry + the
    // codec/reputation kernel names the guest module-calls. NB: no `quota` — that is
    // operator policy supplied at boot, not author-signed content.
    config: {
      k: cfg.k, m: cfg.m, blockSize: cfg.blockSize,
      replicas: cfg.replicas, lowWater: cfg.lowWater, smallMaxBlocks: cfg.smallMaxBlocks,
      // Pin the per-message batch cap explicitly: a holder bounds one FETCH response
      // by ITS value (serveFetch), so the cohort should agree on it deliberately
      // rather than lean on the guest's fallback. Operator config can still override
      // at boot (the shell merges over the signed config), and a mismatched client
      // now degrades to tail re-requests instead of failing (runFetchTasks).
      maxMessageBytes: cfg.maxMessageBytes,
      codecName: toHex(names.codec), repName: toHex(names.reputation),
      // The scoped-signature prefix `DOMAIN_guest ‖ scope` the guest prepends before
      // CAP_VERIFY (README §16). The shell's SIGN op scopes to (this author, this app),
      // so build the byte-identical prefix here from the same (pk, APP_NAME).
      signPrefix: toHex(guestSignPrefix(guestSignScope(pk, APP_NAME))),
    },
  };

  writeFileSync(join(dir, "manifest.bundle"), signManifest(sodium, sk, pk, manifest));
  return manifest;
}

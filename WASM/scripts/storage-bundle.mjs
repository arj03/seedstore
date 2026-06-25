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
import { CAP } from "seedkernel-wasm/cap-bridge";
import { storageNames } from "../build/host/names.js";
import { defaultConfig } from "../build/host/core.js";
import { toHex } from "../build/host/util.js";

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
 * @param {(s:string)=>void} [o.log]  optional progress logger
 * @returns the manifest object that was signed (for logging/inspection).
 */
export function writeStorageBundle({ dir, host, sodium, sk, pk, build, log = () => {} }) {
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
    const payload = host.encodeInstallPayload(++seq, m.kernelName, [], null, wasm);
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

  const cfg = defaultConfig();
  const manifest = {
    app: "seedstore",
    version: "1",
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
      codecName: toHex(names.codec), repName: toHex(names.reputation),
    },
  };

  writeFileSync(join(dir, "manifest.bundle"), signManifest(sodium, sk, pk, manifest));
  return manifest;
}

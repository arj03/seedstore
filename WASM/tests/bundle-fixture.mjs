// Build a signed seedstore bundle directory on disk — the same content
// scripts/build-bundle.mjs writes, factored out so the shell tests (shell-run +
// holder-guest) produce a byte-identical bundle from one place. The module kernel
// names are derived deterministically, so they match what a shell's own host (and
// the guest's APP.codecName/repName) resolve to.

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

import { loadKernelHost, CURRENT_VERSION } from "seedkernel-wasm";
import { signManifest } from "seedkernel-wasm/bundle";
import { CAP } from "seedkernel-wasm/cap-bridge";
import { storageNames } from "../build/host/names.js";
import { defaultConfig } from "../build/host/core.js";
import { toHex } from "../build/host/util.js";

/** @param build absolute path to seedstore's build/ dir (holds kernel/codec wasm + the staged guest). */
export async function buildBundle(dir, author, sodium, build) {
  const host = await loadKernelHost(join(build, "kernel.wasm"), join(build, "bootstrap.wasm"));
  host.registerSignature(host.deriveBootstrapName("signature"));
  const names = storageNames(host);
  const installName = host.deriveBootstrapName("install");
  const modSpecs = [
    { name: "codec", file: "codec.wasm", kernelName: names.codec },
    { name: "reputation", file: "reputation.wasm", kernelName: names.reputation },
  ];
  mkdirSync(dir, { recursive: true });
  let seq = 0;
  const modules = modSpecs.map((m) => {
    const wasm = new Uint8Array(readFileSync(join(build, m.file)));
    const payload = host.encodeInstallPayload(++seq, m.kernelName, [], null, wasm);
    const install = host.wrapAndEncode(author.privateKey, author.publicKey, CURRENT_VERSION, installName, payload);
    writeFileSync(join(dir, m.file), wasm);
    writeFileSync(join(dir, `${m.name}.install`), install);
    return {
      name: m.name, file: m.file, hash: toHex(host.genesisHash(wasm)),
      install: `${m.name}.install`, kernelName: toHex(m.kernelName),
    };
  });
  const guestText = readFileSync(join(build, "host", "tier2-guest.js"), "utf8");
  writeFileSync(join(dir, "tier2-guest.js"), guestText);
  const cfg = defaultConfig();
  const manifest = {
    app: "seedstore", version: "1", modules,
    guest: { file: "tier2-guest.js", hash: toHex(host.genesisHash(new TextEncoder().encode(guestText))) },
    ops: { ...CAP }, caps: [],
    config: {
      k: cfg.k, m: cfg.m, blockSize: cfg.blockSize, replicas: cfg.replicas,
      lowWater: cfg.lowWater, smallMaxBlocks: cfg.smallMaxBlocks,
      quota: 64 * 1024 * 1024,
      codecName: toHex(names.codec), repName: toHex(names.reputation),
    },
  };
  writeFileSync(join(dir, "manifest.bundle"), signManifest(sodium, author.privateKey, author.publicKey, manifest));
}

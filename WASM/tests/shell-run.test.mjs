// The "shell runs the app" end-to-end (the runtime split). A *generic*
// seedkernel-shell — which knows nothing about storage and imports no seedstore
// code — loads the signed seedstore bundle and runs its zero-authority guest as
// the PUT/GET initiator over the application-neutral cap-bridge, against a cohort
// of real seedstore StorageNode holders on the loopback network. This is the proof
// that storage rides on the runtime as signed content over a fixed primitive
// vocabulary (crypto / net / fs / module-call / clock / identity) — the binary
// never learns it is running storage.
//
//   node tests/shell-run.test.mjs
//   bun  tests/shell-run.test.mjs

import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { boot } from "seedkernel-wasm/shell";
import { kernelNameFor } from "seedkernel-wasm/bundle";
import {
  loadSodium, generateKeyPair, LoopbackNetwork, createConnectedCohort,
} from "../build/host/node.js";
import { toHex, bytesEqual, concatBytes } from "../build/host/util.js";
import { buildBundle } from "./bundle-fixture.mjs";
import { makeT } from "./harness.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const build = join(__dirname, "..", "build");

function file(n, seed = 1) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + seed * 7) & 255;
  return out;
}

export async function run(t) {
  const sodium = await loadSodium();

  t.group("shell: a generic seedkernel-shell runs the seedstore guest end-to-end (step 7)");
  {
    // The bundle author fixes the deployment's signing scope (README §16). The shell
    // running the bundle signs descriptors under it, so the host-side StorageNode holders
    // must verify under the SAME scope — they load the SAME signed bundle.
    const author = generateKeyPair(sodium);
    const net = new LoopbackNetwork();

    const bundleDir = mkdtempSync(join(tmpdir(), "seedstore-bundle-"));
    const bundlePath = join(bundleDir, "seedstore.skb");
    const shellDir = mkdtempSync(join(tmpdir(), "seedstore-shell-"));
    let shell, holders = [];
    try {
      await buildBundle(bundlePath, author, sodium, build);
      const bundleBlob = new Uint8Array(readFileSync(bundlePath));
      holders = await createConnectedCohort({
        // Match the shell's test-scale geometry so this tiny file spreads across the
        // cohort (the signed bundle ships PRODUCTION 256 KiB blocks).
        count: 6, network: net, sodium, wasm: { bundleBlob }, config: { blockSize: 64 }, timeoutMs: 40,
      });

      // The shell knows only its policy + the kernel; storage arrives as content.
      shell = await boot({
        policyJson: JSON.stringify({ authors: [toHex(author.publicKey)] }),
        dir: shellDir, identity: generateKeyPair(sodium),
        network: net, timeoutMs: 40,
        livePeers: () => holders.map((h) => h.peerId),
        // Operator config merges over the signed bundle config: bring blockSize back
        // to test scale (the bundle ships the PRODUCTION 256 KiB, which would make
        // this tiny test file single-block/replicated instead of RS across the cohort).
        config: { blockSize: 64 },
      });
      const loaded = await shell.loadBundle(bundlePath);
      for (const m of loaded.manifest.modules) {
        t.ok(shell.host.isBound(kernelNameFor(author.publicKey, loaded.manifest.app, m.name)),
          `module ${m.name} installed`);
      }

      // PUT, orchestrated by the confined guest the shell loaded.
      const data = file(600, 7); // > k blocks → multi-chunk RS path
      const r = await shell.runGuest("put", data);
      const manifestId = r.slice(0, 32), key = r.slice(36, 68);
      t.ok(holders.filter((h) => h.store.list().length > 0).length >= 4,
        "the shell's guest placed blocks across several distinct holders");
      t.eq(shell.fs.list().length, 0, "the shell itself holds nothing — durability is the cohort's");

      // GET, same confined guest, reconstructing from the holders.
      const got = await shell.runGuest("get", concatBytes([manifestId, key]));
      t.ok(bytesEqual(got, data), "PUT → GET round-trips: the generic shell ran storage over primitive caps");

      // A shell whose policy does not allow the bundle author refuses to load it.
      const shell2Dir = mkdtempSync(join(tmpdir(), "seedstore-shell2-"));
      const shell2 = await boot({
        policyJson: JSON.stringify({ authors: [toHex(generateKeyPair(sodium).publicKey)] }),
        dir: shell2Dir, identity: generateKeyPair(sodium), network: net,
      });
      let refused = false;
      try { await shell2.loadBundle(bundlePath); } catch { refused = true; }
      t.ok(refused, "a shell whose policy omits the author refuses the bundle");
      shell2.close();
      rmSync(shell2Dir, { recursive: true, force: true });
    } finally {
      if (shell) shell.close();
      holders.forEach((h) => h.close());
      rmSync(bundleDir, { recursive: true, force: true });
      rmSync(shellDir, { recursive: true, force: true });
      // boot() writes the freshness high-water mark as a sibling of the data dir
      // (deliberately outside the guest-writable dir), so it survives the dir's rmSync —
      // remove it too or every run orphans a *.freshness.json in the OS tmpdir.
      rmSync(`${shellDir}.freshness.json`, { force: true });
    }
  }

  t.group("shell: bundle version freshness — a downgrade is refused (§12.4)");
  {
    // The manifest `version` is a monotonic integer high-water mark per (author, app).
    // Once a shell loads version 5 it refuses a same-author version-3 bundle as a
    // downgrade — the guest is loaded wholesale from the bundle, so this is the only
    // guard against silently swapping in an older signed bundle.
    const author = generateKeyPair(sodium);
    const net = new LoopbackNetwork();
    const hiDir = mkdtempSync(join(tmpdir(), "seedstore-bundle-hi-"));
    const loDir = mkdtempSync(join(tmpdir(), "seedstore-bundle-lo-"));
    const shellDir = mkdtempSync(join(tmpdir(), "seedstore-shell-fresh-"));
    let shell;
    try {
      const hiPath = join(hiDir, "seedstore.skb"), loPath = join(loDir, "seedstore.skb");
      await buildBundle(hiPath, author, sodium, build, 5);
      await buildBundle(loPath, author, sodium, build, 3);
      shell = await boot({
        policyJson: JSON.stringify({ authors: [toHex(author.publicKey)] }),
        dir: shellDir, identity: generateKeyPair(sodium), network: net, timeoutMs: 40,
      });
      await shell.loadBundle(hiPath); // advances the (author, app) high-water mark to 5
      let refused = false;
      try { await shell.loadBundle(loPath); } catch { refused = true; }
      t.ok(refused, "a version-3 bundle is refused after a version-5 bundle loaded (no downgrade)");
    } finally {
      if (shell) shell.close();
      rmSync(hiDir, { recursive: true, force: true });
      rmSync(loDir, { recursive: true, force: true });
      rmSync(shellDir, { recursive: true, force: true });
      rmSync(`${shellDir}.freshness.json`, { force: true }); // sibling of the data dir — see above
    }
  }
}

// Allow running this module directly (node/bun tests/shell-run.test.mjs).
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("shell-run.test.mjs")) {
  const t = makeT();
  run(t).then(() => process.exit(t.summary() > 0 ? 1 : 0));
}

// The "shell runs the app" end-to-end (the runtime split). A *generic*
// seedkernel-shell — which knows nothing about storage and imports no seedstore
// code — loads the signed seedstore bundle and runs its zero-authority guest as
// the PUT/GET initiator over the application-neutral cap-bridge, against a cohort
// of real seedstore StorageNode holders on the in-process loopback fabric. This
// is the proof that storage rides on the runtime as signed content over a fixed
// primitive vocabulary (crypto / net / fs / module-call / clock / identity) — the
// binary never learns it is running storage.
//
// The shell's network is itself a signed bundle: `boot()` admits the kernel's
// transport bundle (its author must clear the policy's `grants: { link: [...] }` entry),
// standing the TransportHost driver up over the socket seam — here a per-node
// view of the shared LoopbackNetwork fabric, exactly as a shell-run node on real
// sockets would.
//
//   node tests/shell-run.test.mjs
//   bun  tests/shell-run.test.mjs

import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { boot } from "seedkernel-wasm/shell";
import { appKeyFor, verifyBundle } from "seedkernel-wasm/bundle";
import { TRANSPORT_BUNDLE_B64 } from "seedkernel-wasm/transport-bundle";
import {
  loadSodium, generateKeyPair, LoopbackNetwork, createConnectedCohort,
} from "../build/host/node.js";
import { toHex, bytesEqual, concatBytes, readU32BE } from "../build/host/util.js";
import { buildBundle } from "./bundle-fixture.mjs";
import { makeT } from "./harness.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const build = join(__dirname, "..", "build");
// The per-request deadline. Generous, and it has to be: a request now crosses two
// confined realms on each side — the app's guest calls the transport, the transport answers the
// far end's `_host`, and the far end's shell dispatches into its own app's realm — where
// it used to cross a host-side facade. 40 ms was a wire budget, not a realm budget.
const TIMEOUT = 200;

function file(n, seed = 1) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + seed * 7) & 255;
  return out;
}

/** The transport bundle's author — derived from the artifact, never restated —
 *  so the policy can admit it for the transport role. */
function transportAuthorHex(sodium) {
  const bin = atob(TRANSPORT_BUNDLE_B64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return toHex(verifyBundle(sodium, bytes).author);
}

/** Wire one shell's driver to one storage node's driver (addresses + dial) and
 *  add the node to the shell's cohort view. */
async function link(shell, shellPeerId, node, cohortSet) {
  node.net.addPeerAddr(shellPeerId, { host: "127.0.0.1", port: shell.transport.port, transport: "tcp" });
  shell.transport.addPeerAddr(node.peerId, { host: "127.0.0.1", port: node.net.port, transport: "tcp" });
  cohortSet.add(node.peerId);
  await Promise.all([shell.transport.ready(), node.net.ready()]);
}

export async function run(t) {
  const sodium = await loadSodium();
  const transportHex = transportAuthorHex(sodium);

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
        // The hybrid author id (key-set hash) is what policy and kernel names pin —
        // the bundle is signed under suite 0x02 (§12.4), not the bare Ed25519 key.
        const authorId = await buildBundle(bundlePath, author, sodium, build);
        const bundleBlob = new Uint8Array(readFileSync(bundlePath));
      holders = await createConnectedCohort({
        // Match the shell's test-scale geometry so this tiny file spreads across the
        // cohort (the signed bundle ships PRODUCTION 256 KiB blocks).
        count: 6, network: net, sodium, wasm: { bundleBlob }, config: { blockSize: 1024 }, timeoutMs: TIMEOUT,
      });

      // The shell knows only its policy + the kernel; storage arrives as content. The
      // policy admits the bundle author for apps AND grants the transport bundle's
      // author the `link` privilege — the latter is what stands the shell's network up.
      //
      // A cohort is MUTUAL: the holders must know the shell too, because a holder now
      // anchors a descriptor's author to a peer it knows (§4.3) — a valid signature from
      // a stranger is exactly the forgery the anchor exists to stop.
      const shellIdentity = generateKeyPair(sodium);
      for (const h of holders) h.addPeer(toHex(shellIdentity.publicKey));
      shell = await boot({
        policyJson: JSON.stringify({
          authors: [toHex(authorId)],
          grants: { link: [transportHex] },
        }),
        dir: shellDir, identity: shellIdentity,
        channels: net.view(toHex(shellIdentity.publicKey)),
        listen: { host: "127.0.0.1", port: 0 },
        timeoutMs: TIMEOUT,
        // Operator config merges over the signed bundle config: bring blockSize back
        // to test scale (the bundle ships the PRODUCTION 256 KiB, which would make
        // this tiny test file single-block/replicated instead of RS across the cohort).
        config: { blockSize: 1024 },
      });
      await shell.transport.start();
      for (const h of holders) await link(shell, toHex(shellIdentity.publicKey), h, new Set());
      const loaded = await shell.loadBundle(bundlePath);
      // The app key is not optional: a node with a network has at least two apps loaded — the
      // storage bundle and the transport, which is an ordinary app that claims `_net` (§12.10).
      const appKey = appKeyFor(authorId, loaded.manifest.app);
      for (const m of loaded.manifest.modules) {
        t.ok(shell.host.isBound(appKey, m.name),
          `module ${m.name} installed`);
      }

      // PUT, orchestrated by the confined guest the shell loaded.
      const data = file(9600, 7); // > k blocks → multi-chunk RS path
      const r = await shell.runGuest("put", data, appKey);
      const key = r.slice(0, 32), root = r.slice(48, 48 + readU32BE(r, 44));
      let holding = 0;
      for (const h of holders) if ((await h.store.list()).length > 0) holding++;
      t.ok(holding >= 4, "the shell's guest placed blocks across several distinct holders");
      t.eq((await shell.fs.list()).length, 0, "the shell itself holds nothing — durability is the cohort's");

      // GET, same confined guest, reconstructing from the holders.
      const got = await shell.runGuest("get", concatBytes([key, root]), appKey);
      t.ok(bytesEqual(got, data), "PUT → GET round-trips: the generic shell ran storage over primitive caps");

      // A shell whose policy does not allow the bundle author refuses to load it.
      const shell2Dir = mkdtempSync(join(tmpdir(), "seedstore-shell2-"));
      const shell2Id = generateKeyPair(sodium);
      const shell2 = await boot({
        policyJson: JSON.stringify({
          authors: [toHex(generateKeyPair(sodium).publicKey)],
          grants: { link: [transportHex] },
        }),
        dir: shell2Dir, identity: shell2Id, channels: net.view(toHex(shell2Id.publicKey)),
      });
      let refused = false;
      try { await shell2.loadBundle(bundlePath); } catch { refused = true; }
      t.ok(refused, "a shell whose policy omits the author refuses the bundle");
      shell2.close();
      rmSync(shell2Dir, { recursive: true, force: true });
    } finally {
      if (shell) shell.close();
      holders.forEach((h) => h.close());
      net.close();
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
      const authorId = await buildBundle(hiPath, author, sodium, build, 5);
      await buildBundle(loPath, author, sodium, build, 3);
      const shellId = generateKeyPair(sodium);
      shell = await boot({
        policyJson: JSON.stringify({
          authors: [toHex(authorId)],
          grants: { link: [transportHex] },
        }),
        dir: shellDir, identity: shellId, channels: net.view(toHex(shellId.publicKey)),
        timeoutMs: TIMEOUT,
      });
      await shell.transport.start();
      await shell.loadBundle(hiPath); // advances the (author, app) high-water mark to 5
      let refused = false;
      try { await shell.loadBundle(loPath); } catch { refused = true; }
      t.ok(refused, "a version-3 bundle is refused after a version-5 bundle loaded (no downgrade)");
    } finally {
      if (shell) shell.close();
      net.close();
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

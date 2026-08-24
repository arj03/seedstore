// The "shell runs the app" end-to-end (the runtime split). A *generic*
// seedkernel-shell — no seedstore code — loads the signed seedstore bundle and
// runs its zero-authority guest as the PUT/GET initiator over the
// application-neutral guest seam, against real StorageNode holders on the
// loopback fabric: proof storage rides the runtime as signed content, never
// baked into the binary.
//
// The shell's network is itself a signed bundle: `boot()` admits the kernel's
// transport bundle, standing the TransportHost driver up over a per-node view
// of the shared LoopbackNetwork fabric — exactly as a real-sockets node would.
//
//   node tests/shell-run.test.mjs
//   bun  tests/shell-run.test.mjs

import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// `bootNodeShell` where the test drives the channel adapter (addresses, listeners) and
// where only the shell is wanted — the adapter is the platform's now, so it comes back
// beside the shell rather than on it.
import { bootNodeShell } from "seedkernel-wasm/shell-node";
import { verifyBundle } from "seedkernel-wasm/bundle";
import { transportBundleBytes } from "seedkernel-wasm/transport-bundle";
import {
  loadSodium, generateKeyPair, LoopbackNetwork, createConnectedCohort,
} from "../build/host/node.js";
import { toHex, bytesEqual, concatBytes, readU32BE } from "../build/host/util.js";
import { writeOp } from "seedkernel-wasm/op-frame";
import { Op } from "../build/host/protocol.js";
import { buildBundle } from "./bundle-fixture.mjs";
import { makeT } from "./harness.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const build = join(__dirname, "..", "build");
// The per-request deadline. Generous, and it has to be: a request now crosses two
// confined realms on each side — the app's guest calls the transport, the transport
// returns the delivery the host routes to the far end's app, and that realm answers —
// where it used to cross a host-side facade. 40 ms was a wire budget, not a realm
// budget.
const TIMEOUT = 200;

function file(n, seed = 1) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + seed * 7) & 255;
  return out;
}

/** The transport bundle's author — derived from the artifact, never restated —
 *  so the policy can admit it for the transport role. */
function transportAuthorHex(sodium) {
  const bytes = transportBundleBytes();
  return toHex(verifyBundle(sodium, bytes).author);
}

/** Wire one shell's channel adapter to one storage node's (addresses + dial) and
 *  add the node to the shell's cohort view. The adapter is the platform's — the shell
 *  does not carry one — so it is passed in beside the peer id it belongs to. */
async function link(shellNet, shellPeerId, node, cohortSet) {
  node.net.addPeerAddr(shellPeerId, { host: "127.0.0.1", port: shellNet.port, transport: "tcp" });
  shellNet.addPeerAddr(node.peerId, { host: "127.0.0.1", port: node.net.port, transport: "tcp" });
  cohortSet.add(node.peerId);
  await Promise.all([shellNet.ready(), node.net.ready()]);
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

      // The shell knows only its policy + the kernel; storage arrives as
      // content. A cohort is MUTUAL: the holders must know the shell too,
      // since a holder anchors a descriptor's author to a peer it knows (§4.3).
      const shellIdentity = generateKeyPair(sodium);
      for (const h of holders) h.addPeer(toHex(shellIdentity.publicKey));
      const rt = await bootNodeShell({
        policyJson: JSON.stringify({
          authors: [toHex(authorId)],
          grants: { link: [transportHex] },
        }),
        dir: shellDir, identity: shellIdentity,
        channels: net.view(toHex(shellIdentity.publicKey)),
        listen: { host: "127.0.0.1", port: 0 },
        timeoutMs: TIMEOUT,
      });
      shell = rt.shell;
      await rt.transport.start();
      for (const h of holders) await link(rt.transport, toHex(shellIdentity.publicKey), h, new Set());
      // This installation's settings ride WITH the load (seedkernel §12.4), reaching the
      // guest as `LOCAL`, which its `CFG` lets win: blockSize back to test scale (the
      // bundle ships the PRODUCTION 256 KiB, which would make this tiny file
      // single-block/replicated instead of RS across the cohort).
      const loaded = await shell.loadBundle(bundlePath, { localConfig: { blockSize: 1024 } });
      // The app key rides the load's handle: a node with a network has at least two apps
      // loaded — the storage bundle and the transport, an ordinary app claiming `_net`
      // under its `services` list (§12.10), a co-resident guest's to reach and never a peer's.
      const appKey = loaded.key;
      // A slot's modules are private to its guest now, so there is no table to ask what
      // landed: the load is all-or-none (seedkernel §12.4), so what proves the modules
      // stood up is the app answering on the claim it made — and, below, a PUT that
      // cannot complete without the codec.
      for (const proto of loaded.manifest.protocols ?? []) {
        t.eq(shell.resolve(proto), appKey, `the loaded app claims ${proto}`);
      }

      // PUT, orchestrated by the confined guest the shell loaded.
      const data = file(9600, 7); // > k blocks → multi-chunk RS path
      const r = await loaded.invoke(writeOp(Op.PUT, data));
      const key = r.slice(0, 32), root = r.slice(48, 48 + readU32BE(r, 44));
      let holding = 0;
      for (const h of holders) if ((await h.store.list()).length > 0) holding++;
      t.ok(holding >= 4, "the shell's guest placed blocks across several distinct holders");
      t.eq((await shell.fs.list()).length, 0, "the shell itself holds nothing — durability is the cohort's");

      // GET, same confined guest, reconstructing from the holders.
      const got = await loaded.invoke(writeOp(Op.GET, concatBytes([key, root])));
      t.ok(bytesEqual(got, data), "PUT → GET round-trips: the generic shell ran storage over the seam's names");

      // A shell whose policy does not allow the bundle author refuses to load it.
      const shell2Dir = mkdtempSync(join(tmpdir(), "seedstore-shell2-"));
      const shell2Id = generateKeyPair(sodium);
      const { shell: shell2 } = await bootNodeShell({
        policyJson: JSON.stringify({
          authors: [toHex(generateKeyPair(sodium).publicKey)],
          grants: { link: [transportHex] },
        }),
        dir: shell2Dir, identity: shell2Id, channels: net.view(toHex(shell2Id.publicKey)),
        listen: { host: "127.0.0.1", port: 0 },
      });
      let refused = false;
      try { await shell2.loadBundle(bundlePath); } catch { refused = true; }
      t.ok(refused, "a shell whose policy omits the author refuses the bundle");
      shell2.close();
      rmSync(shell2Dir, { recursive: true, force: true });
      rmSync(`${shell2Dir}.freshness.json`, { force: true });
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
      const rt = await bootNodeShell({
        policyJson: JSON.stringify({
          authors: [toHex(authorId)],
          grants: { link: [transportHex] },
        }),
        dir: shellDir, identity: shellId, channels: net.view(toHex(shellId.publicKey)),
        timeoutMs: TIMEOUT,
      });
      shell = rt.shell;
      await rt.transport.start();
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

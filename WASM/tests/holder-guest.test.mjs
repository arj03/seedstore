// The holder side, confined (the runtime split — full Target B). Where
// shell-run.test.mjs proved a generic seedkernel-shell runs the *initiator* side as
// signed content, this proves the *request* side too: a shell serving HAVE / OFFER /
// STORE / FETCH — admission control, the §6 sibling rule, content-addressing, the
// §14 quota, and the <hex>.blk/.dsc fs writes — entirely from the confined guest,
// with zero storage-specific host code in the runtime.
//
// The holder path is async now, like the initiator's: a holder answers from local
// fs, and the fs seam is asynchronous on every backend (seedkernel core/fs.ts).
// What once kept the two roles from interleaving — the realm's synchronous second
// entry (`callSync`, which never pumped the job queue) — is now the realm's
// explicit per-realm FIFO (seedkernel realm-queue.ts): one entrypoint runs to
// completion before the next begins, so an inbound request to a node whose
// initiator is parked waits for the queue to drain rather than being answered
// around. The concurrency group below still overlaps two initiators — the
// serialization costs round trips on a busy realm, never correctness.
//
//   node tests/holder-guest.test.mjs
//   bun  tests/holder-guest.test.mjs

import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { boot } from "seedkernel-wasm/shell";
import { verifyBundle } from "seedkernel-wasm/bundle";
import { TRANSPORT_BUNDLE_B64 } from "seedkernel-wasm/transport-bundle";
import {
  loadSodium, generateKeyPair, LoopbackNetwork, createConnectedCohort,
} from "../build/host/node.js";
import { toHex, bytesEqual, concatBytes, readU32BE } from "../build/host/util.js";
import { buildBundle } from "./bundle-fixture.mjs";
import { makeT } from "./harness.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const build = join(__dirname, "..", "build");
const TIMEOUT = 200; // ms — generous: QuickJS realms + loopback under concurrency

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

export async function run(t) {
  const sodium = await loadSodium();
  const transportHex = transportAuthorHex(sodium);
  const author = generateKeyPair(sodium);
  const bundleDir = mkdtempSync(join(tmpdir(), "seedstore-bundle-"));
  const bundlePath = join(bundleDir, "seedstore.skb");
  // The hybrid author id (key-set hash) is what the policy pins — the bundle is
  // signed under suite 0x02 (§12.4), not the bare Ed25519 key.
  const authorId = await buildBundle(bundlePath, author, sodium, build);
  // The StorageNode cohort loads the SAME signed bundle the shells load, so every node
  // derives the one author signing scope and a descriptor one signs verifies on another.
  const bundleBlob = new Uint8Array(readFileSync(bundlePath));
  const policyJson = JSON.stringify({
    authors: [toHex(authorId)],
    transportAuthors: [transportHex],
  });
  const tmpDirs = [bundleDir];

  // Durable cohort set shared by all shells in the group — the network owns
  // connectivity, the cohort is app state. All shells reference this set via
  // their livePeers closure so NET_PEERS is consistent.
  let cohortSet = new Set();

  // Boot a generic shell that both initiates and holds: it loads the bundle and
  // serves the confined holder side. Knows nothing about storage; storage is
  // content. Returns the shell + its peer id (for cohort wiring).
  async function bootShell(net) {
    const dir = mkdtempSync(join(tmpdir(), "seedstore-shell-"));
    tmpDirs.push(dir);
    const identity = generateKeyPair(sodium);
    const shell = await boot({
      policyJson, dir, identity,
      channels: net.view(toHex(identity.publicKey)),
      listen: { host: "127.0.0.1", port: 0 },
      timeoutMs: TIMEOUT,
      livePeers: () => [...cohortSet],
      // Quota is operator policy (not signed into the bundle): the operator supplies it
      // at boot, merged over the bundle's guest config into the guest's APP. NB this is
      // the SHELL's config — opaque operator input the shell merges wholesale. A
      // StorageNode's `config` is the typed StorageConfig instead, and takes quota as a
      // sibling option (`StorageNode.create({ quota })`); the same spelling used there is
      // rejected rather than ignored. Both drivers run in this file, so the two are easy
      // to confuse.
      // blockSize is overridden back to test scale — the signed bundle carries the
      // PRODUCTION 256 KiB (storage-bundle.mjs), which would make these tiny test
      // files single-block/replicated instead of exercising the RS path.
      config: { quota: 64 * 1024 * 1024, blockSize: 1024 },
    });
    await shell.net.start(); // bind the loopback port the cohort dials
    // A generic shell + the signed storage bundle is a storage node: the manifest
    // claims STORAGE_PROTO and the load routes it (§12.10), so nothing here points
    // the protocol anywhere — `serve()` is the only step between loading and answering.
    await shell.loadBundle(bundlePath);
    await shell.serve();
    return { shell, peerId: toHex(identity.publicKey), net: shell.net };
  }
  // Dial every pair (addresses + ready), and mirror the memberships into the shared
  // cohort set so every shell's NET_PEERS sees the whole cohort. A StorageNode's
  // livePeers reads its OWN cohort set (StorageNode.addPeer), so those get the
  // memberships too — a StorageNode whose cohort set is empty would PUT nowhere.
  const connectAll = async (net, entries) => {
    cohortSet = new Set(entries.map((e) => e.peerId));
    for (const e of entries) {
      for (const o of entries) {
        if (e === o) continue;
        e.addPeer?.(o.peerId);
        e.net.addPeerAddr(o.peerId, { host: "127.0.0.1", port: o.net.port, transport: "tcp" });
      }
    }
    await Promise.all(entries.map((e) => e.net.ready()));
    void net;
  };

  try {
    t.group("holder: a cohort of generic shells runs storage end-to-end, holder side confined too (step 8)");
    {
      const net = new LoopbackNetwork();
      const shells = [];
      for (let i = 0; i < 5; i++) shells.push(await bootShell(net));
      await connectAll(net, shells);
      try {
        const data = file(12800, 7); // several blocks → the RS path, placed across the cohort
        const r = await shells[0].shell.runGuest("put", data);
        const key = r.slice(0, 32), root = r.slice(48, 48 + readU32BE(r, 44));

        let holding = 0;
        for (const e of shells.slice(1)) if ((await e.shell.fs.list()).length > 0) holding++;
        t.ok(holding >= 4, "the confined holders admitted + stored blocks (fs writes via the guest)");
        t.eq((await shells[0].shell.fs.list()).length, 0, "the initiator holds nothing — durability is the cohort's");

        const got = await shells[0].shell.runGuest("get", concatBytes([key, root]));
        t.ok(bytesEqual(got, data), "PUT → GET round-trips: a generic shell served the holder side from the confined guest");
      } finally {
        shells.forEach((e) => e.shell.close());
        net.close();
      }
    }

    t.group("holder: the confined holder serves (async, serialized) while the node's own initiator is parked mid-await in the same realm (§2.1)");
    {
      const net = new LoopbackNetwork();
      const shells = [];
      for (let i = 0; i < 5; i++) shells.push(await bootShell(net));
      // A host-side StorageNode (plain JS — no QuickJS) is a second, concurrent
      // initiator + holder in the same cohort, so two PUTs overlap. The realm
      // serializes: a shell whose initiator is parked answers inbound requests as
      // its queue drains (the parker's own round trips to free realms settle in
      // microseconds on the loopback), so the overlap costs latency on a busy
      // realm — never correctness.
      const [sn] = await createConnectedCohort({
        // Same signed bundle as the shells ⇒ same author scope (cross-path parity).
        // blockSize back to test scale so this tiny file takes the RS path across the cohort.
        count: 1, network: net, sodium, wasm: { bundleBlob }, config: { blockSize: 1024 }, timeoutMs: TIMEOUT,
      });
      const all = [...shells, { shell: null, peerId: sn.peerId, net: sn.net, addPeer: (p) => sn.addPeer(p) }];
      await connectAll(net, all);
      try {
        const dataA = file(12800, 11), dataB = file(12800, 12);
        // Concurrent: the shell's guest PUT (its initiator parks on net) runs while
        // the StorageNode places STOREs on that same shell — the shell's holder path
        // must answer (queued behind the parked initiator, served as it drains).
        const [rA, putB] = await Promise.all([
          shells[0].shell.runGuest("put", dataA),
          sn.put(dataB),
        ]);
        const keyA = rA.slice(0, 32), rootA = rA.slice(48, 48 + readU32BE(rA, 44));

        const [gotA, gotB] = await Promise.all([
          shells[0].shell.runGuest("get", concatBytes([keyA, rootA])),
          sn.get(putB.root, putB.key),
        ]);
        t.ok(bytesEqual(gotA, dataA), "the shell's own file round-trips despite serving holder requests mid-PUT");
        t.ok(bytesEqual(gotB, dataB), "the StorageNode's file round-trips — the shell held + served its blocks concurrently");
        let shellsHeld = false;
        for (const e of shells) if ((await e.shell.fs.list()).length > 0) shellsHeld = true;
        t.ok(shellsHeld, "shells held blocks for the concurrent host-side initiator");
      } finally {
        shells.forEach((e) => e.shell.close());
        sn.close();
        net.close();
      }
    }

    t.group("holder: a confined shell holder is byte-compatible with the host-side initiator (cross-path parity)");
    {
      const net = new LoopbackNetwork();
      cohortSet = new Set();
      // Pure holders — they never initiate. They still need the WRITER in their roster,
      // because a holder anchors a descriptor's author to a peer it knows (§4.3): a
      // signature that verifies against a key nobody knows binds authority to nothing.
      const shells = [];
      for (let i = 0; i < 5; i++) shells.push(await bootShell(net));
      const [sn] = await createConnectedCohort({
        // Same signed bundle as the shells ⇒ same author scope (cross-path parity).
        // blockSize back to test scale so this tiny file takes the RS path across the cohort.
        count: 1, network: net, sodium, wasm: { bundleBlob }, config: { blockSize: 1024 }, timeoutMs: TIMEOUT,
      });
      for (const e of shells) {
        sn.addPeer(e.peerId);
        cohortSet.add(sn.peerId);
        sn.net.addPeerAddr(e.peerId, { host: "127.0.0.1", port: e.net.port, transport: "tcp" });
        e.net.addPeerAddr(sn.peerId, { host: "127.0.0.1", port: sn.net.port, transport: "tcp" });
      }
      await Promise.all([sn.net.ready(), ...shells.map((e) => e.net.ready())]);
      try {
        // Written by the trusted host-side path, served entirely by confined shells.
        const data = file(12800, 21);
        const put = await sn.put(data);
        let holding = 0;
        for (const e of shells) if ((await e.shell.fs.list()).length > 0) holding++;
        t.ok(holding >= 4, "the host-side initiator placed blocks across the confined shell holders");
        const got = await sn.get(put.root, put.key);
        t.ok(bytesEqual(got, data), "host-side PUT reads back through the confined holders — the guest holder is wire-compatible");
      } finally {
        shells.forEach((e) => e.shell.close());
        sn.close();
        net.close();
      }
    }
  } finally {
    for (const d of tmpDirs) {
      rmSync(d, { recursive: true, force: true });
      // boot() writes the freshness high-water mark as a sibling of each shell's data dir
      // (outside the guest-writable dir), so it survives the dir's rmSync. Remove it too or
      // every run orphans a *.freshness.json in the OS tmpdir. Harmless no-op for bundleDir.
      rmSync(`${d}.freshness.json`, { force: true });
    }
  }
}

// Allow running this module directly (node/bun tests/holder-guest.test.mjs).
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("holder-guest.test.mjs")) {
  const t = makeT();
  run(t).then(() => process.exit(t.summary() > 0 ? 1 : 0));
}

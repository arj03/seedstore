// The holder side, confined (the runtime split — full Target B). Where
// shell-run.test.mjs proved a generic seedkernel-shell runs the *initiator* side
// as signed content, this proves the *request* side too: a shell serving
// HAVE/OFFER/STORE/FETCH — admission, the §6 sibling rule, content-addressing,
// §14 quota, and the fs writes — entirely from the confined guest.
//
// The holder path is async, like the initiator's. The realm's per-realm FIFO
// (seedkernel realm-queue.ts) keeps the two roles from interleaving: an
// inbound request to a node whose initiator is parked waits for the queue to
// drain, costing round trips on a busy realm, never correctness.
//
//   node tests/holder-guest.test.mjs
//   bun  tests/holder-guest.test.mjs

import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { bootRuntime } from "seedkernel-wasm/shell";
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
const TIMEOUT = 200; // ms — generous: QuickJS realms + loopback under concurrency

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
    grants: { link: [transportHex] },
  });
  const tmpDirs = [bundleDir];

  // Boot a generic shell that both initiates and holds: it loads the bundle and
  // serves the confined holder side. Knows nothing about storage; storage is
  // content. Returns the shell + its peer id (for cohort wiring).
  async function bootShell(net) {
    const dir = mkdtempSync(join(tmpdir(), "seedstore-shell-"));
    tmpDirs.push(dir);
    const identity = generateKeyPair(sodium);
    const { shell, transport } = await bootRuntime({
      policyJson, dir, identity,
      channels: net.view(toHex(identity.publicKey)),
      listen: { host: "127.0.0.1", port: 0 },
      timeoutMs: TIMEOUT,
    });
    await transport.start(); // bind the loopback port the cohort dials
    // A generic shell + the signed storage bundle is a storage node: the
    // manifest claims STORAGE_PROTO and the load routes it (§12.10). Operator
    // settings go on THIS LOAD as `LOCAL` (seedkernel §12.4) — note this is the
    // SHELL's spelling of quota; StorageNode takes it as a sibling option instead.
    // blockSize goes back to test scale (the bundle ships PRODUCTION 256 KiB).
    const loaded = await shell.loadBundle(bundlePath, {
      localConfig: { quota: 64 * 1024 * 1024, blockSize: 1024 },
    });
    // The app key rides the load's handle: a node with a network runs ≥2 apps
    // (storage + transport), so "the only loaded app" isn't unambiguous for `invoke`.
    return { shell, peerId: toHex(identity.publicKey), net: transport, appKey: loaded.key };
  }
  // Dial every pair (addresses + ready). Each guest's cohort is the TRANSPORT's
  // authenticated set (it asks the transport's `_net` local service for peers),
  // so linking IS the wiring.
  // `addPeer` stays for a StorageNode, whose cohort is its own durable app state.
  const connectAll = async (net, entries) => {
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
        const r = await shells[0].shell.invoke(writeOp(Op.PUT, data), shells[0].appKey);
        const key = r.slice(0, 32), root = r.slice(48, 48 + readU32BE(r, 44));

        let holding = 0;
        for (const e of shells.slice(1)) if ((await e.shell.fs.list()).length > 0) holding++;
        t.ok(holding >= 4, "the confined holders admitted + stored blocks (fs writes via the guest)");
        t.eq((await shells[0].shell.fs.list()).length, 0, "the initiator holds nothing — durability is the cohort's");

        const got = await shells[0].shell.invoke(writeOp(Op.GET, concatBytes([key, root])), shells[0].appKey);
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
      // A host-side StorageNode (plain JS) is a second, concurrent initiator +
      // holder in the same cohort, so two PUTs overlap. The realm serializes —
      // costing latency on a busy realm, never correctness.
      const [sn] = await createConnectedCohort({
        // Same signed bundle as the shells (cross-path parity); blockSize back to
        // test scale so this tiny file takes the RS path.
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
          shells[0].shell.invoke(writeOp(Op.PUT, dataA), shells[0].appKey),
          sn.put(dataB),
        ]);
        const keyA = rA.slice(0, 32), rootA = rA.slice(48, 48 + readU32BE(rA, 44));

        const [gotA, gotB] = await Promise.all([
          shells[0].shell.invoke(writeOp(Op.GET, concatBytes([keyA, rootA])), shells[0].appKey),
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
      // Pure holders — they never initiate. They still need the WRITER among the peers
      // they are LINKED to, because a holder anchors a descriptor's author to a peer it
      // knows (§4.3) and "knows" is now the transport's authenticated set: a signature that
      // verifies against a key nobody has a link to binds authority to nothing.
      const shells = [];
      for (let i = 0; i < 5; i++) shells.push(await bootShell(net));
      const [sn] = await createConnectedCohort({
        // Same signed bundle as the shells ⇒ same author scope (cross-path parity).
        // blockSize back to test scale so this tiny file takes the RS path across the cohort.
        count: 1, network: net, sodium, wasm: { bundleBlob }, config: { blockSize: 1024 }, timeoutMs: TIMEOUT,
      });
      for (const e of shells) {
        sn.addPeer(e.peerId);
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


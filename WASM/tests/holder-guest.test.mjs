// The holder side, confined (the runtime split — full Target B). Where
// shell-run.test.mjs proved a generic seedkernel-shell runs the *initiator* side as
// signed content, this proves the *request* side too: a shell serving HAVE / OFFER /
// STORE / FETCH — admission control, the §6 sibling rule, content-addressing, the
// §14 quota, and the <hex>.blk/.dsc fs writes — entirely from the confined guest,
// via the realm's synchronous `callSync`, with zero storage-specific host code in the
// runtime.
//
// The synchronous holder path is the load-bearing piece: a holder answers from local
// fs + crypto without yielding, so it responds *re-entrantly* while the node's own
// initiator is parked mid-await in the same realm — a suspended async guest is just
// heap state, and callSync never pumps the job queue, so it cannot advance the parked
// initiator. The concurrency group exercises exactly that: a guest (async) initiator
// and a host-side StorageNode (plain JS) initiator place blocks at the same time, so
// STOREs land on a shell while its initiator is busy and its holder path has to serve
// them.
//
//   node tests/holder-guest.test.mjs
//   bun  tests/holder-guest.test.mjs

import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { boot } from "seedkernel-wasm/shell";
import {
  loadSodium, generateKeyPair, LoopbackNetwork, createConnectedCohort,
} from "../build/host/node.js";
import { toHex, bytesEqual, concatBytes } from "../build/host/util.js";
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

export async function run(t) {
  const sodium = await loadSodium();
  const author = generateKeyPair(sodium);
  const bundleDir = mkdtempSync(join(tmpdir(), "seedstore-bundle-"));
  const bundlePath = join(bundleDir, "seedstore.skb");
  await buildBundle(bundlePath, author, sodium, build);
  // The StorageNode cohort loads the SAME signed bundle the shells load, so every node
  // derives the one author signing scope and a descriptor one signs verifies on another.
  const bundleBlob = new Uint8Array(readFileSync(bundlePath));
  const policyJson = JSON.stringify({ authors: [toHex(author.publicKey)] });
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
      policyJson, dir, identity, network: net, timeoutMs: TIMEOUT,
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
      config: { quota: 64 * 1024 * 1024, blockSize: 64 },
    });
    await shell.loadBundle(bundlePath);
    await shell.serve();
    return { shell, peerId: toHex(identity.publicKey) };
  }
  const connectAll = (entries) => {
    for (const a of entries) for (const b of entries) if (a !== b) cohortSet.add(b.peerId);
  };

  try {
    t.group("holder: a cohort of generic shells runs storage end-to-end, holder side confined too (step 8)");
    {
      const net = new LoopbackNetwork();
      cohortSet = new Set();
      const shells = [];
      for (let i = 0; i < 5; i++) shells.push(await bootShell(net));
      connectAll(shells);
      try {
        const data = file(800, 7); // 4 blocks → the RS path, placed across the cohort
        const r = await shells[0].shell.runGuest("put", data);
        const manifestId = r.slice(0, 32), key = r.slice(37, 69);
        t.ok(r[32] === 0, "the shell-run guest took the RS path");

        const holding = shells.slice(1).filter((e) => e.shell.fs.list().length > 0);
        t.ok(holding.length >= 4, "the confined holders admitted + stored blocks (fs writes via the guest)");
        t.eq(shells[0].shell.fs.list().length, 0, "the initiator holds nothing — durability is the cohort's");

        const got = await shells[0].shell.runGuest("get", concatBytes([manifestId, key]));
        t.ok(bytesEqual(got, data), "PUT → GET round-trips: a generic shell served the holder side from the confined guest");
      } finally {
        shells.forEach((e) => e.shell.close());
      }
    }

    t.group("holder: the confined holder serves (callSync) while the node's own initiator is parked mid-await in the same realm (§2.1)");
    {
      const net = new LoopbackNetwork();
      cohortSet = new Set();
      const shells = [];
      for (let i = 0; i < 5; i++) shells.push(await bootShell(net));
      connectAll(shells);
      // A host-side StorageNode (plain JS — no QuickJS) is a second, concurrent
      // initiator + holder in the same cohort, so two PUTs overlap and the shell's
      // one realm must serve holder requests (callSync) while its own initiator is
      // parked mid-await.
      const [sn] = await createConnectedCohort({
        // Same signed bundle as the shells ⇒ same author scope (cross-path parity).
        // blockSize back to test scale so this tiny file takes the RS path across the cohort.
        count: 1, network: net, sodium, wasm: { bundleBlob }, config: { blockSize: 64 }, timeoutMs: TIMEOUT,
      });
      for (const e of shells) { sn.addPeer(e.peerId); cohortSet.add(sn.peerId); }
      try {
        const dataA = file(800, 11), dataB = file(800, 12);
        // Concurrent: the shell's guest PUT (its initiator parks on net) runs while
        // the StorageNode places STOREs on that same shell — the shell's holder path
        // (callSync) must answer re-entrantly mid-flight.
        const [rA, putB] = await Promise.all([
          shells[0].shell.runGuest("put", dataA),
          sn.put(dataB),
        ]);
        const midA = rA.slice(0, 32), keyA = rA.slice(37, 69);

        const [gotA, gotB] = await Promise.all([
          shells[0].shell.runGuest("get", concatBytes([midA, keyA])),
          sn.get(putB.manifestId, putB.key),
        ]);
        t.ok(bytesEqual(gotA, dataA), "the shell's own file round-trips despite serving holder requests mid-PUT");
        t.ok(bytesEqual(gotB, dataB), "the StorageNode's file round-trips — the shell held + served its blocks concurrently");
        t.ok(shells.some((e) => e.shell.fs.list().length > 0), "shells held blocks for the concurrent host-side initiator");
      } finally {
        shells.forEach((e) => e.shell.close());
        sn.close();
      }
    }

    t.group("holder: a confined shell holder is byte-compatible with the host-side initiator (cross-path parity)");
    {
      const net = new LoopbackNetwork();
      cohortSet = new Set();
      // Pure holders — they never initiate, so they need no peers of their own.
      const shells = [];
      for (let i = 0; i < 5; i++) shells.push(await bootShell(net));
      const [sn] = await createConnectedCohort({
        // Same signed bundle as the shells ⇒ same author scope (cross-path parity).
        // blockSize back to test scale so this tiny file takes the RS path across the cohort.
        count: 1, network: net, sodium, wasm: { bundleBlob }, config: { blockSize: 64 }, timeoutMs: TIMEOUT,
      });
      for (const e of shells) sn.addPeer(e.peerId);
      try {
        // Written by the trusted host-side path, served entirely by confined shells.
        const data = file(800, 21);
        const put = await sn.put(data);
        t.ok(shells.filter((e) => e.shell.fs.list().length > 0).length >= 4,
          "the host-side initiator placed blocks across the confined shell holders");
        const got = await sn.get(put.manifestId, put.key);
        t.ok(bytesEqual(got, data), "host-side PUT reads back through the confined holders — the guest holder is wire-compatible");
      } finally {
        shells.forEach((e) => e.shell.close());
        sn.close();
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

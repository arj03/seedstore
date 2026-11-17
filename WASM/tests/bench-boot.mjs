// A node's START over a store that already holds a lot: what a node pays before it answers
// its first request, and what each repair pass then pays, as its store grows. Fills `dir`
// once with `sizeMB` of 256 KiB records under valid signed descriptors (k=1 chunks, group
// cohort), then boots a node over it, on disk, and times:
//   boot      the node standing up and loading the bundle
//   first op  its first answer that needs the store index (holdings)
//   repair    one repair pass over everything held (no peers, so it audits and asks no one)
//
// Run:  node tests/bench-boot.mjs [sizeMB=1024] [dir]   (dir defaults to a temp dir, removed)

import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { randomBytes } from "node:crypto";
import { loadCrypto } from "seedkernel-wasm";
import { nodeChannels } from "seedkernel-wasm/shell-node";
import { NodeFs } from "seedkernel-wasm/fs-node";
import { scopedFs } from "seedkernel-wasm/shell-core";
import { generateKeyPair, defaultConfig, PRODUCTION_BLOCK_SIZE } from "../build/host/node.js";
import { signDescriptor } from "../build/host/descriptor.js";
import { toHex } from "../build/host/util.js";
import { plantBlock } from "./helpers.mjs";
import { bootNode } from "../scripts/boot-node.mjs";

const sizeMB = Number(process.argv[2] ?? 1024);
const given = process.argv[3];
const dir = given ?? mkdtempSync(join(tmpdir(), "seedstore-boot-"));
const BS = PRODUCTION_BLOCK_SIZE;
const sodium = await loadCrypto();
const identity = generateKeyPair(sodium);
const config = defaultConfig(BS, 1, 1);
const quota = 64 * 1024 * 1024 * 1024;

const guestDeadlineMs = Number(process.env.DEADLINE ?? 5000);
const boot = () => bootNode({ identity, sodium, dir, channels: nodeChannels(), config, quota, guestDeadlineMs });

if (!existsSync(join(dir, ".bench-filled"))) {
  const t0 = performance.now();
  const { node } = await boot();
  const fs = scopedFs(new NodeFs(dir), node.appScope);
  const author = generateKeyPair(sodium);
  const n = Math.ceil((sizeMB * 1024 * 1024) / BS);
  const bytes = randomBytes(BS);
  for (let i = 0; i < n; i++) {
    const id = randomBytes(32);
    const desc = signDescriptor(sodium, { group: "cohort", level: 0, k: 1, m: 1, blockSize: BS, tailBytes: BS,
      authTag: new Uint8Array(16), blockIds: [id, randomBytes(32)] }, author.publicKey, author.privateKey);
    plantBlock(fs, toHex(id), bytes, desc);
  }
  await node.close?.();
  writeFileSync(join(dir, ".bench-filled"), String(n));
  console.log(`filled ${dir}: ${n} records (${sizeMB} MB) in ${((performance.now() - t0) / 1000).toFixed(1)} s`);
}

const t0 = performance.now();
const { node } = await boot();
const t1 = performance.now();
console.log(`boot ${(t1 - t0).toFixed(0)} ms`);
const h = await node.client.holdings();
const t2 = performance.now();
console.log(`first op ${(t2 - t1).toFixed(0)} ms`);
const repaired = await node.runRepair();
const t3 = performance.now();
await node.runRepair();
const t4 = performance.now();
console.log(`held ${(h.used / 1024 / 1024).toFixed(0)} MiB in ${h.holds.reduce((a, r) => a + r.blocks, 0)} blocks`);
console.log(`boot ${(t1 - t0).toFixed(0)} ms   first op ${(t2 - t1).toFixed(0)} ms   repair pass ${(t3 - t2).toFixed(0)} ms (asked ${repaired})   2nd pass ${(t4 - t3).toFixed(0)} ms`);
if (!given) rmSync(dir, { recursive: true, force: true });
process.exit(0);

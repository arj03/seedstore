// seedstore test runner. Each test module exports `run(t)`; we share one
// harness so the final tally covers the whole suite.
//
//   npm test        (builds first, then runs)
//   node tests/run.mjs

import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { makeT } from "./harness.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));

const modules = [
  "./codec.test.mjs",
  "./bridges.test.mjs",
  "./manifest.test.mjs",
  "./protocol.test.mjs",
  "./reputation.test.mjs",
  "./storage.test.mjs",
  "./concurrency.test.mjs",
  "./net.test.mjs",
  "./browser.test.mjs",
  "./tier2-port.test.mjs",
  "./shell-run.test.mjs",
  "./holder-guest.test.mjs",
];

const t = makeT();

for (const m of modules) {
  // Modules not yet present (during incremental build-out) are skipped.
  if (!existsSync(join(__dirname, m))) {
    console.log(`\n(skipping ${m} — not present yet)`);
    continue;
  }
  const mod = await import(m);
  console.log(`\n=== ${m} ===`);
  await mod.run(t);
}

const failed = t.summary();
if (failed > 0) process.exit(1);

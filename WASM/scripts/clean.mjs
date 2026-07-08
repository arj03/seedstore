// Remove every build artifact so the next build starts from nothing.
//
// The incremental scripts overwrite in place and don't wipe their output dirs
// (tsc, build:guest, build:browser-demo), so a stale file from an earlier build —
// or a different branch — can linger and get shipped. `npm run clean` is the escape
// hatch: delete build/ wholesale, then `npm run build` (or `npm run build:browser`)
// regenerates it. Use it whenever the demo behaves like it's running old code.
//
//   npm run clean          →  removes build/
//   npm run clean && npm run build:browser
//
// rmSync retries through the transient Windows/Defender file locks that make a
// plain delete flaky right after a server or the browser touched the dir.

import { rmSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const buildDir = join(root, "build");

if (!existsSync(buildDir)) {
  console.log("clean: build/ already absent — nothing to do.");
} else {
  rmSync(buildDir, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
  console.log("clean: removed build/ — run `npm run build` (or `npm run build:browser`) to regenerate.");
}

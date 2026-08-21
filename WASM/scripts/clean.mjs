// Remove every build artifact so the next build starts from nothing. The
// incremental scripts (tsc, build:guest, build:browser-demo) overwrite in place
// and don't wipe their output dirs, so a stale file can linger and get shipped.
// rmSync retries through transient Windows/Defender file locks.

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

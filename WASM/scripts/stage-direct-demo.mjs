// Stage the relay-less WebRTC-Direct storage demo (browser/direct.html) into
// build/direct-demo — everything the page needs to boot a full StorageNode in the
// browser and dial console holders with no relay:
//   - the four WASM modules (kernel, bootstrap, codec, reputation)
//   - this project's compiled host, minified (build/host-min → host/)
//   - seedkernel's node:fs-free browser host, minified (build/host-min → seedkernel/)
//   - browser/direct.html
//
//   npm run demo:direct          (in seedstore/WASM)
//   npx serve build/direct-demo  then open  http://localhost:3000/direct.html
//
// In other terminals run the holders:  bun scripts/serve-direct-holder.mjs  (one
// each), paste their tokens into the page, and store a file across them.
//
// Needs both builds' minified host: seedstore `npm run build`, and seedkernel
// `npm run build:host && npm run build:host:min`.

import { mkdirSync, copyFileSync, existsSync, readdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const build = join(root, "build");
const out = process.env.DIRECT_DEMO_OUT ?? join(build, "direct-demo");
const seedstoreHost = join(build, "host-min");
const seedkernelHost = join(root, "..", "..", "seedkernel", "WASM", "build", "host-min");

if (!existsSync(join(seedstoreHost, "browser.js"))) {
  console.error("seedstore build/host-min not found — run `npm run build` first (in seedstore/WASM).");
  process.exit(1);
}
if (!existsSync(join(seedkernelHost, "webrtc-direct-browser.js"))) {
  console.error(`seedkernel host-min (with webrtc-direct-browser.js) not found at ${seedkernelHost}\n` +
    "build it first:  (in seedkernel/WASM)  npm run build:host && npm run build:host:min");
  process.exit(1);
}

// Clean the previous staging. On Windows this fails with EPERM if a `serve` is
// still holding a file in there — that is a user mistake, not a fatal build error,
// so warn and overwrite in place rather than dumping a stack trace.
try {
  rmSync(out, { recursive: true, force: true });
} catch {
  console.warn(`could not clear ${out} (a 'serve' may be running on it) — overwriting in place.`);
}
mkdirSync(out, { recursive: true });

// WASM modules the browser StorageNode fetches relative to the page.
for (const f of ["kernel.wasm", "bootstrap.wasm", "codec.wasm", "reputation.wasm"]) {
  copyFileSync(join(build, f), join(out, f));
}

// Host JS (seedstore + seedkernel). Copy only .js — the page's import map resolves
// "seedkernel-wasm/*" into ./seedkernel/ and this project's host imports into ./host/.
const copyJs = (srcDir, dstDir) => {
  mkdirSync(dstDir, { recursive: true });
  for (const name of readdirSync(srcDir)) {
    if (name.endsWith(".js")) copyFileSync(join(srcDir, name), join(dstDir, name));
  }
};
copyJs(seedstoreHost, join(out, "host"));
copyJs(seedkernelHost, join(out, "seedkernel"));

copyFileSync(join(root, "browser", "direct.html"), join(out, "direct.html"));

console.log(`direct storage demo staged at ${out}`);
console.log("serve it:   npx serve build/direct-demo");
console.log("holders:    bun scripts/serve-direct-holder.mjs   (run a few, copy each token)");
console.log("then open:  http://localhost:3000/direct.html   and paste the tokens");

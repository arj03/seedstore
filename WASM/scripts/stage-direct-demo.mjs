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

import { mkdirSync, copyFileSync, existsSync, readdirSync } from "node:fs";
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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Copy by overwriting in place — we do NOT wipe `out` first. A recursive delete
// followed by an immediate re-copy races on Windows (the dir entry lingers, and
// Defender briefly locks each freshly written file for scanning), which used to
// abort the stage mid-copy and leave a half-populated — or empty — direct-demo.
// The staged file set is fixed, so overwriting is enough; transient EPERM/EBUSY/
// EACCES on a just-written file is retried rather than fatal.
async function copy(src, dst) {
  for (let attempt = 1; ; attempt++) {
    try { copyFileSync(src, dst); return; }
    catch (e) {
      const transient = e && (e.code === "EPERM" || e.code === "EBUSY" || e.code === "EACCES");
      if (!transient || attempt >= 8) {
        throw new Error(`could not write ${dst} (${e.code ?? e.message}). ` +
          "If a server or browser is holding build/direct-demo open, stop it and re-run `npm run demo:direct`.");
      }
      await sleep(attempt * 50); // back off through the transient lock
    }
  }
}

mkdirSync(out, { recursive: true });

// WASM modules the browser StorageNode fetches relative to the page.
for (const f of ["kernel.wasm", "bootstrap.wasm", "codec.wasm", "reputation.wasm"]) {
  await copy(join(build, f), join(out, f));
}

// Host JS (seedstore + seedkernel). Copy only .js — the page's import map resolves
// "seedkernel-wasm/*" into ./seedkernel/ and this project's host imports into ./host/.
async function copyJs(srcDir, dstDir) {
  mkdirSync(dstDir, { recursive: true });
  for (const name of readdirSync(srcDir)) {
    if (name.endsWith(".js")) await copy(join(srcDir, name), join(dstDir, name));
  }
}
await copyJs(seedstoreHost, join(out, "host"));
await copyJs(seedkernelHost, join(out, "seedkernel"));

await copy(join(root, "browser", "direct.html"), join(out, "direct.html"));

console.log(`direct storage demo staged at ${out}`);
console.log("serve it:   npx serve build/direct-demo");
console.log("holders:    bun scripts/serve-direct-holder.mjs   (run a few, copy each token)");
console.log("then open:  http://localhost:3000/direct.html   and paste the tokens");

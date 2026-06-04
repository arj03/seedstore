// Stage a self-contained browser demo into build/browser-demo:
//   - the four WASM modules (kernel, bootstrap, codec, reputation)
//   - this project's compiled host, minified (build/host-min → host/)
//   - seedkernel's node:fs-free browser host, minified (build/host-min → seedkernel/)
//   - browser/index.html
//
// Serve it with any static file server, e.g.:
//   npx http-server build/browser-demo -p 8080   (then open http://localhost:8080)
//
// The page's import map resolves "seedkernel-wasm/browser" → ./seedkernel/browser.js
// and pulls sumo libsodium from a CDN; vendor an ESM build there to run offline.

import { mkdirSync, copyFileSync, existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const build = join(root, "build");
const out = join(build, "browser-demo");
const seedkernelHost = join(root, "..", "..", "seedkernel", "WASM", "build", "host-min");

if (!existsSync(join(build, "host-min", "browser.js"))) {
  console.error("build/host-min not found — run `npm run build` first.");
  process.exit(1);
}
if (!existsSync(join(seedkernelHost, "browser.js"))) {
  console.error(`seedkernel minified host not found at ${seedkernelHost} — build seedkernel first (its build emits build/host-min).`);
  process.exit(1);
}

mkdirSync(out, { recursive: true });

// WASM modules.
for (const f of ["kernel.wasm", "bootstrap.wasm", "codec.wasm", "reputation.wasm"]) {
  copyFileSync(join(build, f), join(out, f));
}

// Host JS (seedstore + seedkernel). Copy only .js — the browser does not need
// the .d.ts/.wat/.map artifacts.
const copyJs = (srcDir, dstDir) => {
  mkdirSync(dstDir, { recursive: true });
  for (const name of readdirSync(srcDir)) {
    if (name.endsWith(".js")) copyFileSync(join(srcDir, name), join(dstDir, name));
  }
};
copyJs(join(build, "host-min"), join(out, "host"));
copyJs(seedkernelHost, join(out, "seedkernel"));

// The page itself.
copyFileSync(join(root, "browser", "index.html"), join(out, "index.html"));

console.log(`browser demo staged at ${out}`);
console.log("serve it:  npx http-server build/browser-demo -p 8080");

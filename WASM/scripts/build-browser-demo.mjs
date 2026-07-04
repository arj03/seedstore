// Stage a self-contained browser demo into build/browser-demo — ALL browser pages
// plus the assets they share, so there is ONE staged dir (not one per page):
//   - the four WASM modules (kernel, bootstrap, codec, reputation)
//   - this project's compiled host, minified (build/host-min → host/)
//   - seedkernel's node:fs-free browser host, minified (build/host-min → seedkernel/)
//   - the pages:
//       index.html   — in-page loopback cohort (self-contained)
//       p2p.html     — real P2P over RtcNetwork + relay (signaling) + STUN
//
// Serve it with any static file server, e.g.:
//   npx http-server build/browser-demo -p 3000   (then open /index.html, /p2p.html)
//
// The pages' import maps resolve "seedkernel-wasm/*" → ./seedkernel/* and this
// project's host → ./host/, and pull sumo libsodium from a CDN (vendor an ESM build
// there to run offline). Needs both builds' minified host: seedstore `npm run build`
// and seedkernel `npm run build:host && npm run build:host:min`.

import { mkdirSync, copyFileSync, existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const build = join(root, "build");
const out = process.env.BROWSER_DEMO_OUT ?? join(build, "browser-demo");
const seedstoreHost = join(build, "host-min");
const seedkernelHost = join(root, "..", "..", "seedkernel", "WASM", "build", "host-min");

if (!existsSync(join(seedstoreHost, "browser.js"))) {
  console.error("seedstore build/host-min not found — run `npm run build` first.");
  process.exit(1);
}
if (!existsSync(join(seedkernelHost, "browser.js"))) {
  console.error(`seedkernel minified host not found at ${seedkernelHost} — build seedkernel first ` +
    "(in seedkernel/WASM:  npm run build:host && npm run build:host:min).");
  process.exit(1);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Copy by overwriting in place — we do NOT wipe `out` first. A recursive delete
// followed by an immediate re-copy races on Windows (the dir entry lingers, and
// Defender briefly locks each freshly written file for scanning), which aborts the
// stage mid-copy and leaves a half-populated dir. The staged file set is fixed, so
// overwriting is enough; a transient EPERM/EBUSY/EACCES on a just-written file is
// retried rather than fatal.
async function copy(src, dst) {
  for (let attempt = 1; ; attempt++) {
    try { copyFileSync(src, dst); return; }
    catch (e) {
      const transient = e && (e.code === "EPERM" || e.code === "EBUSY" || e.code === "EACCES");
      if (!transient || attempt >= 8) {
        throw new Error(`could not write ${dst} (${e.code ?? e.message}). ` +
          "If a server or browser is holding build/browser-demo open, stop it and re-run `npm run build:browser-demo`.");
      }
      await sleep(attempt * 50); // back off through the transient lock
    }
  }
}

mkdirSync(out, { recursive: true });

// WASM modules the pages fetch relative to themselves.
for (const f of ["kernel.wasm", "bootstrap.wasm", "codec.wasm", "reputation.wasm"]) {
  await copy(join(build, f), join(out, f));
}

// The guest program (the whole protocol) is content the page fetches as text,
// next to the wasm — browser.js feeds it to StorageNode (no node:fs in the browser).
await copy(join(build, "host", "tier2-guest.js"), join(out, "tier2-guest.js"));

// Host JS (seedstore + seedkernel). Copy only .js — the import maps resolve
// "seedkernel-wasm/*" into ./seedkernel/ and this project's host into ./host/.
async function copyJs(srcDir, dstDir) {
  mkdirSync(dstDir, { recursive: true });
  for (const name of readdirSync(srcDir)) {
    if (name.endsWith(".js")) await copy(join(srcDir, name), join(dstDir, name));
  }
}
await copyJs(seedstoreHost, join(out, "host"));
await copyJs(seedkernelHost, join(out, "seedkernel"));

// ── vendor the browser-only npm deps so the demo runs OFFLINE ────────────────
// QuickJS (quickjs-emscripten + the two quickjs-ng wasm variants) and sumo libsodium
// are multi-file ESM packages with their own bare-specifier imports and a .wasm each;
// the pages used to pull them from esm.sh. Copy the exact runtime files into ./vendor/
// and let the pages' import map name every bare specifier in their graph (…-core,
// quickjs-ffi-types, the /emscripten-module subpaths, libsodium-sumo). Each emscripten
// module finds its wasm via `new URL("emscripten-module.wasm", import.meta.url)`, so the
// .wasm rides in the same dir; libsodium embeds its wasm as base64 (no sibling). Source
// from seedkernel's node_modules (where safe-js pulls QuickJS), falling back to seedstore's.
const nodeModulesDirs = [
  join(root, "..", "..", "seedkernel", "WASM", "node_modules"),
  join(root, "node_modules"),
];
function pkgDist(pkg, sub) {
  for (const nm of nodeModulesDirs) {
    const d = join(nm, ...pkg.split("/"), sub);
    if (existsSync(d)) return d;
  }
  throw new Error(`vendor: ${pkg}/${sub} not found — run npm install (looked in ${nodeModulesDirs.join(", ")}).`);
}
// [package, dist subdir, dest under vendor/, explicit files, copy EVERY .mjs in the dir?]
// The umbrella + core packages are chunked/code-split with hashed names (chunk-*.mjs,
// module-*.mjs), so copy every .mjs from their dist rather than chase hashes; the leaf
// packages need only their named entry (+ the emscripten .wasm sibling).
const VENDOR = [
  ["quickjs-emscripten",      "dist", "quickjs-emscripten",      ["index.mjs"], true],
  ["quickjs-emscripten-core", "dist", "quickjs-emscripten-core", ["index.mjs"], true],
  ["@jitl/quickjs-ffi-types", "dist", "quickjs-ffi-types",       ["index.mjs"], false],
  ["@jitl/quickjs-ng-wasmfile-release-asyncify", "dist", "qjs-async",
    ["index.mjs", "ffi.mjs", "emscripten-module.browser.mjs", "emscripten-module.wasm"], false],
  ["@jitl/quickjs-ng-wasmfile-release-sync", "dist", "qjs-sync",
    ["index.mjs", "ffi.mjs", "emscripten-module.browser.mjs", "emscripten-module.wasm"], false],
  ["libsodium-wrappers-sumo", "dist/modules-sumo-esm", "libsodium-wrappers-sumo", ["libsodium-wrappers.mjs"], false],
  ["libsodium-sumo",          "dist/modules-sumo-esm", "libsodium-sumo",          ["libsodium-sumo.mjs"], false],
];
for (const [pkg, sub, dest, files, allMjs] of VENDOR) {
  const src = pkgDist(pkg, sub);
  const dstDir = join(out, "vendor", dest);
  mkdirSync(dstDir, { recursive: true });
  const names = new Set(files);
  if (allMjs) for (const n of readdirSync(src)) if (n.endsWith(".mjs")) names.add(n);
  for (const n of names) await copy(join(src, n), join(dstDir, n));
}

// The signed bundle manifest, if a bundle has been built (`npm run build:bundle`).
// p2p.html fetches ./manifest.bundle and reads its author public key (the first 32
// bytes) to auto-derive the cohort's signing scope, so a browser joining a cohort of
// bundle-running holders (seedloaders) matches their author scope without the user
// pasting a key. Absent → the page falls back to the zero-author default. Only the
// manifest is staged (32-byte author header + JSON); the *.wasm/*.install payloads
// stay on the holders — the browser needs the author, not the bundle contents.
const bundleManifest = [join(root, "bundle", "manifest.bundle"), join(build, "bundle", "manifest.bundle")]
  .find((p) => existsSync(p));
if (bundleManifest) await copy(bundleManifest, join(out, "manifest.bundle"));

// Every browser page, into the one dir.
for (const page of ["index.html", "p2p.html"]) {
  await copy(join(root, "browser", page), join(out, page));
}

console.log(`browser demo staged at ${out}  (deps vendored under ./vendor — runs offline)`);
console.log(bundleManifest
  ? "cohort author: p2p.html auto-reads ./manifest.bundle (bundle present)"
  : "cohort author: no ./bundle — p2p.html defaults to zero-author scope (run `npm run build:bundle` for a seedloader cohort)");
console.log("serve it:   npx http-server build/browser-demo -p 3000");
console.log("  in-page cohort:        http://localhost:3000/index.html");
console.log("  real P2P (relay+STUN): npm run demo:relay  +  npm run serve:rtc-holder  → http://localhost:3000/p2p.html");

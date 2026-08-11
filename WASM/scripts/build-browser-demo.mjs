// Stage a self-contained browser demo into build/browser-demo — ALL browser pages
// plus the assets they share, so there is ONE staged dir (not one per page):
//   - the four WASM modules (kernel, signature, codec, reputation)
//   - this project's compiled host, minified (build/host-min → host/)
//   - seedkernel's node:fs-free browser host, minified (build-min → seedkernel/)
//   - the pages:
//       index.html   — in-page loopback cohort (self-contained)
//       p2p.html     — real P2P over RtcNetwork + relay (signaling) + STUN
//
// Serve it with any static file server, e.g.:
//   npx http-server build/browser-demo -p 3000   (then open /index.html, /p2p.html)
//
// The pages' import maps resolve "seedkernel-wasm/*" → ./seedkernel/* and this
// project's host → ./host/. Nothing is fetched at runtime: QuickJS is vendored under
// ./vendor/ and libsodium comes from the kernel (its "./libsodium" export), so the
// staged dir runs offline. Needs both builds' minified host: seedstore `npm run build`
// and seedkernel `npm run build:host && npm run build:host:min`.

import { mkdirSync, copyFileSync, existsSync, readdirSync, statSync, rmSync,
         readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { unpackBundle, MANIFEST_FILE } from "seedkernel-wasm/bundle";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const build = join(root, "build");
const out = process.env.BROWSER_DEMO_OUT ?? join(build, "browser-demo");
const seedstoreHost = join(build, "host-min");
// The kernel's minified tree: build-min (host/ + core/ subdirs) — its minifier
// moved the output there from the old build/host-min.
const seedkernelHost = join(root, "..", "..", "seedkernel", "WASM", "build-min");

if (!existsSync(join(seedstoreHost, "browser.js"))) {
  console.error("seedstore build/host-min not found — run `npm run build` first.");
  process.exit(1);
}
if (!existsSync(join(seedkernelHost, "host", "shell-core.js"))) {
  console.error(`seedkernel minified host not found at ${seedkernelHost} — build seedkernel first ` +
    "(in seedkernel/WASM:  npm run build).");
  process.exit(1);
}

// ── staleness guard: the browser runs the MINIFIED host, Node tests run build/ ──
// The two builds diverge silently when `build:host` (tsc) is re-run but `build:host:min`
// (minify) is not — a real trap after switching branches: tests stay green against the
// fresh build/ while the browser serves a stale min tree, so the demo runs old code
// and fails in confusing ways (e.g. a codec/guest mismatch → "blockIds.length must equal
// k+m"). Catch it here, the last step before the browser, for BOTH repos: if any compiled
// build/ .js is newer than the whole min tree, the minify step lagged. This also
// covers the cross-repo seam — seedkernel's min tree is trivial to leave stale from here.
function newestJsMtime(dir) {
  let newest = 0;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) newest = Math.max(newest, newestJsMtime(p));
    else if (name.endsWith(".js")) newest = Math.max(newest, st.mtimeMs);
  }
  return newest;
}
function assertMinFresh(label, hostDir, minDir, rebuildCmd) {
  // Need both trees to compare mtimes: no compiled host (a min-only checkout) or no min
  // dir at all → nothing to assert. (The min dirs are also checked earlier before staging,
  // so a missing min here is only reachable if this guard is reused in another order.)
  if (!existsSync(hostDir) || !existsSync(minDir)) return;
  const host = newestJsMtime(hostDir), min = newestJsMtime(minDir);
  if (host > min + 1000) { // 1s slack for filesystem mtime granularity
    console.error(
      `${label} min tree is STALE: build/ is newer than build-min, so the minify ` +
      `step did not re-run after the last compile.\n` +
      `The browser would run old code (Node tests read build/ and stay green — this only ` +
      `bites the browser).\n` +
      `Fix: ${rebuildCmd}`);
    process.exit(1);
  }
}
assertMinFresh("seedstore", join(build, "host"), seedstoreHost,
  "in seedstore/WASM run `npm run build` (or at least `npm run build:host:min`).");
assertMinFresh("seedkernel", join(root, "..", "..", "seedkernel", "WASM", "build"),
  seedkernelHost,
  "in seedkernel/WASM run `npm run build`.");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Copy by overwriting in place — we do NOT wipe `out` first. A recursive delete
// followed by an immediate re-copy races on Windows (the dir entry lingers, and
// Defender briefly locks each freshly written file for scanning), which aborts the
// stage mid-copy and leaves a half-populated dir. The staged file set is fixed, so
// overwriting is enough; a transient EPERM/EBUSY/EACCES on a just-written file is
// retried rather than fatal.
const staged = new Set(); // every path we write, so we can prune anything else from `out`
async function copy(src, dst) {
  staged.add(resolve(dst));
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
for (const f of ["codec.wasm", "reputation.wasm"]) {
  await copy(join(build, f), join(out, f));
}

// The guest program (the whole protocol) is content the page fetches as text,
// next to the wasm — browser.js feeds it to StorageNode (no node:fs in the browser).
await copy(join(build, "host", "tier2-guest.js"), join(out, "tier2-guest.js"));

// Host JS (seedstore + seedkernel). Copy .js recursively — the kernel's minified
// tree now has host/ and core/ subdirs (host modules import ../core/* by relative
// path), and the import maps resolve "seedkernel-wasm/*" into ./seedkernel/ and
// this project's host into ./host/.
//
// Node-only modules do NOT ship. Both minified trees carry modules that exist for the
// Node host (the kernel's crypto-node/fs-node/net-node/main*, this project's node.js)
// and reach for `node:` builtins and bare npm specifiers no browser can resolve. No
// page imports them, so today they are only dead weight — but dead weight that makes
// the served tree look like it depends on packages it does not (crypto-node's bare
// `libsodium-wrappers-sumo` is why the import map used to carry a sumo entry it never
// needed). Skip them on the property that makes them node-only, a `node:` import, and
// assert below that nothing staged imports one — so the rule can never silently drop a
// module a page actually needs.
const skippedNodeOnly = new Set(); // dest paths deliberately NOT staged
const isNodeOnly = (src) => /["']node:[\w/.-]+["']/.test(readFileSync(src, "utf8"));
async function copyJs(srcDir, dstDir) {
  mkdirSync(dstDir, { recursive: true });
  for (const name of readdirSync(srcDir)) {
    const p = join(srcDir, name);
    const st = statSync(p);
    if (st.isDirectory()) await copyJs(p, join(dstDir, name));
    else if (!name.endsWith(".js")) continue;
    else if (isNodeOnly(p)) skippedNodeOnly.add(resolve(join(dstDir, name)));
    else await copy(p, join(dstDir, name));
  }
}
await copyJs(seedstoreHost, join(out, "host"));
await copyJs(seedkernelHost, join(out, "seedkernel"));

// ML-DSA-65, the PQ half of seedkernel's one manifest suite (§12.4) — the same artifact
// Node reads and the Go loader embeds. p2p.html mixes it into its sodium instance so
// `verifyManifest` can read the cohort's author id; without it no manifest verifies at
// all and the page would silently fall back to the zero-author scope.
{
  const src = join(root, "..", "..", "seedkernel", "WASM", "browser", "mldsa65.wasm");
  if (!existsSync(src)) {
    console.error(`seedkernel mldsa65.wasm not found at ${src} — build it first ` +
      "(in seedkernel/WASM:  npm run build:pq).");
    process.exit(1);
  }
  await copy(src, join(out, "mldsa65.wasm"));
}

// ── sumo libsodium: the kernel's, not a second copy ──────────────────────────
// The pages import "seedkernel-wasm/libsodium" — the kernel's published browser entry
// — rather than the upstream npm package, so the browser, the Node host and the Go
// loader all run the SAME crypto binary. (They used to vendor libsodium-wrappers-sumo
// out of node_modules below, which is the same library but not the same artifact, and
// it needed a dev install of the kernel to stage.) These three files are checked in and
// must land in ONE directory: the wrapper resolves the core and the .wasm relative to
// its own import.meta.url, and its wasm is a sibling fetch rather than a base64 blob.
{
  const srcDir = join(root, "..", "..", "seedkernel", "WASM", "browser");
  for (const f of ["libsodium-wrappers.mjs", "libsodium-core.mjs", "libsodium.wasm"]) {
    const src = join(srcDir, f);
    if (!existsSync(src)) {
      console.error(`seedkernel ${f} not found at ${src} — build it first ` +
        "(in seedkernel/WASM:  npm run build:browser-sodium).");
      process.exit(1);
    }
    await copy(src, join(out, "seedkernel", f));
  }
}

// ── vendor the browser-only npm deps so the demo runs OFFLINE ────────────────
// QuickJS (quickjs-emscripten + the two quickjs-ng wasm variants) is a set of multi-file
// ESM packages with their own bare-specifier imports and a .wasm each; the pages used to
// pull them from esm.sh. Copy the exact runtime files into ./vendor/ and let the pages'
// import map name every bare specifier in their graph (…-core, quickjs-ffi-types, the
// /emscripten-module subpaths). Each emscripten module finds its wasm via
// `new URL("emscripten-module.wasm", import.meta.url)`, so the .wasm rides in the same
// dir. Source from seedkernel's node_modules (where safe-js pulls QuickJS), falling back
// to seedstore's. libsodium is NOT here — it is staged from the kernel above.
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
// pasting a key. Absent → the page falls back to the zero-author default.
//
// A bundle is one blob (seedkernel §12.4), so unpack it and stage ONLY the manifest
// envelope from inside — a standalone signed artifact (32-byte author header + sig +
// JSON) that `verifyManifest` checks on its own. The *.wasm payloads and the guest stay
// on the holders: the browser needs the author, not megabytes of bundle contents.
const bundleBlob = [join(root, "bundle", "seedstore.skb"), join(build, "bundle", "seedstore.skb")]
  .find((p) => existsSync(p));
let bundleManifest = false;
if (bundleBlob) {
  // Stage the whole signed bundle: a browser page boots a StorageNode on it (the ONE
  // install path), so the page fetches ./seedstore.skb exactly like a Node node reads
  // bundle/seedstore.skb.
  await copy(bundleBlob, join(out, "seedstore.skb"));
  const files = unpackBundle(new Uint8Array(readFileSync(bundleBlob)));
  if (files[MANIFEST_FILE]) {
    const dst = join(out, MANIFEST_FILE);
    writeFileSync(dst, files[MANIFEST_FILE]);
    staged.add(resolve(dst)); // it is unpacked, not copy()'d, so register it or prune eats it
    bundleManifest = true;
  }
}

// Every browser page, into the one dir.
for (const page of ["index.html", "p2p.html"]) {
  await copy(join(root, "browser", page), join(out, page));
}

// ── resolve each page's module graph, exactly as the browser will ────────────
// Two ways this stage ships a dir the browser refuses, both of which used to surface
// only as a console error on load: a bare "seedkernel-wasm/*" specifier the page's
// import map has no entry for (the map is hand-maintained, the imports are not), and a
// relative import of a module that is not staged — including the `node:`-importing ones
// copyJs deliberately left out. Walk the real graph from each page: follow relative
// imports through the staged files, resolve bare ones through that page's own map, and
// fail here with the file that named the specifier. Only what a page can actually reach
// is checked, so a module staged for the OTHER page (net-rtc) needs no entry in this one.
// A specifier is `from "x"`, `import("x")`, or a bare side-effect `import "x"` at the
// start of a statement. Kept deliberately tight — no newline inside the quotes and no
// newline before them — so prose in a comment ("…the import kind…") followed by an
// unrelated string literal cannot read as an import.
const SPEC = /(?:\bfrom[ \t]*|\bimport[ \t]*\([ \t]*|(?:^|[;}])[ \t]*import[ \t]*)["']([^"'\n]+)["']/gm;
function importMapOf(html) {
  const m = html.match(/<script type="importmap">([\s\S]*?)<\/script>/);
  if (!m) throw new Error("page has no import map");
  return JSON.parse(m[1]).imports ?? {};
}
function checkPage(page) {
  const pagePath = join(out, page);
  const map = importMapOf(readFileSync(pagePath, "utf8"));
  const seen = new Set();
  const fail = (from, spec, why) => {
    console.error(`${page}: ${relative(out, from)} imports "${spec}" — ${why}`);
    process.exit(1);
  };
  (function walk(file) {
    if (seen.has(file)) return;
    seen.add(file);
    for (const [, spec] of readFileSync(file, "utf8").matchAll(SPEC)) {
      let target;
      if (spec.startsWith(".")) {
        target = resolve(dirname(file), spec);
      } else if (map[spec]) {
        target = resolve(out, map[spec]);
      } else if (spec.startsWith("node:")) {
        fail(file, spec, "a Node builtin: this module should not be in the browser graph.");
      } else {
        fail(file, spec, `no import map entry on this page. Add one, or stop importing it.\n` +
          `  (bare specifiers only resolve in a browser through the map — the Node build ` +
          `resolves them through node_modules, so tests stay green while the page breaks.)`);
      }
      if (!existsSync(target)) {
        fail(file, spec, skippedNodeOnly.has(target)
          ? `NOT staged: it imports a \`node:\` builtin, so it is a Node-host module the ` +
            `browser cannot load. Either it stopped being Node-only, or the browser code ` +
            `should not reach for it.`
          : `not staged at ${relative(out, target)}.`);
      }
      walk(target);
    }
  })(pagePath);
}
for (const page of ["index.html", "p2p.html"]) checkPage(page);

// ── prune: remove anything in `out` we did NOT just stage ────────────────────
// We overwrite in place rather than wiping `out` up front (a wipe-then-recopy races
// Windows/Defender — see copy() above), so files from an earlier build linger. After
// a branch switch that means stale host/*.js, seedkernel/*.js, or a leftover signed
// bundle sit next to fresh code and get served — the same class of confusing failure
// the staleness guard above prevents. The staged set is authoritative: delete every
// other file, then drop the dirs left empty, so `out` holds EXACTLY this build. A
// staged manifest.bundle is in the set (copy() adds it), so it survives; a stale one
// from a prior build with no bundle now is correctly pruned.
function prune(dir) {
  let kept = 0;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      const childKept = prune(p);
      if (childKept === 0) { rmSync(p, { recursive: true, force: true }); }
      else kept += childKept;
    } else if (staged.has(resolve(p))) {
      kept++;
    } else {
      rmSync(p, { force: true });
      console.log(`  pruned stale ${relative(out, p)}`);
    }
  }
  return kept;
}
prune(out);

console.log(`browser demo staged at ${out}  (deps vendored under ./vendor — runs offline)`);
console.log(bundleManifest
  ? "cohort author: p2p.html auto-reads ./manifest.bundle (bundle present)"
  : "cohort author: no ./bundle — p2p.html defaults to zero-author scope (run `npm run build:bundle` for a seedloader cohort)");
console.log("serve it:   npm run serve:demo        (re-stages + http-server with caching OFF)");
console.log("  ── DO NOT use a plain `http-server` without -c-1: its default max-age=3600 makes");
console.log("     the browser keep a STALE codec.wasm after a rebuild → confusing errors.");
console.log("  in-page cohort:        http://localhost:3000/index.html");
console.log("  real P2P (direct WS):  seedloader --ws-listen nodes, endpoints pasted in → http://localhost:3000/p2p.html");
console.log("  real P2P (relay+STUN): seedchat's `npm run relay`  +  npm run serve:rtc-holder  → same page, WebRTC transport");

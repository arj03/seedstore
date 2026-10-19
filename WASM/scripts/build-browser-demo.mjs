// Stage a self-contained browser demo into build/browser-demo — ALL browser pages
// plus the assets they share, so there is ONE staged dir (not one per page):
//   - the four WASM modules (libsodium, signature, codec, reputation)
//   - this project's compiled host, minified (build/host-min → host/)
//   - seedkernel's node:fs-free browser host, minified (build-min → seedkernel/)
//   - the pages: index.html (in-page loopback cohort), p2p.html (real P2P)
//
// Serve it with any static file server:
//   npx http-server build/browser-demo -p 3000   (then open /index.html, /p2p.html)
//
// The pages' import maps resolve "seedkernel-wasm/*" → ./seedkernel/* and this
// project's host → ./host/. Nothing is fetched from elsewhere at runtime — QuickJS
// (qjs.wasm) and libsodium ship under this dir, so it runs offline. Needs
// both builds' minified host and seedkernel's browser/ artifacts: seedstore
// `npm run build`, seedkernel `npm run build`.

import { mkdirSync, copyFileSync, existsSync, readdirSync, statSync, rmSync,
         readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const build = join(root, "build");
const out = process.env.BROWSER_DEMO_OUT ?? join(build, "browser-demo");
const seedstoreHost = join(build, "host-min");
// seedkernel's minified tree: build-min (host/ + services/ subdirs) — its minifier
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
// The two builds diverge silently when `build:host` (tsc) reruns but
// `build:host:min` does not — tests stay green against fresh build/ while the
// browser serves stale code. Catch it here, for both repos: if any compiled
// build/ .js is newer than the whole min tree, the minify step lagged.
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
function assertMinFresh(label, hostDir, minDir, rebuildCmd, subs = [""]) {
  // `subs` narrows the comparison to the subtrees the minify step actually
  // covers — seedkernel's build/ also holds fixture output that no
  // tsc<->minify cycle touches, which would otherwise false-alarm every run.
  for (const sub of subs) {
    const host = join(hostDir, sub), min = join(minDir, sub);
    if (!existsSync(host) || !existsSync(min)) continue;
    if (newestJsMtime(host) > newestJsMtime(min) + 1000) { // 1s slack for mtime granularity
      console.error(
        `${label} min tree is STALE: build/${sub} is newer than build-min, so the minify ` +
        `step did not re-run after the last compile.\n` +
        `The browser would run old code (Node tests read build/ and stay green — this only ` +
        `bites the browser).\n` +
        `Fix: ${rebuildCmd}`);
      process.exit(1);
    }
  }
}
assertMinFresh("seedstore", join(build, "host"), seedstoreHost,
  "in seedstore/WASM run `npm run build` (or at least `npm run build:host:min`).");
assertMinFresh("seedkernel", join(root, "..", "..", "seedkernel", "WASM", "build"),
  seedkernelHost,
  "in seedkernel/WASM run `npm run build`.",
  ["host", "services"]);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Copy by overwriting in place — we do NOT wipe `out` first. A recursive delete
// followed by an immediate re-copy races on Windows (Defender briefly locks each
// freshly written file), aborting the stage mid-copy. Retry a transient
// EPERM/EBUSY/EACCES rather than treating it as fatal.
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

// seedrelay's room client, which p2p.html meets its room with: rooms are the page's, not
// the transport's. seedrelay is a sibling checkout, as seedkernel is.
const roomsSrc = join(root, "..", "..", "seedrelay", "rooms.mjs");
if (!existsSync(roomsSrc)) {
  console.error(`seedrelay not found at ${dirname(roomsSrc)} — check it out beside seedstore.`);
  process.exit(1);
}
mkdirSync(join(out, "seedrelay"), { recursive: true });
await copy(roomsSrc, join(out, "seedrelay", "rooms.mjs"));

// The guest program (the whole protocol) is content the page fetches as text,
// next to the wasm — browser.js feeds it to StorageNode (no node:fs in the browser).
await copy(join(build, "host", "tier2-guest.js"), join(out, "tier2-guest.js"));

// Host JS (seedstore + seedkernel). Copy .js recursively — seedkernel's minified
// tree has host/ and services/ subdirs, and the import maps resolve
// "seedkernel-wasm/*" into ./seedkernel/ and this project's host into ./host/.
//
// Node-only modules do NOT ship: both minified trees carry modules that exist
// only for the Node host and reach for `node:` builtins or bare npm specifiers
// no browser can resolve. Skip them on the property that makes them node-only —
// a STATIC `node:` import — and assert below that nothing staged still imports
// one, so the rule can never silently drop a module a page actually needs.
//
// A DYNAMIC `node:` import is a branch, not a dependency (e.g. seedkernel's
// module table reaches for `node:worker_threads` only when there's no DOM
// `Worker`), so it must not be treated as node-only.
//
// A specifier is `from "x"`, `import("x")`, or a bare side-effect `import "x"`
// at the statement start — kept tight (no newline inside or before the quotes)
// so comment prose can't be misread as an import.
const SPEC = /(?:\bfrom[ \t]*|(\bimport[ \t]*\([ \t]*)|(?:^|[;}])[ \t]*import[ \t]*)["']([^"'\n]+)["']/gm;
const skippedNodeOnly = new Set(); // dest paths deliberately NOT staged
const isNodeOnly = (src) => {
  for (const [, dynamic, spec] of readFileSync(src, "utf8").matchAll(SPEC)) {
    if (spec.startsWith("node:") && !dynamic) return true;
  }
  return false;
};
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

// ML-DSA-65, the PQ half of seedkernel's one manifest suite (§12.4). p2p.html
// mixes it into its sodium instance so `verifyBundle` can read the cohort's
// author id; without it no bundle verifies and the page falls back silently
// to the zero-author scope.
{
  const src = join(root, "..", "..", "seedkernel", "WASM", "browser", "mldsa65.wasm");
  if (!existsSync(src)) {
    console.error(`seedkernel mldsa65.wasm not found at ${src} — build it first ` +
      "(in seedkernel/WASM:  npm run build:pq).");
    process.exit(1);
  }
  await copy(src, join(out, "mldsa65.wasm"));
}

// ML-KEM-768 is private content of the signed transport bundle now; no loose
// browser artifact is needed here.

// ── core libsodium: seedkernel's, not a second copy ──────────────────────────
// The pages import "seedkernel-wasm/libsodium" (seedkernel's published browser
// entry) rather than the upstream npm package, so browser, Node, and the Go
// binary all run the SAME crypto binary. These three files must land in ONE
// directory: the wrapper resolves the core and .wasm relative to its own
// import.meta.url, and the wasm is a sibling fetch, not a base64 blob.
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

// ── the QuickJS engine: seedkernel's qjs.wasm, the one every target runs ─────
// Realms run on WebAssembly itself (seedkernel host/engine-web.ts), which fetches
// `../../browser/qjs.wasm` relative to its own module: from ./seedkernel/host/ that
// is ./browser/qjs.wasm here.
{
  const src = join(root, "..", "..", "seedkernel", "WASM", "browser", "qjs.wasm");
  if (!existsSync(src)) {
    console.error(`seedkernel qjs.wasm not found at ${src} — build it first ` +
      "(in seedkernel/WASM:  npm run build).");
    process.exit(1);
  }
  mkdirSync(join(out, "browser"), { recursive: true });
  await copy(src, join(out, "browser", "qjs.wasm"));
}

// The signed bundle, if one has been built (`npm run build:bundle`). ONE artifact
// for both jobs: a browser page boots a StorageNode on it, fetching ./seedstore.skb
// exactly like a Node node reads bundle/seedstore.skb, and reads its verified author
// to auto-derive the cohort's signing scope. Absent -> the zero-author default.
const bundleBlob = [join(root, "bundle", "seedstore.skb"), join(build, "bundle", "seedstore.skb")]
  .find((p) => existsSync(p));
if (bundleBlob) await copy(bundleBlob, join(out, "seedstore.skb"));

// Every browser page, into the one dir.
for (const page of ["index.html", "p2p.html"]) {
  await copy(join(root, "browser", page), join(out, page));
}

// ── resolve each page's module graph, exactly as the browser will ────────────
// Catches two failures that otherwise only surface as a console error on load:
// a bare specifier missing from the page's (hand-maintained) import map, and a
// relative import of a module that isn't staged. Walk the real graph from each
// page, resolving relative imports through staged files and bare ones through
// the map, failing with the file that named the bad specifier.
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
    for (const [, dynamic, spec] of readFileSync(file, "utf8").matchAll(SPEC)) {
      let target;
      if (spec.startsWith(".")) {
        target = resolve(dirname(file), spec);
      } else if (map[spec]) {
        target = resolve(out, map[spec]);
      } else if (spec.startsWith("node:")) {
        // STATIC is fatal wherever it appears (catches a Node-host module that
        // slipped past copyJs). DYNAMIC is a branch, not a dependency (e.g. the
        // seedkernel's glue reaches for `node:module` only inside its
        // ENVIRONMENT_IS_NODE test) — nothing to resolve, so skip it.
        if (dynamic) continue;
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
// We overwrite in place rather than wiping `out` up front (see copy() above),
// so files from an earlier build (or branch) can linger and get served stale.
// The staged set is authoritative: delete everything else, then drop dirs left empty.
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

console.log(`browser demo staged at ${out}  (runs offline)`);

console.log("serve it:   npm run serve:demo        (re-stages + http-server with caching OFF)");
console.log("  ── DO NOT use a plain `http-server` without -c-1: its default max-age=3600 makes");
console.log("     the browser keep a STALE codec.wasm after a rebuild → confusing errors.");
console.log("  in-page cohort:        http://localhost:3000/index.html");
console.log("  real P2P (direct WS):  seedkernel --listen ws=… nodes, endpoints pasted in → http://localhost:3000/p2p.html");
console.log("  real P2P (relay+STUN): `seedrelay` (or seedshell's `npm run relay`) + npm run serve:rtc-holder");

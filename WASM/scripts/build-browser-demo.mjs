// Stage a self-contained browser demo into build/browser-demo — ALL browser pages
// plus the assets they share, so there is ONE staged dir (not one per page):
//   - seedkernel's host blob (host.skb: its realm engine and the host's crypto)
//   - this project's own libsodium (libsodium/), and the signed seedstore bundle
//     (seedstore.skb: codec, reputation module and guest under one signature)
//   - this project's compiled host, minified (build/host-min → host/)
//   - seedkernel's node:fs-free browser host, minified (build-min → seedkernel/)
//   - the pages: index.html (in-page loopback cohort), p2p.html (real P2P)
//
// Serve it with any static file server:
//   npx http-server build/browser-demo -p 3000   (then open /index.html, /p2p.html)
//
// The pages' import maps resolve "seedkernel-wasm/*" → ./seedkernel/* and this
// project's host → ./host/. Nothing is fetched from elsewhere at runtime — QuickJS and
// the host's crypto (in host.skb) and libsodium ship under this dir, so it runs offline.
// Needs both builds' minified host and seedkernel's host blob: seedstore `npm run build`,
// seedkernel `npm run build`.

import { mkdirSync, copyFileSync, existsSync, readdirSync, statSync, rmSync,
         readFileSync, writeFileSync } from "node:fs";
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

// seedrelay's room client, which p2p.html meets its room with: rooms are the page's, not
// the transport's. seedrelay is a sibling checkout, as seedkernel is.
const roomsSrc = join(root, "..", "..", "seedrelay", "rooms.mjs");
if (!existsSync(roomsSrc)) {
  console.error(`seedrelay not found at ${dirname(roomsSrc)} — check it out beside seedstore.`);
  process.exit(1);
}
mkdirSync(join(out, "seedrelay"), { recursive: true });
await copy(roomsSrc, join(out, "seedrelay", "rooms.mjs"));

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

// seedkernel's host blob: the host script, the realm engine every guest runs on, and the
// host's crypto, libsodium and ML-DSA-65 (the PQ half of seedkernel's one manifest suite,
// §12.4, without which no bundle verifies). The pages' loader runs it
// (seedkernel-wasm/platform-web `browserHost`): the host the Node and native nodes run.
{
  const src = join(root, "..", "..", "seedkernel", "WASM", "build", "host.skb");
  if (!existsSync(src)) {
    console.error(`seedkernel host.skb not found at ${src} — build it first ` +
      "(in seedkernel/WASM:  npm run build).");
    process.exit(1);
  }
  await copy(src, join(out, "host.skb"));
}

// ML-KEM-768 is private content of the signed transport bundle now; no loose
// browser artifact is needed here.

// ── this project's own libsodium ─────────────────────────────────────────────
// What the page's own code computes (block ids, key sealing, ChaCha20-Poly1305) is
// seedstore's, so it runs on seedstore's own dependency, libsodium-wrappers, the whole
// API. Its wasm is the libsodium.wasm already in host.skb, so the page fetches it once:
// the wrapper is staged with its core's embedded base64 copy blanked, and patched to
// instantiate the bytes the page hands it (`useWasm`, from seedkernel-wasm/platform-web
// `readHostBlob(blob).sodium`) as its own instance beside the host's. The wrapper
// starts its init at import, so the bytes arrive through a promise it waits on.
{
  const nm = join(root, "node_modules");
  const coreSrc = join(nm, "libsodium", "dist", "modules-esm", "libsodium.mjs");
  const wrapSrc = join(nm, "libsodium-wrappers", "dist", "modules-esm", "libsodium-wrappers.mjs");
  if (!existsSync(coreSrc) || !existsSync(wrapSrc)) {
    console.error("libsodium-wrappers not found in node_modules — run `npm install`.");
    process.exit(1);
  }
  const core = readFileSync(coreSrc, "utf8");
  // The embedded wasm is a base64 string literal beginning "AGFzbQ" (the "\0asm" magic).
  const b64Start = core.indexOf('"AGFzbQ');
  const b64End = b64Start < 0 ? -1 : core.indexOf('"', b64Start + 1);
  if (b64End < 0) throw new Error("could not locate the base64 wasm in libsodium.mjs — upstream layout changed?");
  // Emscripten glue runs only the wasm it was built with, so this package's libsodium
  // must be the build seedkernel's host blob carries: bump them together.
  const { readHostBlob } = await import("seedkernel-wasm/platform-web");
  const blobWasm = readHostBlob(new Uint8Array(readFileSync(join(out, "host.skb")))).sodium;
  if (!Buffer.from(core.slice(b64Start + 1, b64End), "base64").equals(blobWasm)) {
    console.error("libsodium-wrappers in node_modules is not the libsodium build in seedkernel's host blob — " +
      "pin seedstore's libsodium-wrappers to the version seedkernel/WASM/package.json pins, then `npm install`.");
    process.exit(1);
  }
  const wrap = readFileSync(wrapSrc, "utf8");
  const wrapPatched = "let giveWasm;const wasmBytes=new Promise((r)=>{giveWasm=r;});" +
    "export function useWasm(bytes){giveWasm(bytes);}" +
    wrap
      .replace('import e from"libsodium"', 'import e from"./libsodium-core.mjs"')
      .replace(
        "a({getRandomValue:function(){",
        "a({instantiateWasm:async(imports,cb)=>{" +
          "const{instance}=await WebAssembly.instantiate(await wasmBytes,imports);" +
          "cb(instance);" +
        "},getRandomValue:function(){");
  if (!wrapPatched.includes("./libsodium-core.mjs") || !wrapPatched.includes("instantiateWasm")) {
    throw new Error("libsodium-wrappers patch failed — upstream layout changed?");
  }
  mkdirSync(join(out, "libsodium"), { recursive: true });
  const write = (name, data) => {
    const dst = join(out, "libsodium", name);
    staged.add(resolve(dst));
    writeFileSync(dst, data);
  };
  write("libsodium-core.mjs", core.slice(0, b64Start) + '""' + core.slice(b64End + 1));
  write("libsodium-wrappers.mjs", wrapPatched);
}

// The signed bundle (`npm run build:bundle`): the codec, the reputation module and the
// guest all ride inside it, so it is the one storage artifact a page fetches
// (./seedstore.skb), as a Node node reads bundle/seedstore.skb. Both pages boot on it.
const bundleBlob = join(root, "bundle", "seedstore.skb");
if (!existsSync(bundleBlob)) {
  console.error(`seedstore bundle not found at ${bundleBlob} — run \`npm run build\` first.`);
  process.exit(1);
}
await copy(bundleBlob, join(out, "seedstore.skb"));

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
console.log("     the browser keep a STALE seedstore.skb or host JS after a rebuild → confusing errors.");
console.log("  in-page cohort:        http://localhost:3000/index.html");
console.log("  real P2P (direct WS):  seedkernel --listen ws=… nodes, endpoints pasted in → http://localhost:3000/p2p.html");
console.log("  real P2P (relay+STUN): `seedrelay` (or seedshell's `npm run relay`) + npm run serve:holder");

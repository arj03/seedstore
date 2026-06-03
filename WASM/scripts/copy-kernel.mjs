// Copy the prebuilt kernel.wasm + bootstrap.wasm from the sibling seedkernel
// checkout into this project's build/ dir. seedstore runs a node *on* the
// seedkernel — it does not re-implement the kernel — so the two core modules
// are taken verbatim from upstream (path dependency, README "How it composes
// with the kernel" §2).
//
// Run: node scripts/copy-kernel.mjs
//
// If seedkernel has not been built yet, build it first:
//   (cd ../../seedkernel/WASM && npm install && npm run build)

import { mkdirSync, copyFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const kernelBuild = join(root, "..", "..", "seedkernel", "WASM", "build");
const outDir = join(root, "build");

const files = ["kernel.wasm", "bootstrap.wasm"];

mkdirSync(outDir, { recursive: true });

let missing = false;
for (const f of files) {
  const src = join(kernelBuild, f);
  if (!existsSync(src)) {
    console.error(`  MISSING: ${src}`);
    missing = true;
    continue;
  }
  copyFileSync(src, join(outDir, f));
  console.log(`  copied ${f}`);
}

if (missing) {
  console.error(
    "\nseedkernel build artifacts not found. Build the sibling project first:\n" +
      "  (cd ../../seedkernel/WASM && npm install && npm run build)\n",
  );
  process.exit(1);
}

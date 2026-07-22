// Browser entry-point test. We exercise host/browser.js — which loads the WASM
// modules via fetch() and takes an injected libsodium — by shimming fetch over
// the local build dir. This proves the same StorageNode boots and serves
// PUT/GET through the browser code path, without node:fs (§1, §20: browser and
// long-running nodes run the same protocol).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ensureSodium } from "./helpers.mjs";
import { bytesEqual } from "../build/host/util.js";

const buildDir = join(dirname(fileURLToPath(import.meta.url)), "..", "build");

export async function run(t) {
  const sodium = await ensureSodium();
  const origFetch = globalThis.fetch;
  // Shim fetch to serve the wasm + the guest program from disk, as a static file
  // server would in a real deployment. The wasm sit at the build root; the guest
  // program is under host/ (browser.js fetches it as text).
  globalThis.fetch = async (url) => {
    const name = String(url).split("/").pop();
    // codec.wasm/reputation.wasm live under build/; the bundle lives under bundle/
    const path = name === "seedstore.skb"
      ? join(buildDir, "..", "bundle", name)
      : name === "tier2-guest.js" ? join(buildDir, "host", name) : join(buildDir, name);
    const buf = readFileSync(path);
    return {
      arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength),
      text: async () => buf.toString("utf8"),
    };
  };
  try {
    const { createStorageNode, LoopbackNetwork, StorageNode } = await import("../build/host/browser.js");

    t.group("browser entry: fetch-loaded WASM + injected sodium runs a node");
    const net = new LoopbackNetwork();
    const config = { k: 2, m: 2, blockSize: 64 };
    const nodes = [];
    for (let i = 0; i < 5; i++) {
      nodes.push(await createStorageNode({ network: net, sodium, baseUrl: "build/", config, timeoutMs: 40 }));
    }
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) StorageNode.connect(nodes[i], nodes[j]);
    }
    t.ok(nodes[0].handlersInstalled(), "node booted through the browser fetch path");

    const data = new Uint8Array(200).map((_, i) => (i * 5 + 1) & 255);
    const put = await nodes[0].put(data);
    const got = await nodes[0].get(put.manifestId, put.key);
    t.ok(bytesEqual(got, data), "PUT/GET round trip works through the browser entry point");

    nodes.forEach((n) => n.close());
  } finally {
    globalThis.fetch = origFetch;
  }
}

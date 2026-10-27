// seedstore — put and get files, and see where they are kept. Each command is an op of the
// bundle's client surface (SPEC §18.1), so the node answers from its own state:
//
//   node scripts/seedstore.mjs put <file> [--save <token file>] [--group <name>]
//   node scripts/seedstore.mjs get <token | token file> [--out <path>]
//   node scripts/seedstore.mjs ls
//   node scripts/seedstore.mjs where [<token | root>] [--live]
//   node scripts/seedstore.mjs holdings
//   node scripts/seedstore.mjs probe [<token | root>] [--watch <seconds>]
//
// The node it asks:
//   --dir <dir>   the node serving that directory (`seedkernel --dir <dir> --bundle
//                 seedstore.skb …`), through its control socket, which only the user it
//                 runs as can reach. It answers itself, so the flags below that boot a
//                 node are refused while it serves. If none serves it, a node booted here
//                 over that store.
//   --peers "pk[.secret]@host:port,…" [--relay ws://host:port]   a node booted here for
//                 the one command (over --dir's store, or in memory), linked to those
//                 peers as group --group (default cohort). Holders store for it only if
//                 their own groups list its key (§5.1).
//   --key <file>  a booted node's master seed, as seedkernel's --key (default
//                 ./seedkernel.key, created on first run), so a node booted over a
//                 directory is the one seedkernel would boot there.
//   A booted node's geometry: --k 1 --m 1 --block 256 (KiB).
//
// A token is `<root hex>:<key hex>` and reads the file back, so keep it private.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { loadCrypto } from "seedkernel-wasm";
import { nodeChannels, nodeDatagrams, nodeLocalChannels } from "seedkernel-wasm/shell-node";
import { controlInvoke, controlServes } from "seedkernel-wasm/control";
import { deriveNodeKey } from "seedkernel-wasm/subkeys";
import {
  StoreClient, encodeToken, decodeToken, defaultConfig, PRODUCTION_BLOCK_SIZE, STORAGE_APP, toHex, fromHex, netRoutes,
} from "../build/host/node.js";
import { bootNode, peerSpecs } from "./boot-node.mjs";

// ── args ─────────────────────────────────────────────────────────────────────
const words = [], args = new Map();
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (a.startsWith("--")) args.set(a.slice(2), process.argv[i + 1] && !process.argv[i + 1].startsWith("--") ? process.argv[++i] : "true");
  else words.push(a);
}
const [command, target] = words;
const COMMANDS = ["put", "get", "ls", "where", "holdings", "probe"];
if (!COMMANDS.includes(command) || (!args.has("dir") && !args.has("peers"))) {
  console.error(`usage: node scripts/seedstore.mjs <${COMMANDS.join("|")}> [<file | token>] (--dir <dir> | --peers "pk@host:port,…")`);
  process.exit(1);
}
const num = (k, d) => (args.has(k) ? Number(args.get(k)) : d);

// A token's text, from a file or as typed; its root alone also names a file.
const tokenText = (s) => (existsSync(s) ? readFileSync(s, "utf8").trim() : s.trim());
const rootOf = (s) => {
  if (!s) return undefined;
  const t = tokenText(s);
  return t.includes(":") ? decodeToken(t).root : fromHex(t);
};

// ── the node ─────────────────────────────────────────────────────────────────
/** The flags only a node booted here reads. */
const BOOT_FLAGS = ["peers", "relay", "key", "k", "m", "block", "timeout"];

/** The client, and how the node was reached. The node serving --dir when there is one, so
 *  two nodes never share a store. */
async function connect() {
  const dir = args.get("dir");
  if (dir) {
    const remote = { dir, local: nodeLocalChannels() };
    if (await controlServes(remote)) {
      const unread = BOOT_FLAGS.filter((f) => args.has(f));
      if (unread.length > 0) {
        throw new Error(`a node serves ${dir} and answers itself, reading no --${unread.join(", --")}: drop them, or stop that node`);
      }
      return {
        client: new StoreClient(async (frame) => {
          const r = await controlInvoke(remote, STORAGE_APP, frame);
          if (r === null) throw new Error(`the node serving ${dir} stopped`);
          return r;
        }),
        label: `the node serving ${dir}`,
      };
    }
  }
  const sodium = await loadCrypto();
  const keyPath = args.get("key") ?? "./seedkernel.key";
  if (!existsSync(keyPath)) writeFileSync(keyPath, toHex(sodium.randombytes_buf(32)), { mode: 0o600 });
  const seed = readFileSync(keyPath, "utf8").trim();
  if (!/^[0-9a-f]{64}$/i.test(seed)) throw new Error(`--key ${keyPath}: want a 32-byte master seed in hex, as seedkernel's --key`);
  const identity = deriveNodeKey(sodium, fromHex(seed.toLowerCase()));
  const relay = args.get("relay");
  const config = { ...defaultConfig(num("block", PRODUCTION_BLOCK_SIZE / 1024) * 1024, num("k", 1), num("m", 1)), maxMessageBytes: 512 * 1024 };
  const { node, runtime, peers, linked } = await bootNode({
    identity, sodium, dir, channels: nodeChannels(), ...(relay ? { datagrams: nodeDatagrams(), relay } : {}),
    timeoutMs: num("timeout", 5000), config, peers: peerSpecs(args.get("peers"), relay), group: args.get("group") ?? "cohort",
  });
  console.error(`node ${short(node.peerId)} booted here${dir ? ` over ${dir}` : ""}: ${linked.size}/${peers.length} peers linked` +
    (peers.length ? `  (holders must list ${node.peerId}, from ${keyPath})` : ""));
  return { client: node.client, label: `this node (${short(node.peerId)})`, routes: () => netRoutes(runtime.shell) };
}

// ── report ───────────────────────────────────────────────────────────────────
const MiB = 1024 * 1024;
const size = (n) => (n >= MiB ? (n / MiB).toFixed(1) + " MiB" : (n / 1024).toFixed(1) + " KiB");
const short = (hex) => hex.slice(0, 12) + "…";
const ratio = (c) => (c ? `${Math.round(c[0])}/${Math.round(c[0] + c[1])}` : "-");
const fileLine = (f) => `${short(f.id)}  ${size(f.bytes).padStart(10)}  ${f.chunks} chunks + ${f.index} index  group ${f.group}  k=${f.k} m=${f.m}`;

function probeReport(p, routes) {
  console.log(`members, asked about ${p.asked} block(s) at ${new Date().toLocaleTimeString()}`);
  for (const m of p.peers) {
    const state = !m.up ? "DOWN" : m.refused ? "up, refuses us (we are not in its groups)" : "up";
    const route = routes?.has(m.peer) ? (routes.get(m.peer) ? "direct" : "relayed") : "";
    console.log(`  ${short(m.peer)}  ${state.padEnd(4)}  ${route.padEnd(7)}` + (m.rtt === null ? "" : `  rtt ${m.rtt.toFixed(0).padStart(4)} ms`) +
      (m.up && !m.refused && p.asked > 0 ? `  has ${m.has}/${p.asked}` : ""));
  }
  for (const f of p.files) {
    console.log(`  file ${short(f.id)}: ${f.healthy} chunks at full redundancy, ${f.short} short, ${f.lost} unreadable from the members up now`);
  }
}

// ── commands ─────────────────────────────────────────────────────────────────
const { client, label, routes } = await connect();
console.error(`asking ${label}`);

if (command === "put") {
  if (!target) throw new Error("put: name the file");
  const r = await client.put(new Uint8Array(readFileSync(target)), args.has("group") ? { group: args.get("group") } : {});
  console.log(`put ${target}: ${r.chunkCount} chunks, ${r.replicasLanded}/${r.replicasIntended} replicas landed`);
  if (r.replicasLanded < r.replicasIntended) console.log("  UNDER-REPLICATED: a holder declined, or the group is smaller than k + m");
  const token = encodeToken(r);
  if (args.has("save")) {
    writeFileSync(args.get("save"), token + "\n", { mode: 0o600 });
    console.log(`  token saved to ${args.get("save")} — keep it private: it reads the file`);
  } else console.log(`  token ${token}`);
} else if (command === "get") {
  if (!target) throw new Error("get: give a token or a token file");
  const { root, key } = decodeToken(tokenText(target));
  const out = await client.get(root, key);
  if (args.has("out")) { writeFileSync(args.get("out"), out); console.error(`wrote ${out.length} B to ${args.get("out")}`); }
  else process.stdout.write(out);
} else if (command === "ls") {
  const files = await client.files();
  if (files.length === 0) console.log("no files of its own");
  for (const f of files) console.log(fileLine(f));
} else if (command === "where") {
  const files = await client.placement(rootOf(target));
  const live = args.has("live") ? await client.probe(rootOf(target)) : null;
  if (live) probeReport(live, await routes?.());
  if (files.length === 0) console.log("no files of its own");
  for (const f of files) {
    console.log(`\nfile ${fileLine(f)}`);
    console.log(`  ledger: ${f.healthy} chunks at full redundancy, ${f.short} short, ${f.unaudited} not audited yet`);
    for (const [p, s] of Object.entries(f.peers).sort((a, b) => b[1].holds - a[1].holds)) {
      console.log(`    ${short(p)}  holds ${s.holds}/${f.chunkHolders.length} chunks   reliability ${ratio(s.reliability)}` +
        `  availability ${ratio(s.availability)}${s.member ? "" : "  (not in the group)"}`);
    }
  }
} else if (command === "holdings") {
  const h = await client.holdings();
  console.log(`keeps ${size(h.used)} of ${size(h.quota)}, ${size(h.cache)} of it cache`);
  if (h.holds.length === 0) console.log("  nothing for others");
  for (const r of h.holds.sort((a, b) => b.bytes - a.bytes)) {
    console.log(`  for ${short(r.author)}  group ${r.group}  ${r.tier}: ${r.blocks} blocks, ${size(r.bytes)}` +
      `   (it keeps ${size(r.keepsForUs)} for us${r.allowance === undefined ? "" : `; allowance ${size(r.allowance)}`})`);
  }
  for (const k of h.keepsForUs.filter((k) => !h.holds.some((r) => r.author === k.peer && r.group === k.group))) {
    console.log(`  ${short(k.peer)}  group ${k.group} keeps ${size(k.bytes)} for us, we keep nothing for it`);
  }
} else if (command === "probe") {
  const watch = num("watch", 0) * 1000;
  for (;;) {
    const p = await client.probe(rootOf(target));
    if (watch) console.clear();
    probeReport(p, await routes?.());
    if (!watch) break;
    await new Promise((r) => setTimeout(r, watch));
  }
}
process.exit(0);

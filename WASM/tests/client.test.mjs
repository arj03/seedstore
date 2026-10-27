// The client surface (SPEC §18.1): the read-only ops answer from the guest's own state —
// its files, the ledger in memory, its store index, and a live HAVE to its roster — and
// the token carries a file between nodes.

import { loadSodium, loadWasmBytes, LoopbackNetwork, createConnectedCohort, toHex } from "../build/host/node.js";
import { encodeToken, decodeToken } from "../build/host/client.js";

export async function run(t) {
  const sodium = await loadSodium(), wasm = await loadWasmBytes();

  t.group("client: files, placement and holdings answer from the guest's own state");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 3, network: net, sodium, wasm,
      config: { k: 1, m: 1, blockSize: 1024 }, timeoutMs: 200 });
    const [a, b, c] = nodes;
    try {
      t.eq((await a.client.files()).length, 0, "a fresh node has no files");
      const r = await a.put(new Uint8Array(5000).fill(5));
      const [file] = await a.client.files();
      t.eq(file.root, toHex(r.root), "the file is listed by the root a GET starts from");
      t.eq([file.bytes, file.chunks, file.group, file.k, file.m], [5000, r.chunkCount, "cohort", 1, 1], "its size, chunks, group and geometry");

      const before = (await a.client.placement())[0];
      t.eq([before.healthy, before.unaudited], [0, file.chunks + file.index], "no chunk audited before a repair pass");
      t.ok(before.chunkHolders.every((ch) => ch.holders === null), "so no chunk has holders yet");

      await a.runRepair();
      const [after] = await a.client.placement(r.root);
      t.eq([after.healthy, after.short, after.unaudited], [file.chunks + file.index, 0, 0], "after a pass, every chunk at full redundancy by the ledger");
      t.eq(Object.keys(after.peers).sort().join(","), [b.peerId, c.peerId].sort().join(","), "every other member of the file's group is listed");
      t.ok(Object.values(after.peers).every((p) => p.member && p.holds === file.chunks + file.index && p.availability !== null),
        "each holding every chunk, with its availability seen");

      const held = await b.client.holdings();
      const row = held.holds.find((h) => h.author === a.peerId);
      t.ok(row && row.group === "cohort" && row.tier === "committed" && row.blocks === file.chunks + file.index,
        "b keeps one committed block per chunk for a");
      t.ok(row.allowance > 0 && held.used >= row.bytes && held.quota > 0, "with a's allowance and its own quota and use");
      const back = (await a.client.holdings()).keepsForUs.filter((k) => k.group === "cohort").map((k) => k.peer).sort();
      t.eq(back.join(","), [b.peerId, c.peerId].sort().join(","), "and a sees what b and c keep for it");

      let threw = false;
      try { await a.client.placement(new Uint8Array(200).fill(9)); } catch { threw = true; }
      t.ok(threw, "a root that is not one of the node's files is refused");
    } finally { nodes.forEach((n) => n.close()); net.close(); }
  }

  t.group("client: probe asks each member now, and tells up, refusing and down apart");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 4, network: net, sodium, wasm,
      config: { k: 1, m: 2, blockSize: 1024 }, timeoutMs: 200 });
    const [a, b, c, d] = nodes;
    try {
      const r = await a.put(new Uint8Array(3000).fill(6));
      const all = await a.client.probe();
      t.ok(all.asked > 0 && all.peers.every((p) => p.up && !p.refused && p.linked && p.has === all.asked),
        "every member up, each with every block (k = 1, three copies)");
      t.eq(all.files[0].healthy, all.files[0].chunks, "so every chunk is at full redundancy");

      await b.setGroups({ cohort: [b.peerId, c.peerId, d.peerId] }); // b no longer stores for a
      d.close();
      const now = await a.client.probe(r.root);
      const state = (id) => { const p = now.peers.find((x) => x.peer === id); return !p.up ? "down" : p.refused ? "refused" : "up"; };
      t.eq([b, c, d].map((n) => state(n.peerId)).join(","), "refused,up,down", "b refuses a non-member, c answers, d is down");
      const f = now.files[0];
      t.eq([f.healthy, f.short, f.lost], [0, f.chunks, 0], "one copy answering: every chunk short, none unreadable");
    } finally { nodes.forEach((n) => n.close()); net.close(); }
  }

  t.group("client: a token carries a file to another node of the group");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 3, network: net, sodium, wasm,
      config: { k: 1, m: 1, blockSize: 1024 }, timeoutMs: 200 });
    const [a, b] = nodes;
    try {
      const data = sodium.randombytes_buf(4000);
      const token = encodeToken(await a.client.put(data));
      t.ok(/^[0-9a-f]+:[0-9a-f]{64}$/.test(token), "the token is <root hex>:<key hex>");
      const { root, key } = decodeToken(token);
      const out = await b.client.get(root, key);
      t.ok(out.length === data.length && out.every((x, i) => x === data[i]), "b reads the file back from the token alone");
    } finally { nodes.forEach((n) => n.close()); net.close(); }
  }

  t.group("client: a later stream on a node replaces the earlier one, which fails rather than mix files");
  {
    const net = new LoopbackNetwork();
    const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 3, network: net, sodium, wasm,
      config: { k: 1, m: 1, blockSize: 1024 }, timeoutMs: 200 });
    const [a, b] = nodes;
    try {
      const files = [new Uint8Array(20000).fill(1), new Uint8Array(20000).fill(2)];
      const same = (out, i) => out.length === files[i].length && out.every((v, j) => v === files[i][j]);
      const refused = (s) => s.status === "rejected" && /is not open/.test(s.reason.message);
      // Two clients on one node, as two tools over its control endpoint are.
      const puts = await Promise.allSettled(files.map((f) => a.client.put(f)));
      const done = puts.findIndex((p) => p.status === "fulfilled");
      t.ok(done >= 0 && refused(puts[1 - done]), "of two overlapping puts one completes and the other is refused");
      t.ok(same(await b.client.get(puts[done].value.root, puts[done].value.key), done), "and the one that completed reads back as its own file");

      const tokens = [await a.put(files[0]), await a.put(files[1])];
      const gets = await Promise.allSettled(tokens.map((r) => b.client.get(r.root, r.key)));
      const read = gets.findIndex((g) => g.status === "fulfilled");
      t.ok(read >= 0 && refused(gets[1 - read]) && same(gets[read].value, read),
        "of two overlapping gets one reads its own file and the other is refused, never handed the other's bytes");
    } finally { nodes.forEach((n) => n.close()); net.close(); }
  }
}

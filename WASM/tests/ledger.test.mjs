// The ledger (SPEC §13): per (group, peer), reliability, availability and holdings, and what
// they drive — a chunk counts only its dependable copies (§8, §9), peers rank by
// reliability × availability, agreed repairs run most urgent first, and an author's
// allowance at a holder grows with what it verifiably holds for that holder (§13.2).

import { readFileSync } from "node:fs";
import vm from "node:vm";
import { Crypto } from "../build/host/crypto.js";
import { signDescriptor } from "../build/host/descriptor.js";
import { encodeStoreBatch, encodeFetchBatchRes, decodeMask, MsgType, VERDICT_ACCEPTED, VERDICT_ALLOWANCE } from "../build/host/protocol.js";
import { loadSodium, loadWasmBytes, LoopbackNetwork, createConnectedCohort } from "../build/host/node.js";
import { newKey } from "./helpers.mjs";

function typed(type, data) {
  const out = new Uint8Array(1 + data.length);
  out[0] = type; out.set(data, 1);
  return out;
}

export async function run(t) {
  const sodium = await loadSodium(), wasm = await loadWasmBytes();
  const crypto = new Crypto(sodium);

  t.group("ledger: a chunk counts only dependable copies, peers rank by reliability × availability, repairs run most urgent first");
  {
    // The production guest, its network stubbed: two live holders of a k = 1 chunk that
    // wants two copies, one of them a peer that is mostly offline.
    const author = newKey();
    const bytes = sodium.randombytes_buf(1024);
    const id = crypto.blockId(author.publicKey, bytes);
    const env = signDescriptor(sodium, { group: "g", level: 0, k: 1, m: 1, blockSize: 1024, tailBytes: 1024,
      authTag: new Uint8Array(16), blockIds: [id, id] }, author.publicKey, author.privateKey);
    const source = readFileSync(new URL("../build/host/tier2-guest.js", import.meta.url), "utf8");
    const ctx = vm.createContext({ APP: { k: 1, m: 1, blockSize: 1024, maxMessageBytes: 8192, fanoutWindow: 4,
      verifyFreshMs: 60000, verifyDeadlineMs: 2000, newcomerShare: 0.5 }, LOCAL: {}, Uint8Array, env, crypto,
      good: encodeFetchBatchRes([bytes]) });
    vm.runInContext(source, ctx);
    const r = await vm.runInContext(`(async () => {
      for (const name of ["auditChunk", "rank", "takeDueJob", "haveWant", "netSend", "verifyEnv", "myPeer", "repObserve", "blake2b"]) {
        if (typeof globalThis[name] !== "function") throw new Error("fault injection: the guest no longer defines " + name);
      }
      const steady = "01".repeat(32), flaky = "02".repeat(32);
      globalThis.myPeer = () => "self";
      globalThis.verifyEnv = async () => true;
      globalThis.blake2b = async (req) => crypto.hash(req.subarray(2));
      globalThis.repObserve = async () => {};
      globalThis.haveWant = async (ids) => new Map(ids.map((id) => [toHex(id), new Set([steady, flaky])]));
      globalThis.netSend = async () => good;
      const seen = (peer, present, absent) => availReps.set(repKey("g", peer), { serve: present, miss: absent, last: Date.now() });
      seen(steady, 10, 0);
      seen(flaky, 1, 9);
      const onFlaky = await auditChunk(env);
      seen(flaky, 9, 1);
      const onSteady = await auditChunk(env);
      seen(flaky, 1, 9);
      const ranked = await rank([flaky, steady], "g");
      repairJobs.push({ margin: 1, due: 0 }, { margin: -1, due: 0 }, { margin: 0, due: 0 });
      const order = [takeDueJob(Date.now()).margin, takeDueJob(Date.now()).margin, takeDueJob(Date.now()).margin];
      return { flakyShort: onFlaky !== null, flakyMargin: onFlaky && onFlaky.margin, steadyShort: onSteady !== null,
        ranked: ranked.map((p) => p === steady ? "steady" : "flaky"), order };
    })()`, ctx);
    t.ok(r.flakyShort, "two live copies, one on a mostly offline peer: the chunk is short and gets repaired early");
    t.eq(r.flakyMargin, 0, "its margin counts the dependable copy only");
    t.ok(!r.steadyShort, "once that peer is steady, the same two copies are healthy");
    t.eq(r.ranked.join(","), "steady,flaky", "a steady peer ranks before one that is often offline");
    t.eq(r.order.join(","), "-1,0,1", "agreed repairs run lowest margin first");
  }

  t.group("ledger: an author's allowance grows with what it verifiably holds for the holder (§13.2)");
  {
    // Each of b's blocks costs 1168 (1000 + 164 + 4) at a, whose newcomer share of a 4000-byte
    // quota is 2000: one block. Once a has audited its own file and seen b hold a 1024-byte
    // block of it, b may fill 2000 + 1024 there: two, with the quota still room for a third.
    const net = new LoopbackNetwork();
    const [a, b, c] = await createConnectedCohort({ suppressLinkLog: true, count: 3, network: net, sodium, wasm, quota: 4000,
      config: { k: 1, m: 1, blockSize: 1024 }, timeoutMs: 200 });
    try {
      const block = (seed) => new Uint8Array(1000).map((_, i) => (i * 7 + seed) & 255);
      const solo = (blockId) => signDescriptor(sodium, { group: "cohort", level: 0, k: 1, m: 0, blockSize: 1000, tailBytes: 1000,
        authTag: new Uint8Array(16), blockIds: [blockId] }, b.identity.publicKey, b.identity.privateKey);
      const store = async (seed) => {
        const bytes = block(seed), blockId = crypto.blockId(b.identity.publicKey, bytes);
        return decodeMask(await b.request(a.peerId, typed(MsgType.STORE, encodeStoreBatch([{ blockId, descriptor: solo(blockId), bytes }]))))[0];
      };
      t.eq(await store(1), VERDICT_ACCEPTED, "b's first block fits its newcomer share at a");
      t.eq(await store(2), VERDICT_ALLOWANCE, "its second does not, while b holds nothing for a");

      await a.put(new Uint8Array(1024).fill(9));    // k = 1, two copies: on b and c
      t.ok(b.store.list().length > 0, "b holds a block of a's file");
      await a.runRepair();                          // a audits its own file and sees b holding it
      t.eq(await store(2), VERDICT_ACCEPTED, "once a has seen b hold its data, b's allowance there grows by that much");
      t.eq(await store(3), VERDICT_ALLOWANCE, "and no further");
    } finally { [a, b, c].forEach((n) => n.close()); net.close(); }
  }

  t.group("ledger: reliability, availability, holdings and the audit cursor survive a restart (§13)");
  {
    // Boots of the production guest over one store: the first PUTs a file's descriptors as
    // its own, sees who holds them and writes the ledger as a pass ends; the next reads it
    // all back before anything else.
    const disk = new Map(), text = (b) => String.fromCharCode(...b);
    const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
    const host = {
      call: async (name, payload) => {
        if (name === "fs/put") {
          const n = new DataView(payload.buffer, payload.byteOffset).getUint32(0);
          disk.set(text(payload.subarray(4, 4 + n)), payload.slice(4 + n));
          return new Uint8Array(0);
        }
        if (name === "fs/get") {
          const v = disk.get(text(payload));
          if (!v) return Uint8Array.of(0);
          const out = new Uint8Array(1 + v.length); out[0] = 1; out.set(v, 1);
          return out;
        }
        if (name === "fs/list") {
          const parts = [u32(disk.size)];
          for (const key of disk.keys()) parts.push(u32(key.length), Uint8Array.from(key, (c) => c.charCodeAt(0)));
          const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
          let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
          return out;
        }
        throw new Error("unexpected host call " + name);
      },
    };
    const author = newKey();
    const envs = [1, 2, 3].map((seed) => {
      const id = crypto.blockId(author.publicKey, new Uint8Array(1024).fill(seed));
      return signDescriptor(sodium, { group: "g", level: 0, k: 1, m: 1, blockSize: 1024, tailBytes: 1024,
        authTag: new Uint8Array(16), blockIds: [id, id] }, author.publicKey, author.privateKey);
    });
    const source = readFileSync(new URL("../build/host/tier2-guest.js", import.meta.url), "utf8");
    const boot = () => {
      const ctx = vm.createContext({ APP: { k: 1, m: 1, blockSize: 1024, maxMessageBytes: 8192, fanoutWindow: 4,
        verifyFreshMs: 60000, verifyDeadlineMs: 30000, newcomerShare: 0.5 }, LOCAL: {}, Uint8Array, host, envs });
      vm.runInContext(source, ctx);
      vm.runInContext(`globalThis.myPeer = () => "0f".repeat(32);`, ctx);
      return ctx;
    };
    const names = ["ensureRestored", "saveLedger", "saveOwnFile", "recordHoldings", "heldFor", "availability", "repKey", "myPeer"];
    const check = `for (const name of ${JSON.stringify(names)}) {
      if (typeof globalThis[name] !== "function") throw new Error("fault injection: the guest no longer defines " + name);
    }`;
    // `live` for a k = 1 chunk: its one id, held by `peers`.
    const helpers = `const a = "01".repeat(32), b = "02".repeat(32);
      const held = (env, peers) => {
        const d = parseSignedDescriptor(env).descriptor;
        recordHoldings(chunkKey(env), d, new Map([[toHex(d.blockIds[0]), new Set(peers)]]));
      };`;
    await vm.runInContext(`(async () => {
      ${check}
      ${helpers}
      await ensureRestored(call);
      await saveOwnFile(envs[0], envs);
      const now = Date.now();
      peerReps.set(repKey("g", a), { serve: 3, miss: 1, last: now });
      availReps.set(repKey("g", a), { serve: 9, miss: 1, last: now });
      held(envs[0], [a, b]);
      held(envs[1], [a]);
      ownCursor = 2;
      await saveLedger();
    })()`, boot());
    const r = await vm.runInContext(`(async () => {
      ${check}
      ${helpers}
      await ensureRestored(call);
      const rel = peerReps.get(repKey("g", a));
      const out = { serve: rel && rel.serve, miss: rel && rel.miss, avail: availability("g", a),
        heldA: heldFor("g", a), heldB: heldFor("g", b), cursor: ownCursor, own: ownChunks.length };
      held(envs[0], [a]); // re-audited: b no longer holds it
      out.reauditA = heldFor("g", a);
      out.reauditB = heldFor("g", b);
      return out;
    })()`, boot());
    t.eq([r.serve, r.miss], [3, 1], "reliability is read back");
    t.ok(Math.abs(r.avail - 0.9) < 1e-9, "availability is read back");
    t.eq([r.heldA, r.heldB], [2048, 1024], "holdings are read back per chunk");
    t.eq(r.cursor, 2, "the own-audit cursor resumes where it was");
    t.eq(r.own, 3, "the file list is read back");
    t.eq([r.reauditA, r.reauditB], [2048, 0], "re-auditing a restored chunk replaces its holdings, never adds to them");

    for (const key of disk.keys()) if (key === "ledger" || key.startsWith("held.")) disk.set(key, Uint8Array.from("{torn", (c) => c.charCodeAt(0)));
    const torn = await vm.runInContext(`(async () => {
      ${helpers}
      await ensureRestored(call);
      return { reps: peerReps.size, avail: availReps.size, held: heldFor("g", a), own: ownChunks.length };
    })()`, boot());
    t.eq([torn.reps, torn.avail, torn.held], [0, 0, 0], "a torn ledger is read as none, as on a first boot");
    t.eq(torn.own, 3, "and the file list still loads");
  }
}

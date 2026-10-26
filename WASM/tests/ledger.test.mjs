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
}

import { readFileSync } from "node:fs";
import vm from "node:vm";
import { Crypto } from "../build/host/crypto.js";
import { signDescriptor, verifyDescriptor, parseSignedDescriptor } from "../build/host/descriptor.js";
import { encodeStoreBatch, encodeFetchBatchRes, MsgType, VERDICT_ACCEPTED } from "../build/host/protocol.js";
import { loadSodium, loadWasmBytes, LoopbackNetwork, createConnectedCohort } from "../build/host/node.js";
import { bytesEqual, writeU32BE } from "../build/host/util.js";
import { newKey } from "./helpers.mjs";
import { makeT } from "./harness.mjs";

function typed(type, payload) {
  const out = new Uint8Array(1 + payload.length);
  out[0] = type; out.set(payload, 1); return out;
}

export async function run(t) {
  const sodium = await loadSodium(), wasm = await loadWasmBytes();
  const crypto = new Crypto(sodium);
  const net = new LoopbackNetwork();
  const nodes = await createConnectedCohort({ suppressLinkLog: true, count: 3, network: net, sodium, wasm,
    config: { k: 1, m: 1, blockSize: 1024 }, timeoutMs: 200 });
  const [owner, attacker, holder] = nodes;
  const sign = (node, d) => signDescriptor(sodium, d, node.identity.publicKey, node.identity.privateKey, owner.signAuthor);
  try {
    t.group("security: a known peer cannot claim another author's block ids");
    const bytes = sodium.randombytes_buf(1024);
    const id = crypto.blockId(owner.identity.publicKey, bytes);
    const d = { level: 0, k: 1, m: 1, blockSize: 1024, tailBytes: 1024,
      authTag: new Uint8Array(16), blockIds: [id, id] };
    const legitimate = sign(owner, d);
    const forged = sign(attacker, { ...d, m: 0, blockIds: [id] });
    const store = async (descriptor, blockId = id) => (await attacker.request(holder.peerId,
      typed(MsgType.STORE, encodeStoreBatch([{ blockId, descriptor, bytes }]))))[0];
    t.ok(verifyDescriptor(sodium, forged, owner.signAuthor) !== null, "the attack carries a valid cohort signature");
    t.ok(await store(forged) !== VERDICT_ACCEPTED, "re-signed ciphertext is rejected even on a fresh holder");
    t.ok(!(await holder.store.has(id)), "the attack cannot squat on the original block id");
    t.eq(await store(legitimate), VERDICT_ACCEPTED, "a third-party repairer can relay the authentic descriptor");
    t.ok(await store(forged) !== VERDICT_ACCEPTED, "re-signing cannot replace an existing record either");
    t.ok(bytesEqual((await holder.store.get(id)).descriptor, legitimate), "the author's repair metadata stays intact");
    t.ok(!bytesEqual(id, crypto.blockId(attacker.identity.publicKey, bytes)), "identical ciphertext under another author has a different id");
    // The construction the binding replaces: a bare content hash names no author,
    // so it is not a block id whoever signs the descriptor around it.
    const unboundId = crypto.hash(bytes);
    t.ok(await store(sign(owner, { ...d, blockIds: [unboundId, unboundId] }), unboundId) !== VERDICT_ACCEPTED,
      "a bare content hash is not a block id");

    t.group("security: roots are authenticated before their size and shape are trusted");
    const plaintext = new Uint8Array([11, 22, 33, 44]);
    const put = await owner.put(plaintext);
    for (const field of ["tailBytes", "author", "signature"]) {
      const changed = put.root.slice();
      if (field === "tailBytes") writeU32BE(changed, 96 + 8, 1);
      else changed[field === "author" ? 0 : 32] ^= 1;
      let err = null;
      try { await owner.get(changed, put.key); } catch (e) { err = e; }
      t.ok(err && /root descriptor/.test(err.message), "tampered root " + field + " is rejected");
    }
    t.ok(bytesEqual(await owner.get(put.root, put.key), plaintext), "the authentic root still reads after rejected attempts");
  } finally { nodes.forEach(n => n.close()); net.close(); }

  t.group("security: malformed holder responses cannot abort GET or repair");
  // Run the built production guest with fault injection at its network boundary.
  // Actual parsing, peer fallback, block verification, decryption and repair run;
  // no invalid frame needs to pass through the encrypted transport to simulate a
  // malicious endpoint, which legitimately controls its own response plaintext.
  const author = newKey(), K = crypto.randomKey();
  const plaintext = sodium.randombytes_buf(1024);
  const sealed = crypto.encrypt(K, 0, 0, plaintext);
  const id = crypto.blockId(author.publicKey, sealed.ciphertext);
  const env = signDescriptor(sodium, { level: 0, k: 1, m: 2, blockSize: 1024, tailBytes: 1024,
    authTag: sealed.authTag, blockIds: [id, id, id] }, author.publicKey, author.privateKey, author.publicKey);
  const d = parseSignedDescriptor(env).descriptor;
  const good = encodeFetchBatchRes([sealed.ciphertext]);
  const badReplies = [
    new Uint8Array([0]),                         // truncated header
    new Uint8Array([0, 0, 0, 0]),               // wrong count
    new Uint8Array([0, 0, 0, 1, 99]),           // invalid status
    new Uint8Array([0, 0, 0, 1, 1, 0, 0, 4, 0]), // missing payload
    new Uint8Array([...good, 0]),               // trailing garbage
  ];
  const source = readFileSync(new URL("../build/host/tier2-guest.js", import.meta.url), "utf8");
  for (let i = 0; i < badReplies.length; i++) {
    const ctx = vm.createContext({ APP: { k: 1, m: 2, blockSize: 1024, maxMessageBytes: 8192, fanoutWindow: 4 }, LOCAL: {},
      Uint8Array, badReply: badReplies[i], good, d, env, K, crypto,
      verifySigned: bytes => verifyDescriptor(sodium, bytes, author.publicKey) !== null });
    vm.runInContext(source, ctx);
    const result = await vm.runInContext(`(async () => {
      // Every guest name this harness reaches into, checked up front: a rename in the
      // guest then says which symbol moved instead of failing somewhere downstream.
      const stub = (name, fn) => {
        if (typeof globalThis[name] !== "function") throw new Error("fault injection: the guest no longer defines " + name);
        globalThis[name] = fn;
      };
      for (const name of ["reconstructChunks", "repairChunk", "blockHash", "toHex", "bytesEqual",
                          "encodeFetchBatchRes", "decodeFetchBatchReq", "decodeFetchBatchRes"]) {
        if (typeof globalThis[name] !== "function") throw new Error("fault injection: the guest no longer defines " + name);
      }
      stub("hash", async b => crypto.hash(b));
      stub("decrypt", async (...args) => { const out = crypto.decrypt(...args); if (!out) throw new Error("authentication failed"); return out; });
      stub("verifyEnv", async bytes => verifySigned(bytes));
      stub("myPeer", async () => "self");
      stub("clockNow", async () => 0);
      const observations = [];
      stub("repObserve", async (peer, time, passes, misses) => observations.push({ passes, misses }));
      stub("makeRanker", async () => async peers => peers);
      const bad = "01".repeat(32), healthy = "02".repeat(32);
      stub("haveWant", async ids => new Map(ids.map(id => [toHex(id), new Set([bad, healthy])])));
      stub("netSendMany", async requests => requests.map(r => ({peer:r.peer, ok:true, bytes:r.peer === bad ? badReply : good})));
      const read = await reconstructChunks([d], K, 0);
      // Audit each distinct id once, matching a one-block replica's evidence.
      // liveHolders may query a replica id multiple times; answer the requested
      // count on the healthy side while keeping the adversary's malformed frame.
      stub("netSendMany", async requests => requests.map(r => ({peer:r.peer, ok:true,
        bytes:r.peer === bad ? badReply : encodeFetchBatchRes(decodeFetchBatchReq(r.payload).map(() => decodeFetchBatchRes(good)[0]))})));
      stub("placeChunksBatched", async jobs => {
        for (const job of jobs) {
          for (let j=0;j<job.slotIds.length;j++) {
            if (!bytesEqual(await blockHash(d, job.slotBlocks[j]), job.slotIds[j])) throw new Error("repair changed identity");
            job.placedPeer[j] = "fresh" + j;
          }
        }
      });
      const repaired = await repairChunk(env);
      return {read, repaired, misses:observations.reduce((n,o)=>n+o.misses,0)};
    })()`, ctx);
    t.ok(bytesEqual(result.read, plaintext), "malformed response " + i + ": GET retries a healthy holder");
    t.eq(result.repaired, 2, "malformed response " + i + ": repair restores missing replicas");
    t.ok(result.misses > 0, "malformed response " + i + ": the bad holder receives misses");
  }

  t.group("security: a FETCH cannot pull more out of a holder's store than one reply carries");
  {
    // A FETCH id costs 32 bytes to ask for and a whole block to look up, so an
    // unbounded read-ahead let one message pull far more off the store than any
    // reply can carry — and re-asking the unanswered tail paid it again per round.
    // serveFetch reads only as far as the cap, so ids it never reached answer
    // UNANSWERED (re-asked), exactly as a held-but-over-cap block does.
    const ctx = vm.createContext({ APP: { k: 1, m: 2, blockSize: 1024, maxMessageBytes: 4096, fanoutWindow: 4 }, LOCAL: {}, Uint8Array });
    vm.runInContext(source, ctx);
    const r = await vm.runInContext(`(async () => {
      for (const name of ["serveFetch", "storeGetBytes"]) {
        if (typeof globalThis[name] !== "function") throw new Error("fault injection: the guest no longer defines " + name);
      }
      const ids = (n) => Array.from({ length: n }, (_, i) => { const b = new Uint8Array(32); b[0] = i & 255; b[1] = (i >> 8) & 255; return b; });
      let reads = 0;
      const holding = async () => { reads++; return new Uint8Array(1024); };
      const missing = async () => { reads++; return null; };

      globalThis.storeGetBytes = holding;
      const held = await serveFetch(ids(64));            // 64 ids held, cap fits 3
      const heldReads = reads; reads = 0;

      globalThis.storeGetBytes = missing;
      const absent = await serveFetch(ids(1000));        // a miss costs no reply bytes, but still a read
      const missReads = reads; reads = 0;

      globalThis.storeGetBytes = holding;
      await serveFetch([ids(1)[0], ids(1)[0], ids(1)[0]]); // one id named three times
      return {
        served: held.filter((b) => b !== null && b !== FETCH_UNANSWERED).length,
        unanswered: held.filter((b) => b === FETCH_UNANSWERED).length,
        heldReads, missReads,
        missAbsent: absent.filter((b) => b === null).length,
        missUnanswered: absent.filter((b) => b === FETCH_UNANSWERED).length,
        repeatReads: reads,
      };
    })()`, ctx);
    t.eq(r.served, 3, "the reply is still filled to the cap (3 × 1024 B blocks under 4096)");
    t.eq(r.unanswered, 61, "every id past the cap is UNANSWERED, so the reader re-asks it");
    t.ok(r.heldReads <= r.served + 1, `reads are bounded by the reply, not the request (${r.heldReads} for 64 ids)`);
    t.ok(r.missReads < 1000 && r.missAbsent === r.missReads && r.missUnanswered === 1000 - r.missReads,
      `a request of misses is bounded too, and still resolves what it read (${r.missAbsent} ABSENT, ${r.missUnanswered} re-asked)`);
    t.ok(r.missAbsent > 0, "every request decides at least one id, so a re-ask always makes progress");
    t.eq(r.repeatReads, 1, "a repeated id is one store read");
  }
}

if (process.argv[1]?.endsWith("security.test.mjs")) {
  const t = makeT();
  await run(t);
  process.exitCode = t.summary() > 0 ? 1 : 0;
}

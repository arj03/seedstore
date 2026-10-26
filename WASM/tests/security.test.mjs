import { readFileSync } from "node:fs";
import vm from "node:vm";
import { Crypto } from "../build/host/crypto.js";
import { signDescriptor, verifyDescriptor, parseSignedDescriptor } from "../build/host/descriptor.js";
import { encodeStoreBatch, encodeFetchBatchRes, MsgType, VERDICT_ACCEPTED, VERDICT_NOT_AUTHOR } from "../build/host/protocol.js";
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
  const sign = (node, d) => signDescriptor(sodium, d, node.identity.publicKey, node.identity.privateKey);
  try {
    t.group("security: a known peer cannot claim another author's block ids");
    const bytes = sodium.randombytes_buf(1024);
    const id = crypto.blockId(owner.identity.publicKey, bytes);
    const d = { group: "cohort", level: 0, k: 1, m: 1, blockSize: 1024, tailBytes: 1024,
      authTag: new Uint8Array(16), blockIds: [id, id] };
    const legitimate = sign(owner, d);
    const forged = sign(attacker, { ...d, m: 0, blockIds: [id] });
    const store = async (descriptor, blockId = id) => (await attacker.request(holder.peerId,
      typed(MsgType.STORE, encodeStoreBatch([{ blockId, descriptor, bytes }]))))[0];
    t.ok(verifyDescriptor(sodium, forged) !== null, "the attack carries a valid cohort signature");
    t.ok(await store(forged) !== VERDICT_ACCEPTED, "re-signed ciphertext is rejected even on a fresh holder");
    t.ok(!holder.store.has(id), "the attack cannot squat on the original block id");
    t.eq(await store(legitimate), VERDICT_NOT_AUTHOR, "a third party cannot push even the author's authentic block: a repair is pulled (§9)");
    t.eq((await owner.request(holder.peerId, typed(MsgType.STORE, encodeStoreBatch([{ blockId: id, descriptor: legitimate, bytes }]))))[0],
      VERDICT_ACCEPTED, "the author places it");
    t.ok(await store(forged) !== VERDICT_ACCEPTED, "re-signing cannot replace an existing record either");
    t.ok(bytesEqual(holder.store.get(id).descriptor, legitimate), "the author's repair metadata stays intact");
    t.ok(!bytesEqual(id, crypto.blockId(attacker.identity.publicKey, bytes)), "identical ciphertext under another author has a different id");
    // Without the binding: a bare content hash names no author,
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
  const env = signDescriptor(sodium, { group: "cohort", level: 0, k: 1, m: 2, blockSize: 1024, tailBytes: 1024,
    authTag: sealed.authTag, blockIds: [id, id, id] }, author.publicKey, author.privateKey);
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
    const ctx = vm.createContext({ APP: { k: 1, m: 2, blockSize: 1024, maxMessageBytes: 8192, fanoutWindow: 4,
      verifyFreshMs: 60000, verifyDeadlineMs: 2000 }, LOCAL: {},
      Uint8Array, badReply: badReplies[i], good, d, env, K, crypto,
      verifySigned: bytes => verifyDescriptor(sodium, bytes) !== null });
    vm.runInContext(source, ctx);
    const result = await vm.runInContext(`(async () => {
      // Every guest name this harness reaches into, checked up front: a rename in the
      // guest then says which symbol moved instead of failing somewhere downstream.
      const stub = (name, fn) => {
        if (typeof globalThis[name] !== "function") throw new Error("fault injection: the guest no longer defines " + name);
        globalThis[name] = fn;
      };
      for (const name of ["reconstructChunks", "repairChunk", "groupPeers", "blockHash", "toHex", "bytesEqual",
                          "encodeFetchBatchRes", "decodeFetchBatchReq", "decodeFetchBatchRes"]) {
        if (typeof globalThis[name] !== "function") throw new Error("fault injection: the guest no longer defines " + name);
      }
      stub("blake2b", async req => crypto.hash(req.subarray(2)));
      stub("decrypt", async (K, level, index, parts, tag) => {
        const out = crypto.decrypt(K, level, index, concatBytes(parts), tag);
        if (!out) throw new Error("authentication failed");
        return out;
      });
      stub("verifyEnv", async bytes => verifySigned(bytes));
      stub("myPeer", () => "self");
      const observations = [];
      stub("repObserve", async (group, peer, time, passes, misses) => observations.push({ passes, misses }));
      stub("makeRanker", async () => async peers => peers);
      const bad = "01".repeat(32), healthy = "02".repeat(32);
      stub("haveWant", async ids => new Map(ids.map(id => [toHex(id), new Set([bad, healthy])])));
      stub("netSend", async peer => peer === bad ? badReply : good);
      const read = await reconstructChunks([d], K, 0);
      // Audit each distinct id once, matching a one-block replica's evidence.
      // liveHolders may query a replica id multiple times; answer the requested
      // count on the healthy side while keeping the adversary's malformed frame.
      // The audit's verification-fetches meet the malformed frame; two fresh members then
      // agree to repair the copies the chunk lacks.
      const asked = [];
      stub("groupPeers", async () => ["03".repeat(32), "04".repeat(32)]);
      stub("netSend", async (peer, type, payload) => {
        if (type === MsgType.REPAIR) { asked.push(peer); return new Uint8Array([1]); }
        return peer === bad ? badReply : encodeFetchBatchRes(decodeFetchBatchReq(payload).map(() => decodeFetchBatchRes(good)[0]));
      });
      const repaired = await repairChunk(env);
      if (asked.includes(bad) || asked.includes(healthy)) throw new Error("asked a current holder to repair");
      return {read, repaired, misses:observations.reduce((n,o)=>n+o.misses,0)};
    })()`, ctx);
    t.ok(bytesEqual(result.read, plaintext), "malformed response " + i + ": GET retries a healthy holder");
    t.eq(result.repaired, 2, "malformed response " + i + ": repair is asked for both missing replicas");
    t.ok(result.misses > 0, "malformed response " + i + ": the bad holder receives misses");
  }

  t.group("security: a holder that answers UNANSWERED forever cannot hang a GET (§18)");
  {
    // serveFetch always serves the first present block — an honest HOLDER's property, not
    // the wire's. A peer that tags EVERY id UNANSWERED decides nothing, and a reader that
    // took its word would re-ask forever. The reader instead rules a no-progress answer
    // absent (a §8 miss), so with every holder lying the GET must FAIL, on its own verdict.
    const ctx = vm.createContext({ APP: { k: 1, m: 2, blockSize: 1024, maxMessageBytes: 8192, fanoutWindow: 4 }, LOCAL: {},
      Uint8Array, d, K });
    vm.runInContext(source, ctx);
    const r = await vm.runInContext(`(async () => {
      for (const name of ["reconstructChunks", "netSend", "haveWant", "makeRanker", "myPeer", "repObserve"]) {
        if (typeof globalThis[name] !== "function") throw new Error("fault injection: the guest no longer defines " + name);
      }
      globalThis.myPeer = () => "self";
      globalThis.repObserve = async () => {};
      globalThis.makeRanker = async () => async (peers) => peers;
      const liars = ["01".repeat(32), "02".repeat(32)];
      globalThis.haveWant = async (ids) => new Map(ids.map((id) => [toHex(id), new Set(liars)]));
      // Bounded, so a regressed re-ask loop fails this test instead of hanging the suite.
      let asked = 0;
      globalThis.netSend = async (peer, type, payload) => {
        if (++asked > 100) throw new Error("re-asked the lying holders " + asked + " times");
        return encodeFetchBatchRes(decodeFetchBatchReq(payload).map(() => FETCH_UNANSWERED));
      };
      try { await reconstructChunks([d], K, 0); return { asked, err: null }; }
      catch (e) { return { asked, err: e.message }; }
    })()`, ctx);
    t.ok(r.err && /fewer than k blocks/.test(r.err), `the GET ends on its own §8 verdict (${r.err && r.err.slice(0, 70)})`);
    t.eq(r.asked, 2, "each lying holder is asked once, and its no-progress answer is final");
  }

  t.group("security: a verification-fetch answered past its deadline does not count the holder live (§8)");
  {
    // A holder regenerating a block on demand answers correct bytes, only slowly. The
    // audit does not count that holder as storing them.
    const ctx = vm.createContext({ APP: { k: 1, m: 2, blockSize: 1024, maxMessageBytes: 8192, fanoutWindow: 4,
      verifyFreshMs: 60000, verifyDeadlineMs: 50 }, LOCAL: {}, Uint8Array, d, good, crypto });
    vm.runInContext(source, ctx);
    const r = await vm.runInContext(`(async () => {
      for (const name of ["liveHolders", "netSend", "haveWant", "myPeer", "repObserve", "blake2b"]) {
        if (typeof globalThis[name] !== "function") throw new Error("fault injection: the guest no longer defines " + name);
      }
      globalThis.myPeer = () => "self";
      const misses = [];
      globalThis.repObserve = async (group, peer, time, passes, missed) => { if (missed) misses.push(toHex(peer)); };
      globalThis.blake2b = async (req) => crypto.hash(req.subarray(2));
      const slow = "01".repeat(32), fast = "02".repeat(32);
      globalThis.haveWant = async (ids) => new Map(ids.map((id) => [toHex(id), new Set([slow, fast])]));
      globalThis.netSend = async (peer, type, payload, answerBytes, timing) => {
        if (timing) timing.ms = peer === slow ? 5000 : 1;
        return good;
      };
      const live = await liveHolders(d);
      const h = toHex(d.blockIds[0]);
      return { slowLive: live.get(h).has(slow), fastLive: live.get(h).has(fast), misses };
    })()`, ctx);
    t.ok(r.fastLive, "the holder that answered in time is live");
    t.ok(!r.slowLive, "the holder that answered late is not counted as holding the block");
    t.eq(r.misses.length, 1, "the late answer is scored as a miss");
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

  t.group("security: a member cannot hold off a chunk's repair by claiming it (§9, §10)");
  {
    // The production guest with its store and network stubbed. This node holds one copy of a
    // k = 1 chunk that wants two. "member" and "helper" share the chunk's group; "outsider"
    // shares only another group with this node. Any of them can send a REPAIR_FETCH.
    const author = newKey();
    const signed = (blockIds) => signDescriptor(sodium, { group: "g", level: 0, k: 1, m: 1, blockSize: 1024,
      tailBytes: 1024, authTag: new Uint8Array(16), blockIds }, author.publicKey, author.privateKey);
    const id = crypto.blockId(author.publicKey, sodium.randombytes_buf(1024));
    const otherId = crypto.blockId(author.publicKey, sodium.randombytes_buf(1024));
    const env = signed([id, id]), other = signed([otherId, otherId]);
    const source = readFileSync(new URL("../build/host/tier2-guest.js", import.meta.url), "utf8");
    const ctx = vm.createContext({ APP: { k: 1, m: 1, blockSize: 1024, maxMessageBytes: 8192, fanoutWindow: 4,
      verifyFreshMs: 60000, verifyDeadlineMs: 2000, newcomerShare: 0.5 }, LOCAL: {}, Uint8Array,
      env, other, id, d: parseSignedDescriptor(env).descriptor });
    vm.runInContext(source, ctx);
    const r = await vm.runInContext(`(async () => {
      for (const name of ["hintFromRepairFetch", "isRepairing", "requestRepairs", "auditChunk", "chunkKey", "setRoster",
                          "storeGetDescriptor", "groupPeers", "rank", "netSend", "liveHolders", "verifyEnv", "myPeer"]) {
        if (typeof globalThis[name] !== "function") throw new Error("fault injection: the guest no longer defines " + name);
      }
      let now = 1000000;
      Date.now = () => now;
      const self = "0f".repeat(32), member = "01".repeat(32), outsider = "02".repeat(32), helper = "03".repeat(32);
      globalThis.myPeer = () => self;
      globalThis.verifyEnv = async () => true;
      setRoster(new Map([["g", new Set([member, helper])], ["other", new Set([outsider])]]));
      heldBlocks = new Map([[toHex(id), { size: 1200, author: "aa".repeat(32), group: "g", cache: false }]]);
      bytesUsed = 1200;
      storeIndexDirty = false;
      globalThis.storeGetDescriptor = async () => env;
      globalThis.groupPeers = async () => [helper];
      globalThis.rank = async (peers) => peers;
      const asked = [];
      globalThis.netSend = async (peer, type) => {
        if (type === MsgType.REPAIR) asked.push(peer);
        return new Uint8Array([VERDICT_ACCEPTED]);
      };
      const key = chunkKey(env), h = toHex(id);
      const ask = () => requestRepairs(d, env, new Map([[h, new Set([self])]]), 0); // one copy of two: short
      const out = {};
      await hintFromRepairFetch(fromHex(outsider), key, [id]);
      out.outsider = isRepairing(key, now);
      await hintFromRepairFetch(fromHex(member), chunkKey(other), [id]);
      out.wrongKey = isRepairing(chunkKey(other), now) || isRepairing(key, now);
      await hintFromRepairFetch(fromHex(member), key, [id]);
      out.member = isRepairing(key, now);
      out.deferred = await ask();
      now += REPAIR_NOTE_MS - 1000;
      await hintFromRepairFetch(fromHex(member), key, [id]); // a fresh claim, just before the window ends
      now += 2000;
      out.capped = !isRepairing(key, now);
      out.askedAfter = await ask();
      out.asked = asked.slice();
      // Asking noted this node's own request. Once that lapses and an audit finds the chunk
      // healthy, the next shortfall may be deferred again.
      now += REPAIR_NOTE_MS + 1;
      globalThis.liveHolders = async () => new Map([[h, new Set([self, helper])]]);
      out.healthy = (await auditChunk(env)) === null;
      await hintFromRepairFetch(fromHex(member), key, [id]);
      out.again = isRepairing(key, now);
      return out;
    })()`, ctx);
    t.ok(!r.outsider, "a REPAIR_FETCH from outside the chunk's group defers nothing");
    t.ok(!r.wrongKey, "nor one whose key is not the chunk of the block it names");
    t.ok(r.member, "a member fetching one of the chunk's blocks defers this holder's own request");
    t.eq(r.deferred, 0, "while that lasts, the holder asks nobody to repair the chunk");
    t.ok(r.capped, "a fresh claim does not extend the deferral past one window from the first");
    t.eq(r.askedAfter, 1, "after that window the holder asks for the repair itself");
    t.eq(r.asked.join(","), "03".repeat(32), "and asks a member that holds none of the chunk");
    t.ok(r.healthy, "an audit that finds the chunk healthy clears the spent deferral");
    t.ok(r.again, "so the next shortfall may be deferred again");
  }
}

if (process.argv[1]?.endsWith("security.test.mjs")) {
  const t = makeT();
  await run(t);
  process.exitCode = t.summary() > 0 ? 1 : 0;
}

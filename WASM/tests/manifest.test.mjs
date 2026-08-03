// CodecClient (host-owned codec) + chunk-descriptor layout (§4.3) tests.

import { readFileSync } from "node:fs";

import { Crypto } from "../build/host/crypto.js";
import { CodecClient } from "./codec-client.mjs";
import {
  encodeDescriptorCore, decodeDescriptorCore,
  signDescriptor, verifyDescriptor, descriptorContains,
  copyTargets, lossMargin, lowWaterMargin,
  encodeDescriptorList, decodeDescriptorList,
  storageSignScope,
} from "../build/host/manifest.js";
import { bytesEqual } from "../build/host/util.js";

import { ensureSodium, newKey, paths } from "./helpers.mjs";

export async function run(t) {
  const sodium = await ensureSodium();
  const crypto = new Crypto(sodium);
  const codec = await CodecClient.load(new Uint8Array(readFileSync(paths.codec)));

  t.group("CodecClient: info + RS round trip");
  {
    const info = codec.info();
    t.eq(info.version, 1, "codec version 1");

    const k = 4, m = 2, bs = 64;
    const data = [];
    for (let i = 0; i < k; i++) data.push(sodium.randombytes_buf(bs));
    const parity = codec.rsEncode(k, m, bs, data);
    t.eq(parity.length, m, "got m parity blocks");
    // Drop two data blocks; recover from the rest.
    const all = [...data, ...parity];
    const present = [1, 3, 4, 5].map((index) => ({ index, bytes: all[index] }));
    const recovered = codec.rsDecode(k, m, bs, present);
    t.ok(recovered.every((b, i) => bytesEqual(b, data[i])), "rsDecode recovers original data blocks");
  }

  t.group("descriptor: encode/decode round trip (§4.3)");
  {
    const ids = [];
    for (let i = 0; i < 6; i++) ids.push(crypto.hash(new Uint8Array([i])));
    const d = { level: 0, k: 4, m: 2, blockSize: 1024, tailBytes: 4000, blockIds: ids };
    const core = encodeDescriptorCore(d);
    const back = decodeDescriptorCore(core);
    t.eq(back.k, 4, "k preserved");
    t.eq(back.m, 2, "m preserved");
    t.eq(back.blockSize, 1024, "blockSize preserved");
    t.eq(back.level, 0, "level preserved");
    t.eq(back.tailBytes, 4000, "tailBytes preserved");
    t.ok(back.blockIds.every((id, i) => bytesEqual(id, ids[i])), "block ids preserved");
    t.ok(descriptorContains(back, ids[3]), "descriptorContains finds a listed id");
    t.ok(!descriptorContains(back, crypto.hash(new Uint8Array([99]))), "rejects a non-listed id");
  }

  t.group("descriptor: one chunk shape — multiplicity carries the replica count (§4.1, §8)");
  {
    const id = (i) => crypto.hash(new Uint8Array([i]));
    const ids = (n, base = 0) => Array.from({ length: n }, (_, i) => id(base + i));

    // n = k + m for BOTH. A coded chunk lists k+m distinct blocks; a k=1 chunk lists its
    // lone block m+1 times, and that repetition IS its replica count — no second shape.
    const coded = { level: 0, k: 10, m: 6, blockSize: 4096, tailBytes: 40960, blockIds: ids(16) };
    const one = id(100);
    const repl = { level: 0, k: 1, m: 6, blockSize: 4096, tailBytes: 4096, blockIds: new Array(7).fill(one) };
    t.eq(coded.blockIds.length, coded.k + coded.m, "coded: n = k+m");
    t.eq(repl.blockIds.length, repl.k + repl.m, "k=1: n = k+m too, by repeating the id");
    t.eq(copyTargets(coded).size, 16, "a coded chunk has 16 distinct blocks");
    t.eq([...copyTargets(coded).values()].every((v) => v === 1), true, "each wants one holder — parity is its redundancy");
    t.eq(copyTargets(repl).size, 1, "a k=1 chunk has one distinct block");
    t.eq([...copyTargets(repl).values()][0], 7, "…which wants r = m+1 = 7 holders");

    // The placement slots are simply the listed ids, so there is no slot table at all.
    t.eq(coded.blockIds.length, 16, "a coded chunk has k+m placement slots");
    t.eq(repl.blockIds.length, 7, "a k=1 chunk has r slots for its one block");

    // A k=1 descriptor survives its round trip with m intact — the whole point: it is
    // not flattened to m = 0 the way "no parity" would suggest.
    const back = decodeDescriptorCore(encodeDescriptorCore(repl));
    t.eq(back.m, 6, "a k=1 descriptor records m, not 0");
    t.eq(back.blockIds.length, 7, "and still lists its block m+1 times after the round trip");

    // Health is one number and now one FORMULA, full at m and low-water at ceil(m/2).
    t.eq(lowWaterMargin(coded), 3, "low-water is ceil(m/2), from the descriptor alone");
    t.eq(lowWaterMargin(repl), 3, "the same mark for a k=1 chunk of the same m");
    t.eq(lossMargin(coded, new Array(16).fill(1)), 6, "a fully-live coded chunk has margin m");
    t.eq(lossMargin(repl, new Array(7).fill(7)), 6, "a fully-replicated chunk has margin m too — NOT permanently below low-water");
    t.eq(lossMargin(coded, [0, 0, 0, ...new Array(13).fill(1)]), 3, "three blocks lost -> margin m-3");
    t.eq(lossMargin(repl, new Array(7).fill(4)), 3, "three copies lost -> the same margin, so the same repair decision");
    t.eq(lossMargin(coded, new Array(10).fill(1).concat(new Array(6).fill(0))), 0, "k live blocks -> one loss from death");
    t.eq(lossMargin(repl, new Array(7).fill(1)), 0, "one copy left -> one loss from death");

    // The case that makes min(live, multiplicity) load-bearing: an OVER-replicated block
    // must not inflate the margin past what its descriptor asked for.
    t.eq(lossMargin(coded, new Array(16).fill(9)), 6, "an over-replicated coded block is still worth one");
    t.eq(lossMargin(repl, new Array(7).fill(99)), 6, "an over-replicated k=1 chunk caps at m too");

    // n must be exactly k+m now — there is no second accepted id count.
    let threw = false;
    try { encodeDescriptorCore({ level: 0, k: 1, m: 6, blockSize: 4096, tailBytes: 1, blockIds: ids(1, 200) }); } catch { threw = true; }
    t.ok(threw, "a k=1 descriptor listing its id ONCE is rejected — n must be k+m");
    threw = false;
    try { encodeDescriptorCore({ level: 0, k: 10, m: 6, blockSize: 4096, tailBytes: 1, blockIds: ids(12) }); } catch { threw = true; }
    t.ok(threw, "an id count that is not k+m is rejected");
    threw = false;
    try { encodeDescriptorCore({ level: 0, k: 2, m: 2, blockSize: 256, tailBytes: 999, blockIds: ids(4, 300) }); } catch { threw = true; }
    t.ok(threw, "tailBytes past k*blockSize is rejected");
  }

  t.group("descriptor: author signature, tamper-evident (§4.3, §9)");
  {
    const author = newKey();
    const holder = newKey(); // a malicious holder
    const authorScope = storageSignScope(author.publicKey);
    const holderScope = storageSignScope(holder.publicKey);
    const ids = [];
    for (let i = 0; i < 4; i++) ids.push(crypto.hash(new Uint8Array([i + 10])));
    const d = { level: 0, k: 2, m: 2, blockSize: 256, tailBytes: 512, blockIds: ids };
    const env = signDescriptor(sodium, d, author.publicKey, author.privateKey, authorScope);

    const ok = verifyDescriptor(sodium, env, authorScope);
    t.ok(ok !== null, "valid descriptor verifies");
    t.ok(ok && bytesEqual(ok.authorPk, author.publicKey), "author pubkey recovered");

    // A holder alters a block id to misdirect repair → signature breaks.
    const tampered = env.slice();
    tampered[96 + 8] ^= 0xff; // flip a byte inside the first block id of core
    t.ok(verifyDescriptor(sodium, tampered, authorScope) === null, "tampered descriptor rejected");

    // A holder re-signs with its own key → authority is bound to the author,
    // so a repairer keyed to the author's pubkey would not accept holder's key.
    const forged = signDescriptor(sodium, d, holder.publicKey, holder.privateKey, holderScope);
    const fv = verifyDescriptor(sodium, forged, holderScope);
    t.ok(fv !== null && !bytesEqual(fv.authorPk, author.publicKey), "holder re-sign is detectable (different author)");

    // The signature is bound to its signing scope (§16): the same author + core signed
    // under a different scope does not verify under the original one — a storage signature
    // cannot be replayed into another deployment's (author, app) namespace.
    const otherScope = storageSignScope(holder.publicKey);
    const scoped = signDescriptor(sodium, d, author.publicKey, author.privateKey, otherScope);
    t.ok(verifyDescriptor(sodium, scoped, authorScope) === null, "a descriptor signed under a different scope is rejected");
    t.ok(verifyDescriptor(sodium, scoped, otherScope) !== null, "…but verifies under its own scope");
  }

  t.group("index list: encode/decode + encrypt round trip (§4.3, §4.4)");
  {
    const author = newKey();
    const authorScope = storageSignScope(author.publicKey);
    const envs = [0, 1].map((c) => {
      const ids = [];
      for (let i = 0; i < 4; i++) ids.push(crypto.hash(new Uint8Array([c, i])));
      return signDescriptor(sodium, { level: 0, k: 2, m: 2, blockSize: 512, tailBytes: 1024, blockIds: ids },
        author.publicKey, author.privateKey, authorScope);
    });
    // An index level is JUST the ordered signed descriptors — no header, no file_size, no
    // enc alg, no version. Every one of those either moved into the descriptor (tailBytes,
    // the format tag) or was redundant.
    const plain = encodeDescriptorList(envs);
    const back = decodeDescriptorList(plain);
    t.eq(back.length, 2, "two chunk descriptors");
    t.ok(back.every((e, i) => bytesEqual(e, envs[i])), "descriptor envelopes preserved");
    t.eq(plain.length, envs.reduce((n, e) => n + 4 + e.length, 0), "the list is exactly its length-prefixed entries");

    // The level goes through the SAME encrypt + content-address path a file chunk takes:
    // its nonce domain is the level (1 here), never a manifest domain.
    const K = crypto.randomKey();
    const ct = crypto.encrypt(K, 1 /* level 1 = the first index level */, 0, plain);
    t.eq(ct.length, plain.length, "index ciphertext is length-preserving");
    const reread = decodeDescriptorList(crypto.decrypt(K, 1, 0, ct));
    t.eq(reread.length, 2, "index decrypts and reparses");
    t.ok(bytesEqual(crypto.hash(ct), crypto.hash(ct)), "block_id = content_hash(ciphertext) is stable");

    // A truncated entry is a decode error, not a silently short list.
    let threw = false;
    try { decodeDescriptorList(plain.subarray(0, plain.length - 3)); } catch { threw = true; }
    t.ok(threw, "a truncated index entry is rejected");
  }
}

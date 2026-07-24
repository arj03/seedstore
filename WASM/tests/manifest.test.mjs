// CodecClient (host-owned codec) + manifest/descriptor layout (§4.3) tests.

import { readFileSync } from "node:fs";

import { Crypto } from "../build/host/crypto.js";
import { CodecClient } from "./codec-client.mjs";
import {
  encodeDescriptorCore, decodeDescriptorCore,
  signDescriptor, verifyDescriptor, descriptorContains,
  isReplicated, replicaTarget, slotIndices, lossMargin, lowWaterMargin,
  encodeManifest, decodeManifest, ENC_XCHACHA20,
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
    const d = { k: 4, m: 2, blockSize: 1024, blockIds: ids };
    const core = encodeDescriptorCore(d);
    const back = decodeDescriptorCore(core);
    t.eq(back.k, 4, "k preserved");
    t.eq(back.m, 2, "m preserved");
    t.eq(back.blockSize, 1024, "blockSize preserved");
    t.ok(back.blockIds.every((id, i) => bytesEqual(id, ids[i])), "block ids preserved");
    t.ok(descriptorContains(back, ids[3]), "descriptorContains finds a listed id");
    t.ok(!descriptorContains(back, crypto.hash(new Uint8Array([99]))), "rejects a non-listed id");
  }

  t.group("descriptor: coded and replicated are one model — m means 'survives m losses' (§4.1, §8)");
  {
    const id = (i) => crypto.hash(new Uint8Array([i]));
    const ids = (n, base = 0) => Array.from({ length: n }, (_, i) => id(base + i));

    // Production geometry, both shapes. k+m ids means coded (one block per peer),
    // k=1 ids means replicated (the lone block on r = m+1 peers).
    const coded = { k: 10, m: 6, blockSize: 4096, blockIds: ids(16) };
    const repl = { k: 1, m: 6, blockSize: 4096, blockIds: ids(1, 100) };
    t.ok(!isReplicated(coded), "16 = k+m ids → coded");
    t.ok(isReplicated(repl), "1 = k id → replicated");
    t.eq(replicaTarget(coded), 1, "a coded block wants one holder — parity is its redundancy");
    t.eq(replicaTarget(repl), 7, "a replicated block wants r = m+1 = 7 holders");
    t.eq(slotIndices(coded).length, 16, "a coded chunk has k+m placement slots");
    t.eq(slotIndices(repl).length, 7, "a replicated chunk has r slots for its one block");

    // A replicated descriptor survives its round trip with m intact — the whole point:
    // it is not flattened to m = 0 the way "no parity" would suggest.
    const back = decodeDescriptorCore(encodeDescriptorCore(repl));
    t.eq(back.m, 6, "a replicated descriptor records m, not 0");
    t.ok(isReplicated(back), "and still reads as replicated after the round trip");

    // Health is one number for both: the loss margin, full at m and low-water at ⌈m/2⌉.
    t.eq(lowWaterMargin(coded), 3, "low-water is ceil(m/2), from the descriptor alone");
    t.eq(lowWaterMargin(repl), 3, "the same mark for a replicated chunk of the same m");
    t.eq(lossMargin(coded, new Array(16).fill(1)), 6, "a fully-live coded chunk has margin m");
    t.eq(lossMargin(repl, [7]), 6, "a fully-replicated chunk has margin m too — NOT permanently below low-water");
    t.eq(lossMargin(coded, [0, 0, 0, ...new Array(13).fill(1)]), 3, "three blocks lost → margin m−3");
    t.eq(lossMargin(repl, [4]), 3, "three copies lost → the same margin, so the same repair decision");
    t.eq(lossMargin(coded, new Array(10).fill(1).concat(new Array(6).fill(0))), 0, "k live blocks → one loss from death");
    t.eq(lossMargin(repl, [1]), 0, "one copy left → one loss from death");

    // Replicated at k > 1 is rejected: RS(d, m) strictly dominates for d ≥ 2, so the
    // descriptor format only accepts the replicated shape at k = 1.
    let threw = false;
    try { encodeDescriptorCore({ k: 2, m: 2, blockSize: 256, blockIds: ids(2, 200) }); } catch { threw = true; }
    t.ok(threw, "replicated at k=2 is rejected — the shape does not exist");

    // An id count that is neither k+m nor k=1 (replicated) is malformed.
    threw = false;
    try { encodeDescriptorCore({ k: 10, m: 6, blockSize: 4096, blockIds: ids(12) }); } catch { threw = true; }
    t.ok(threw, "an id count that is neither k+m nor k=1 (replicated) is rejected");
  }

  t.group("descriptor: author signature, tamper-evident (§4.3, §9)");
  {
    const author = newKey();
    const holder = newKey(); // a malicious holder
    const authorScope = storageSignScope(author.publicKey);
    const holderScope = storageSignScope(holder.publicKey);
    const ids = [];
    for (let i = 0; i < 4; i++) ids.push(crypto.hash(new Uint8Array([i + 10])));
    const d = { k: 2, m: 2, blockSize: 256, blockIds: ids };
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

  t.group("manifest: encode/decode + encrypt round trip (§4.3, §4.4)");
  {
    const author = newKey();
    const authorScope = storageSignScope(author.publicKey);
    const envs = [0, 1].map((c) => {
      const ids = [];
      for (let i = 0; i < 4; i++) ids.push(crypto.hash(new Uint8Array([c, i])));
      return signDescriptor(sodium, { k: 2, m: 2, blockSize: 512, blockIds: ids }, author.publicKey, author.privateKey, authorScope);
    });
    // The manifest header carries no (k, m, blockSize): geometry is the descriptor's,
    // self-describing (§4.1/§4.3). Only genuinely per-file metadata travels here.
    const man = { fileSize: 12345, encAlg: ENC_XCHACHA20, chunks: envs };
    const plain = encodeManifest(man);
    const back = decodeManifest(plain);
    t.eq(back.fileSize, 12345, "file size preserved");
    t.eq(back.encAlg, ENC_XCHACHA20, "enc alg preserved");
    t.eq(back.chunks.length, 2, "two chunk descriptors");
    t.ok(back.chunks.every((e, i) => bytesEqual(e, envs[i])), "descriptor envelopes preserved");

    // Encrypt under K, replicate as a content-addressed block, read back.
    const K = crypto.randomKey();
    const ct = crypto.encrypt(K, 0 /* DOMAIN_MANIFEST */, 0, plain);
    const manifestId = crypto.hash(ct);
    t.eq(ct.length, plain.length, "manifest ciphertext is length-preserving");
    const dec = crypto.decrypt(K, 0, 0, ct);
    const reread = decodeManifest(dec);
    t.eq(reread.chunks.length, 2, "manifest decrypts and reparses");
    t.ok(bytesEqual(crypto.hash(ct), manifestId), "manifest_id = genesis_hash(ciphertext) is stable");
  }
}

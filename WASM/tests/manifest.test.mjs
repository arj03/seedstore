// CodecClient (host-owned codec) + manifest/descriptor layout (§4.3) tests.

import { readFileSync } from "node:fs";

import { Crypto } from "../build/host/crypto.js";
import { CodecClient } from "./codec-client.mjs";
import { storageNames } from "../build/host/names.js";
import {
  encodeDescriptorCore, decodeDescriptorCore,
  signDescriptor, verifyDescriptor, descriptorContains,
  encodeManifest, decodeManifest, ENC_XCHACHA20,
} from "../build/host/manifest.js";
import { bytesEqual } from "../build/host/util.js";

import { ensureSodium, newKey, paths, loadHost } from "./helpers.mjs";

export async function run(t) {
  const sodium = await ensureSodium();
  const crypto = new Crypto(sodium);
  // Names need a deriver; reuse a host to derive the crypto.hash name.
  const { host } = await loadHost();
  const names = storageNames(host);
  const codec = await CodecClient.load(new Uint8Array(readFileSync(paths.codec)), crypto, names.cryptoHash);

  t.group("CodecClient: info + RS round trip matches host crypto ids");
  {
    const info = codec.info();
    t.eq(info.version, 1, "codec version 1");
    t.ok(bytesEqual(codec.blockId(new TextEncoder().encode("x")), crypto.hash(new TextEncoder().encode("x"))),
      "codec block-id == crypto.hash");

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

  t.group("descriptor: author signature, tamper-evident (§4.3, §9)");
  {
    const author = newKey();
    const holder = newKey(); // a malicious holder
    const ids = [];
    for (let i = 0; i < 4; i++) ids.push(crypto.hash(new Uint8Array([i + 10])));
    const d = { k: 2, m: 2, blockSize: 256, blockIds: ids };
    const env = signDescriptor(sodium, d, author.publicKey, author.privateKey);

    const ok = verifyDescriptor(sodium, env);
    t.ok(ok !== null, "valid descriptor verifies");
    t.ok(ok && bytesEqual(ok.authorPk, author.publicKey), "author pubkey recovered");

    // A holder alters a block id to misdirect repair → signature breaks.
    const tampered = env.slice();
    tampered[96 + 8] ^= 0xff; // flip a byte inside the first block id of core
    t.ok(verifyDescriptor(sodium, tampered) === null, "tampered descriptor rejected");

    // A holder re-signs with its own key → authority is bound to the author,
    // so a repairer keyed to the author's pubkey would not accept holder's key.
    const forged = signDescriptor(sodium, d, holder.publicKey, holder.privateKey);
    const fv = verifyDescriptor(sodium, forged);
    t.ok(fv !== null && !bytesEqual(fv.authorPk, author.publicKey), "holder re-sign is detectable (different author)");
  }

  t.group("manifest: encode/decode + encrypt round trip (§4.3, §4.4)");
  {
    const author = newKey();
    const envs = [0, 1].map((c) => {
      const ids = [];
      for (let i = 0; i < 4; i++) ids.push(crypto.hash(new Uint8Array([c, i])));
      return signDescriptor(sodium, { k: 2, m: 2, blockSize: 512, blockIds: ids }, author.publicKey, author.privateKey);
    });
    const man = { fileSize: 12345, blockSize: 512, k: 2, m: 2, encAlg: ENC_XCHACHA20, chunks: envs };
    const plain = encodeManifest(man);
    const back = decodeManifest(plain);
    t.eq(back.fileSize, 12345, "file size preserved");
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

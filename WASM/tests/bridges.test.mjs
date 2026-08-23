// Storage host-service tests: the crypto primitives (§16). There are no
// storage-specific kernel services — the guest reaches crypto/fs/clock/module
// through the seam's generic names. store.local is not
// tested here: the host only has a read view (net.test.mjs); admission/quota
// policy is the confined holder's, covered in protocol.test.mjs.

import { Crypto, LEVEL_BODY } from "../build/host/crypto.js";
import { bytesEqual } from "../build/host/util.js";

import { ensureSodium, newKey } from "./helpers.mjs";

export async function run(t) {
  const sodium = await ensureSodium();
  const crypto = new Crypto(sodium);

  t.group("crypto.hash: content hash is BLAKE2b-256 (§4.2)");
  {
    const data = new TextEncoder().encode("block bytes");
    t.ok(bytesEqual(crypto.hash(data), sodium.crypto_generichash(32, data)), "hash == libsodium BLAKE2b-256");
  }

  t.group("crypto.stream: length-preserving, no tag (§4.4)");
  {
    const K = crypto.randomKey();
    const plain = sodium.randombytes_buf(1000);
    const ct = crypto.encrypt(K, LEVEL_BODY, 0, plain);
    t.eq(ct.length, plain.length, "ciphertext is same length as plaintext (no MAC)");
    const back = crypto.decrypt(K, LEVEL_BODY, 0, ct);
    t.ok(bytesEqual(back, plain), "decrypt(encrypt(x)) == x");
    // A different LEVEL or chunk index → different keystream, so ciphertext differs.
    const ctIndex = crypto.encrypt(K, LEVEL_BODY + 1, 0, plain);
    const ctIdx1 = crypto.encrypt(K, LEVEL_BODY, 1, plain);
    t.ok(!bytesEqual(ct, ctIndex), "the level byte separates an index stream from the body stream");
    t.ok(!bytesEqual(ct, ctIdx1), "chunk index changes the keystream");
  }

  t.group("crypto seal/open: share the key, not the bytes (§4.4)");
  {
    const owner = newKey();
    const recipient = newKey();
    const stranger = newKey();
    const K = crypto.randomKey();
    const sealed = crypto.seal(K, recipient.publicKey);
    const opened = crypto.sealOpen(sealed, recipient.publicKey, recipient.privateKey);
    t.ok(opened && bytesEqual(opened, K), "recipient recovers K");
    const wrong = crypto.sealOpen(sealed, stranger.publicKey, stranger.privateKey);
    t.ok(wrong === null, "a stranger cannot open the seal");
    void owner;
  }

}

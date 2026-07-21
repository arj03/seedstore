// Storage host-service tests: the crypto primitives (§16). There are no
// storage-specific kernel bridges any more — the codec no longer hashes through a
// crypto.hash service (it is a pure transform), and the confined guest reaches
// crypto/net/fs/clock/module through seedkernel's generic cap-bridge, so nothing
// storage-named is wired onto the kernel.
//
// store.local is not tested here: the host holds only a read view of it now
// (host/store-view.ts, covered in net.test.mjs), and the policy that fills it —
// admission and the §14 quota — is the confined holder's, covered end-to-end over
// the real wire in protocol.test.mjs.

import { Crypto, DOMAIN_BODY, DOMAIN_MANIFEST } from "../build/host/crypto.js";
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
    const ct = crypto.encrypt(K, DOMAIN_BODY, 0, plain);
    t.eq(ct.length, plain.length, "ciphertext is same length as plaintext (no MAC)");
    const back = crypto.decrypt(K, DOMAIN_BODY, 0, ct);
    t.ok(bytesEqual(back, plain), "decrypt(encrypt(x)) == x");
    // Different domain / index → different keystream, so ciphertext differs.
    const ctManifest = crypto.encrypt(K, DOMAIN_MANIFEST, 0, plain);
    const ctIdx1 = crypto.encrypt(K, DOMAIN_BODY, 1, plain);
    t.ok(!bytesEqual(ct, ctManifest), "domain tag separates manifest from body stream");
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

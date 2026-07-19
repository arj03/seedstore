// Storage host-service tests: the crypto primitives (§16) and the store.local
// backend (§12). There are no storage-specific kernel bridges any more — the
// codec no longer hashes through a crypto.hash service (it is a pure transform),
// and the confined guest reaches crypto/net/fs/clock/module through seedkernel's
// generic cap-bridge, so nothing storage-named is wired onto the kernel.

import { Crypto, DOMAIN_BODY, DOMAIN_MANIFEST } from "../build/host/crypto.js";
import { MemoryBlobStore } from "../build/host/store-local.js";
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

  t.group("store.local backend: put/get/has/delete/stat (§12)");
  {
    const store = new MemoryBlobStore(1024);
    const id = crypto.hash(new TextEncoder().encode("a"));
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const desc = new Uint8Array([9, 9]);
    store.put(id, bytes, desc);
    t.ok(store.has(id), "has after put");
    const got = store.get(id);
    t.ok(got && bytesEqual(got.bytes, bytes), "get returns bytes");
    t.ok(got && got.descriptor && bytesEqual(got.descriptor, desc), "get returns descriptor");
    t.eq(store.stat().used, bytes.length + desc.length, "used reflects ciphertext + descriptor bytes");
    t.eq(store.list().length, 1, "list has one id");
    t.ok(store.delete(id), "delete returns true");
    t.ok(!store.has(id), "gone after delete");
    // Quota refusal feeds admission control (§14).
    let threw = false;
    try { store.put(id, new Uint8Array(2000), null); } catch { threw = true; }
    t.ok(threw, "put past quota throws");
  }
}

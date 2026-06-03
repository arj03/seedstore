// Storage bridge tests: crypto host services (§16), the store.local backend
// (§12), and end-to-end capability gating on the kernel.call path (§8.2) using
// seedkernel's forwarder fixture as the WASM caller.

import { Crypto, DOMAIN_BODY, DOMAIN_MANIFEST } from "../build/host/crypto.js";
import { MemoryBlobStore } from "../build/host/store-local.js";
import { storageNames } from "../build/host/names.js";
import { registerStorageBridges } from "../build/host/bridges.js";
import { bytesEqual } from "../build/host/util.js";

import {
  ensureSodium, newKey, loadHost, makeSeq, installWasm, wasmBytes,
} from "./helpers.mjs";

export async function run(t) {
  const sodium = await ensureSodium();
  const crypto = new Crypto(sodium);

  t.group("crypto.hash: content hash is BLAKE2b-256 (§4.2)");
  {
    const data = new TextEncoder().encode("block bytes");
    t.ok(bytesEqual(crypto.hash(data), sodium.crypto_generichash(32, data)), "hash == libsodium BLAKE2b-256");
    // SHA-3-256 stays available for deployments that want genesis-identical ids.
    const sha = new Crypto(sodium, "sha3-256");
    t.ok(bytesEqual(sha.hash(data), sodium.crypto_hash_sha3256(data)), "pluggable: sha3-256 mode matches the genesis hash");
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
    t.eq(store.stat().used, 4, "used reflects stored bytes");
    t.eq(store.list().length, 1, "list has one id");
    t.ok(store.delete(id), "delete returns true");
    t.ok(!store.has(id), "gone after delete");
    // Quota refusal feeds admission control (§14).
    let threw = false;
    try { store.put(id, new Uint8Array(2000), null); } catch { threw = true; }
    t.ok(threw, "put past quota throws");
  }

  t.group("capability gate: store.local needs cap.store via kernel.call (§8.2)");
  {
    const { host, installName } = await loadHost();
    const names = storageNames(host);
    const store = new MemoryBlobStore(4096);
    registerStorageBridges(host, names, {
      crypto,
      store,
      clockNow: () => 1000,
      randBytes: (n) => sodium.randombytes_buf(n),
      netSend: () => {},
    });

    const seq = makeSeq();
    const author = newKey();
    const withCap = host.deriveScopedName("test.fwd.withcap", author.publicKey);
    const noCap = host.deriveScopedName("test.fwd.nocap", author.publicKey);
    installWasm(host, installName, author.privateKey, author.publicKey, seq(author.publicKey),
      withCap, [names.capStore], wasmBytes.forwarder());
    installWasm(host, installName, author.privateKey, author.publicKey, seq(author.publicKey),
      noCap, [], wasmBytes.forwarder());
    t.ok(host.isRegistered(withCap) && host.isRegistered(noCap), "both forwarders installed");

    // The forwarder calls kernel.call(target, forward_payload). Make the target
    // store.local and the payload a STAT request (op 6, no args).
    const SL_STAT = 6;
    const makeForward = (target) => {
      const fp = new Uint8Array(1);
      fp[0] = SL_STAT;
      const out = new Uint8Array(1 + target.length + fp.length);
      out[0] = target.length;
      out.set(target, 1);
      out.set(fp, 1 + target.length);
      return out;
    };

    const { CURRENT_VERSION } = await import("seedkernel-wasm");
    host.dispatch(host.wrapAndEncode(author.privateKey, author.publicKey, CURRENT_VERSION, withCap, makeForward(names.storeLocal)));
    t.eq(host.callDynamicHandlerI32(withCap, "last_resp_len"), 12, "cap.store holder gets the 12-byte stat");

    host.dispatch(host.wrapAndEncode(author.privateKey, author.publicKey, CURRENT_VERSION, noCap, makeForward(names.storeLocal)));
    t.eq(host.callDynamicHandlerI32(noCap, "last_resp_len"), 0, "no-cap caller is denied (no response)");
  }
}

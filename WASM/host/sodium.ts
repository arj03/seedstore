// libsodium access for the storage layer: hashing, ChaCha20-Poly1305 and key-sealing. On
// Node it is the core libsodium the seedkernel runtime loads (`loadSodium`), which is the
// host's crypto there too (SPEC §2, §16). A page brings its own libsodium (the browser demo
// vendors libsodium-wrappers) and takes the host's crypto from its seedkernel host
// (StorageNodeOptions `host`).

/** The subset of libsodium the storage host uses. */
export interface Sodium {
  ready: Promise<void>;
  // content-address hash for block_id (§4.2). Block-ids never cross into the
  // host, so the storage layer hashes them with BLAKE2b (crypto_generichash)
  // — fast and already in libsodium — rather than the host's BLAKE2b-256 genesis
  // hash. (BLAKE2b-256 is the host's hash for module-name inputs too.)
  crypto_generichash(hashLength: number, message: Uint8Array, key?: Uint8Array | null): Uint8Array;
  crypto_generichash_BYTES: number;
  // key sealing to a recipient's node key (§4.4)
  crypto_box_seal(message: Uint8Array, recipientCurvePk: Uint8Array): Uint8Array;
  crypto_box_seal_open(ciphertext: Uint8Array, recipientCurvePk: Uint8Array, recipientCurveSk: Uint8Array): Uint8Array;
  crypto_sign_ed25519_pk_to_curve25519(edPk: Uint8Array): Uint8Array;
  crypto_sign_ed25519_sk_to_curve25519(edSk: Uint8Array): Uint8Array;
  // identity (§2) — peers are node keypairs
  crypto_sign_keypair(): { publicKey: Uint8Array; privateKey: Uint8Array; keyType: string };
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
  crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
  randombytes_buf(length: number): Uint8Array;
  // The rest of the core surface the shared shell and storage host need.
  crypto_aead_chacha20poly1305_ietf_encrypt(
    message: Uint8Array, additional_data: Uint8Array | null, secret_nonce: Uint8Array | null,
    public_nonce: Uint8Array, key: Uint8Array,
  ): Uint8Array;
  crypto_aead_chacha20poly1305_ietf_decrypt(
    secret_nonce: Uint8Array | null, ciphertext: Uint8Array, additional_data: Uint8Array | null,
    public_nonce: Uint8Array, key: Uint8Array,
  ): Uint8Array;
  crypto_scalarmult(sk: Uint8Array, pk: Uint8Array): Uint8Array;
  /** The PQ half of seedkernel's one manifest suite (§12.4), present when this instance
   *  is also the host's crypto (`loadSodium` mixes it in): a manifest is signed by both
   *  an Ed25519 and an ML-DSA-65 key and requires both to verify. A page's own libsodium
   *  has none; its host's crypto is passed apart. */
  ml_dsa65_verify_detached?(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
}

let cached: Sodium | null = null;

/** Load the core libsodium the seedkernel runtime bundles on Node, returning that one
 *  shared, readied instance, which is the host's crypto too (SPEC §16). Safe to call
 *  repeatedly. */
export async function loadSodium(): Promise<Sodium> {
  if (cached) return cached;
  const { loadCrypto: kernelLoadCrypto } = await import("seedkernel-wasm");
  cached = (await kernelLoadCrypto()) as unknown as Sodium;
  return cached;
}

/** A fresh node keypair = a peer identity (§2). */
export function generateKeyPair(sodium: Sodium): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

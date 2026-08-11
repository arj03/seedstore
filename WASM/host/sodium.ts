// libsodium access for the storage layer. Seed store reuses the kernel's
// cryptography rather than shipping its own (README §2, §16): hashing, the
// length-preserving stream cipher, and key-sealing are all libsodium calls
// exposed as no-cap host services. The kernel's own crypto only needs the
// standard build, but the §4.4 stream cipher (crypto_stream_xchacha20_xor) is
// a "sumo" symbol, so the storage host loads the sumo build and shares that one
// instance with the kernel host as well.

/** The subset of libsodium the storage host uses. */
export interface Sodium {
  ready: Promise<void>;
  // content-address hash for block_id (§4.2). Block-ids never cross into the
  // kernel, so the storage layer hashes them with BLAKE2b (crypto_generichash)
  // — fast and already in libsodium — rather than the kernel's BLAKE2b-256 genesis
  // hash. (BLAKE2b-256 is the kernel's hash for handler-name derivation too.)
  crypto_generichash(hashLength: number, message: Uint8Array, key?: Uint8Array | null): Uint8Array;
  crypto_generichash_BYTES: number;
  // length-preserving stream cipher (§4.4): same op encrypts and decrypts
  crypto_stream_xchacha20_xor(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
  crypto_stream_xchacha20_KEYBYTES: number;
  crypto_stream_xchacha20_NONCEBYTES: number;
  // key sealing to a recipient's kernel key (§4.4)
  crypto_box_seal(message: Uint8Array, recipientCurvePk: Uint8Array): Uint8Array;
  crypto_box_seal_open(ciphertext: Uint8Array, recipientCurvePk: Uint8Array, recipientCurveSk: Uint8Array): Uint8Array;
  crypto_sign_ed25519_pk_to_curve25519(edPk: Uint8Array): Uint8Array;
  crypto_sign_ed25519_sk_to_curve25519(edSk: Uint8Array): Uint8Array;
  // identity (§2) — peers are kernel keypairs
  crypto_sign_keypair(): { publicKey: Uint8Array; privateKey: Uint8Array; keyType: string };
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
  crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
  randombytes_buf(length: number): Uint8Array;
  // The rest of the sumo surface the shared shell needs — the guest seam's crypto
  // catalog (CapSodium: the AEAD + X25519 + ML-KEM primitives) and the bundle
  // manifest checks. One libsodium instance serves the kernel, the shell and the
  // storage host (README §2, §16), so the type is the union, not the seedstore
  // slice. All of these exist on the sumo build `seedkernel-wasm` loads.
  crypto_aead_chacha20poly1305_ietf_encrypt(
    message: Uint8Array, additional_data: Uint8Array | null, secret_nonce: Uint8Array | null,
    public_nonce: Uint8Array, key: Uint8Array,
  ): Uint8Array;
  crypto_aead_chacha20poly1305_ietf_decrypt(
    secret_nonce: Uint8Array | null, ciphertext: Uint8Array, additional_data: Uint8Array | null,
    public_nonce: Uint8Array, key: Uint8Array,
  ): Uint8Array;
  crypto_scalarmult(sk: Uint8Array, pk: Uint8Array): Uint8Array;
  ml_kem768_keypair_from_seed(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
  ml_kem768_encaps(pk: Uint8Array, coins: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array } | null;
  ml_kem768_decaps(sk: Uint8Array, ct: Uint8Array): Uint8Array | null;
  /** The PQ half of seedkernel's one manifest suite (§12.4). Not optional: a manifest
   *  is signed by both an Ed25519 and an ML-DSA-65 key and requires both to verify, so
   *  an instance without this verifies no bundle at all. `loadSodium` mixes it in. */
  ml_dsa65_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
}

let cached: Sodium | null = null;

/** Load the sumo libsodium the seedkernel runtime bundles, returning that one
 *  shared, readied instance. seedstore ships no second crypto library — it
 *  reuses the kernel's (README §16). Safe to call repeatedly. */
export async function loadSodium(): Promise<Sodium> {
  if (cached) return cached;
  const { loadCrypto: kernelLoadCrypto } = await import("seedkernel-wasm");
  cached = (await kernelLoadCrypto()) as unknown as Sodium;
  return cached;
}

/** A fresh kernel keypair = a peer identity (§2). */
export function generateKeyPair(sodium: Sodium): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

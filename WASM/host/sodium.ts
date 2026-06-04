// libsodium access for the storage layer. Seed store reuses the kernel's
// cryptography rather than shipping its own (README §2, §16): hashing, the
// length-preserving stream cipher, and key-sealing are all libsodium calls
// exposed as no-cap host services. The kernel's genesis suite only needs the
// standard build, but the §4.4 stream cipher (crypto_stream_xchacha20_xor) is
// a "sumo" symbol, so the storage host loads the sumo build and shares that one
// instance with the kernel host as well.

/** The subset of libsodium the storage host uses. */
export interface Sodium {
  ready: Promise<void>;
  // content-address hash for block_id (§4.2). Block-ids never cross into the
  // kernel, so the storage layer hashes them with BLAKE2b (crypto_generichash)
  // — fast and already in libsodium — rather than the kernel's SHA-3 genesis
  // hash. (SHA-3 stays the kernel's hash for handler-name derivation, not here.)
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
}

let cached: Sodium | null = null;

/** Load and ready the sumo libsodium build. Safe to call repeatedly. */
export async function loadSodium(): Promise<Sodium> {
  if (cached) return cached;
  const mod = await import("libsodium-wrappers-sumo");
  const s = (mod.default ?? mod) as unknown as Sodium;
  await s.ready;
  cached = s;
  return s;
}

/** A fresh kernel keypair = a peer identity (§2). */
export function generateKeyPair(sodium: Sodium): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

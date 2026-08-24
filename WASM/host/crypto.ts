// Host crypto wrappers (README §16). Thin wrappers over the core libsodium the
// kernel already loads. The guest reaches the same BLAKE2b-256 and
// ChaCha20-Poly1305 transforms through the kernel's ungated `crypto/*` table.
//
// Confidentiality is added client-side here (§4.4). The ciphertext remains
// length-preserving for RS geometry; its detached 16-byte authentication tag is
// carried in the signed descriptor.

import type { Sodium } from "./sodium.js";
import { concatBytes, writeU32BE } from "./util.js";

// The nonce's domain byte is the chunk's own index-tree LEVEL (§4.3): 0 for the
// file's ciphertext, ℓ > 0 for the index chunks above it. Levels never share a
// (K, nonce) pair with each other or with the body, and there is no separate
// manifest domain to keep in step (§4.4).
export const LEVEL_BODY = 0x00;

/** Content-address hash for block_id (§4.2). BLAKE2b (`crypto_generichash`):
 *  fast in software and already in the libsodium the kernel loads (§16), so it
 *  ships no new bytes. (A future BLAKE3 + SIMD step is discussed in the README.) */
export const BLOCK_ID_BYTES = 32;
export const AUTH_TAG_BYTES = 16;

export interface SealedChunk {
  ciphertext: Uint8Array;
  authTag: Uint8Array;
}

export class Crypto {
  readonly keyBytes: number;
  readonly nonceBytes: number;
  constructor(private readonly sodium: Sodium) {
    this.keyBytes = 32;
    this.nonceBytes = 12;
  }

  /** Content-address hash → block_id = hash(block_bytes) (§4.2). */
  hash(bytes: Uint8Array): Uint8Array {
    return this.sodium.crypto_generichash(BLOCK_ID_BYTES, bytes);
  }

  /** 12-byte nonce = [domain u8][index u32 BE][zero padding] (§4.4). One nonce
   *  per chunk, so (K, nonce) never repeats for a fresh K. */
  nonce(domain: number, index: number): Uint8Array {
    const n = new Uint8Array(this.nonceBytes);
    n[0] = domain & 0xff;
    writeU32BE(n, 1, index >>> 0);
    return n;
  }

  /** Seal padded chunk bytes, splitting the AEAD output so RS still sees exactly the
   *  original ciphertext length and the signed descriptor carries the tag. */
  encrypt(key: Uint8Array, domain: number, index: number, message: Uint8Array): SealedChunk {
    const sealed = this.sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      message, null, null, this.nonce(domain, index), key,
    );
    return {
      ciphertext: sealed.slice(0, sealed.length - AUTH_TAG_BYTES),
      authTag: sealed.slice(sealed.length - AUTH_TAG_BYTES),
    };
  }
  decrypt(
    key: Uint8Array, domain: number, index: number,
    ciphertext: Uint8Array, authTag: Uint8Array,
  ): Uint8Array | null {
    if (authTag.length !== AUTH_TAG_BYTES) return null;
    try {
      return this.sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
        null, concatBytes([ciphertext, authTag]), null,
        this.nonce(domain, index), key,
      );
    } catch {
      return null;
    }
  }

  /** A fresh random per-file content key K (§4.4). */
  randomKey(): Uint8Array {
    return this.sodium.randombytes_buf(this.keyBytes);
  }
  randomBytes(n: number): Uint8Array {
    return this.sodium.randombytes_buf(n);
  }

  /** Seal K to a recipient's kernel public key — converting the Ed25519 key to
   *  X25519 (§4.4). Sharing a file is sharing the key, not moving bytes. */
  seal(K: Uint8Array, recipientEdPk: Uint8Array): Uint8Array {
    const curvePk = this.sodium.crypto_sign_ed25519_pk_to_curve25519(recipientEdPk);
    return this.sodium.crypto_box_seal(K, curvePk);
  }

  /** Open a sealed K with the recipient's kernel keypair. Returns null if the
   *  seal was not for this recipient. */
  sealOpen(sealed: Uint8Array, recipientEdPk: Uint8Array, recipientEdSk: Uint8Array): Uint8Array | null {
    try {
      const curvePk = this.sodium.crypto_sign_ed25519_pk_to_curve25519(recipientEdPk);
      const curveSk = this.sodium.crypto_sign_ed25519_sk_to_curve25519(recipientEdSk);
      return this.sodium.crypto_box_seal_open(sealed, curvePk, curveSk);
    } catch {
      return null;
    }
  }
}

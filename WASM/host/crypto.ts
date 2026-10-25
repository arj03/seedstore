// Host-side crypto wrappers (SPEC §16), over seedstore's own libsodium (sodium.ts).
// The guest reaches the same BLAKE2b-256 and
// ChaCha20-Poly1305 transforms through the host's ungated `crypto/*` table.
//
// Confidentiality is added client-side here (§4.4). The ciphertext remains
// length-preserving for RS geometry; its detached 16-byte authentication tag is
// carried in the signed descriptor.

import type { Sodium } from "./sodium.js";
import { concatBytes } from "./util.js";
import { blockHashInput, chunkNonce, BLOCK_ID_LEN, AUTH_TAG_LEN } from "./descriptor-core.js";

export { LEVEL_BODY } from "./descriptor-core.js";

export interface SealedChunk {
  ciphertext: Uint8Array;
  authTag: Uint8Array;
}

export class Crypto {
  readonly keyBytes: number;
  constructor(private readonly sodium: Sodium) {
    this.keyBytes = 32;
  }

  /** General BLAKE2b-256 byte hash (§4.2). A block's id is blockId() below, not this. */
  hash(bytes: Uint8Array): Uint8Array {
    return this.sodium.crypto_generichash(BLOCK_ID_LEN, bytes);
  }

  /** A block's id (§4.2), bound to the descriptor's author. */
  blockId(authorPk: Uint8Array, bytes: Uint8Array): Uint8Array {
    return this.hash(blockHashInput(authorPk, bytes));
  }

  /** Seal padded chunk bytes, splitting the AEAD output so RS still sees exactly the
   *  original ciphertext length and the signed descriptor carries the tag. */
  encrypt(key: Uint8Array, domain: number, index: number, message: Uint8Array): SealedChunk {
    const sealed = this.sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      message, null, null, chunkNonce(domain, index), key,
    );
    return {
      ciphertext: sealed.slice(0, sealed.length - AUTH_TAG_LEN),
      authTag: sealed.slice(sealed.length - AUTH_TAG_LEN),
    };
  }
  decrypt(
    key: Uint8Array, domain: number, index: number,
    ciphertext: Uint8Array, authTag: Uint8Array,
  ): Uint8Array | null {
    if (authTag.length !== AUTH_TAG_LEN) return null;
    try {
      return this.sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
        null, concatBytes([ciphertext, authTag]), null,
        chunkNonce(domain, index), key,
      );
    } catch {
      return null;
    }
  }

  /** A fresh random per-file content key K (§4.4). */
  randomKey(): Uint8Array {
    return this.sodium.randombytes_buf(this.keyBytes);
  }

  /** Seal K to a recipient's node public key — converting the Ed25519 key to
   *  X25519 (§4.4). Sharing a file is sharing the key, not moving bytes. */
  seal(K: Uint8Array, recipientEdPk: Uint8Array): Uint8Array {
    const curvePk = this.sodium.crypto_sign_ed25519_pk_to_curve25519(recipientEdPk);
    return this.sodium.crypto_box_seal(K, curvePk);
  }

  /** Open a sealed K with the recipient's node keypair. Returns null if the
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

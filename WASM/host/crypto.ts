// Host-side crypto wrappers (SPEC §16), over seedstore's own libsodium (sodium.ts): the
// per-file content key and sharing it. Block ids and chunk sealing are the guest's, through
// the host's SHA-256 and AES-256-GCM transforms (`crypto/sha256`, `crypto/aes256gcm/*`).

import type { Sodium } from "./sodium.js";

export { LEVEL_BODY } from "./descriptor-core.js";

export class Crypto {
  readonly keyBytes: number;
  constructor(private readonly sodium: Sodium) {
    this.keyBytes = 32;
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

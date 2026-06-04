// Host crypto services (README §16). Thin wrappers over the libsodium the
// kernel already loads — "storage ships no crypto of its own except Reed–
// Solomon". These perform no I/O, so they are no-cap services (§16): a WASM
// handler may call crypto.hash without declaring any capability, which is what
// lets the codec stay pure (§17).
//
// Confidentiality is added client-side here (§4.4): a plain length-preserving
// stream cipher with no authentication tag — integrity is content addressing's
// job (§1, §4.2), so a MAC would only pad the block and risk misaligning it.

import type { Sodium } from "./sodium.js";
import { writeU32BE } from "./util.js";

// Nonce domain tags separating the manifest stream from the body stream so the
// two never share a (K, nonce) pair (§4.4).
export const DOMAIN_MANIFEST = 0x00;
export const DOMAIN_BODY = 0x01;

/** Content-address hash for block_id (§4.2). Block-ids never cross into the
 *  kernel — they are pure content addressing within the storage layer — so the
 *  hash is a storage-local choice, decoupled from the kernel's SHA-3 genesis
 *  hash. We use BLAKE2b (`crypto_generichash`): fast in software and *also*
 *  already in the libsodium the kernel loads, so it ships no new bytes (§16).
 *  (A future BLAKE3 + SIMD `hash_many` over the equal-size blocks is the next
 *  step up — see ../README.md "Block-id hash choice".) */
export const BLOCK_ID_BYTES = 32;

export class Crypto {
  readonly keyBytes: number;
  readonly nonceBytes: number;
  constructor(private readonly sodium: Sodium) {
    this.keyBytes = sodium.crypto_stream_xchacha20_KEYBYTES;   // 32
    this.nonceBytes = sodium.crypto_stream_xchacha20_NONCEBYTES; // 24
  }

  /** Content-address hash → block_id = hash(block_bytes) (§4.2). */
  hash(bytes: Uint8Array): Uint8Array {
    return this.sodium.crypto_generichash(BLOCK_ID_BYTES, bytes);
  }
  blockId(bytes: Uint8Array): Uint8Array {
    return this.hash(bytes);
  }

  /** 24-byte nonce = [domain u8][index u32 BE][zero padding] (§4.4). One nonce
   *  per chunk (or per manifest), so (K, nonce) never repeats for a fresh K. */
  nonce(domain: number, index: number): Uint8Array {
    const n = new Uint8Array(this.nonceBytes);
    n[0] = domain & 0xff;
    writeU32BE(n, 1, index >>> 0);
    return n;
  }

  /** Length-preserving XOR stream — the same op encrypts and decrypts (§4.4). */
  streamXor(key: Uint8Array, nonce: Uint8Array, message: Uint8Array): Uint8Array {
    return this.sodium.crypto_stream_xchacha20_xor(message, nonce, key);
  }

  encrypt(key: Uint8Array, domain: number, index: number, message: Uint8Array): Uint8Array {
    return this.streamXor(key, this.nonce(domain, index), message);
  }
  decrypt(key: Uint8Array, domain: number, index: number, ciphertext: Uint8Array): Uint8Array {
    return this.streamXor(key, this.nonce(domain, index), ciphertext);
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

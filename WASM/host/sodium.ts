// libsodium access for the storage layer: identities, signatures and key-sealing. It is
// seedstore's own libsodium-wrappers-sumo, not the host's crypto, which the host keeps to its
// trust root (seedkernel docs/CLIENT.md) and serves the guest as `crypto/*` (SPEC §2, §16).
// On Node `loadSodium` loads the npm package; a page vendors the same package over the
// libsodium.wasm its host blob carries.

/** The subset of libsodium the storage host uses. */
export interface Sodium {
  ready: Promise<void>;
  // key sealing to a recipient's node key (§4.4)
  crypto_box_seal(message: Uint8Array, recipientCurvePk: Uint8Array): Uint8Array;
  crypto_box_seal_open(ciphertext: Uint8Array, recipientCurvePk: Uint8Array, recipientCurveSk: Uint8Array): Uint8Array;
  crypto_sign_ed25519_pk_to_curve25519(edPk: Uint8Array): Uint8Array;
  crypto_sign_ed25519_sk_to_curve25519(edSk: Uint8Array): Uint8Array;
  // identity (§2) — peers are node keypairs
  crypto_sign_keypair(): { publicKey: Uint8Array; privateKey: Uint8Array };
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
  crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
  randombytes_buf(length: number): Uint8Array;
}

let cached: Sodium | null = null;

/** Load libsodium on Node, returning one shared, readied instance. Safe to call
 *  repeatedly. Imported lazily, so a page's module graph never reaches it. */
export async function loadSodium(): Promise<Sodium> {
  if (cached) return cached;
  const { default: sodium } = await import("libsodium-wrappers-sumo");
  await sodium.ready;
  cached = sodium as unknown as Sodium;
  return cached;
}

/** A fresh node keypair = a peer identity (§2). */
export function generateKeyPair(sodium: Sodium): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

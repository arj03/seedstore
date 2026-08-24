// The one object that describes a file (README §4.3): the per-chunk *signed*
// descriptor — no separate manifest object. Pure codecs live in manifest-core.ts
// (shared with the guest); this module adds the two scoped-signature pieces:
// signing and verifying the author signature. Verified from the author's public
// key alone, never the read key, which preserves keyless repair (§9); a holder
// additionally anchors that key to a peer its cohort knows (§4.3).

import type { Sodium } from "./sodium.js";
import {
  encodeDescriptorCore, parseSignedDescriptor, type Descriptor, type SignedDescriptor,
} from "./manifest-core.js";
import { concatBytes } from "./util.js";
import { appSigner, guestSignScope } from "seedkernel-wasm/guest-seam";

// This package's sign/verify go through the kernel's scoped signer (seedkernel
// §12.2): `sign` applies `DOMAIN_guest ‖ scope ‖ msg` host-side; neither this
// mirror nor the guest ever reconstructs the prefix bytes.
export { guestSignScope };

export {
  BLOCK_ID_LEN,
  AUTH_TAG_LEN,
  encodeDescriptorCore, decodeDescriptorCore, parseSignedDescriptor,
  descriptorContains, encodeDescriptorList, decodeDescriptorList,
  copyTargets, lossMargin, lowWaterMargin,
} from "./manifest-core.js";
export type { Descriptor, SignedDescriptor } from "./manifest-core.js";

// ── scoped signing (README §16, seedkernel §12.2/§14) ────────────────────────
// The guest's SIGN/VERIFY ops are both *scoped*: the kernel signs and verifies
// `DOMAIN_guest ‖ scope ‖ msg`, never the raw message, so a storage signature
// verifies only as a storage signature — never as a kernel envelope, a bundle
// manifest, or a channel handshake, nor in another app's scope.

/** This app's name — the `app` component of the signing scope (matches the bundle
 *  manifest `app`, so a shell-run node and a host-side StorageNode derive the same
 *  scope when they share a bundle author). */
export const STORAGE_APP = "seedstore";

/** The wire protocol id storage speaks (seedkernel §12.10), claimed by the
 *  bundle's signed manifest (`protocols`, scripts/storage-bundle.mjs) and read by
 *  the guest's NET_PROTO — stated once here rather than retyped per deployment. */
export const STORAGE_PROTO = "seedstore";

/** The signing scope `author_pk ‖ app_len u8 ‖ app` for a storage deployment
 *  (seedkernel `guestSignScope`). The bundle path scopes to the admitted manifest's
 *  `(author, app)`; a host-side StorageNode with no bundle scopes to `(zero, app)`. */
export function storageSignScope(authorPk: Uint8Array): Uint8Array {
  return guestSignScope(authorPk, STORAGE_APP);
}

/** The host-side mirror's one seam: derives the byte-identical scope the shell
 *  derives for the admitted bundle (§16). Built per call — nothing worth caching. */
function storageSigner(sodium: Sodium, authorPk: Uint8Array, authorSk: Uint8Array, scopeAuthor: Uint8Array) {
  return appSigner(sodium, { publicKey: authorPk, privateKey: authorSk }, scopeAuthor, STORAGE_APP);
}

/** A signed chunk descriptor as stored alongside every block and listed in the
 *  manifest (§4.3): [authorPk 32][sig 64][core ...]. Signing stays sender-side
 *  in the host (§16) — this mirrors what the guest's scoped `node/sign` seam does
 *  (Ed25519 over `DOMAIN_guest ‖ scope ‖ core`). `scopeAuthor` is the deployment's
 *  signing-scope author — the key whose `storageSignScope` is the cohort scope,
 *  derived from the bundle author via `storageSignScope(author)`. */
export function signDescriptor(
  sodium: Sodium, d: Descriptor, authorPk: Uint8Array, authorSk: Uint8Array,
  scopeAuthor: Uint8Array,
): Uint8Array {
  const core = encodeDescriptorCore(d);
  const sig = storageSigner(sodium, authorPk, authorSk, scopeAuthor).sign(core);
  return concatBytes([authorPk, sig, core]);
}

/** Verify the author signature over the descriptor (§4.3), via the kernel's scoped
 *  signer — the host applies `DOMAIN_guest ‖ storageSignScope(scopeAuthor) ‖
 *  core` for us. Returns the parsed signed descriptor if valid, else null.
 *  `scopeAuthor` must match the signing-scope author the cohort was built with. */
export function verifyDescriptor(
  sodium: Sodium, env: Uint8Array, scopeAuthor: Uint8Array,
): SignedDescriptor | null {
  let sd: SignedDescriptor;
  try { sd = parseSignedDescriptor(env); } catch { return null; }
  const ok = storageSigner(sodium, sd.authorPk, new Uint8Array(32), scopeAuthor)
    .verify(sd.authorPk, sd.sig, sd.core);
  return ok ? sd : null;
}

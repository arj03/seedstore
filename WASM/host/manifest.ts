// The two small objects that describe a file (README §4.3): the per-chunk
// *signed* descriptor and the file *manifest*.
//
// The pure binary codecs + structural validation live in manifest-core.ts — the
// single definition of the wire format, shared with the zero-authority guest
// (stitched into its bundle at build time). This module re-exports that core and
// adds the only two pieces that need a capability: signing and verifying the
// author signature. The descriptor is signed by the file's author (the §2 identity)
// so a holder cannot forge it to misdirect repair; crucially the signature is
// checked from the author's *public* key alone, never the read key, which is what
// preserves keyless repair (§9). The manifest names *what* blocks a file is made
// of, never *which* peers hold them — placement is discovered live via have/want
// (§5), so it never goes stale under churn.

import type { Sodium } from "./sodium.js";
import {
  encodeDescriptorCore, parseSignedDescriptor, type Descriptor, type SignedDescriptor,
} from "./manifest-core.js";
import { concatBytes } from "./util.js";
import { guestSignScope, guestSignPrefix } from "seedkernel-wasm/cap-bridge";

// The scoped-signature prefix `DOMAIN_guest ‖ scope` (README §16) comes straight from the
// kernel — the SAME function the SIGN op prepends and the shell injects — so the host
// mirror and the guest verify path share one definition of the kernel's domain tag. It
// used to be re-derived here from a hand-copied "seedkernel-guest-sig-v1\0"; if the kernel
// revved that string the mirror would silently diverge and every descriptor verify fail.
export { guestSignPrefix };

export {
  BLOCK_ID_LEN, ENC_XCHACHA20,
  encodeDescriptorCore, decodeDescriptorCore, parseSignedDescriptor,
  descriptorContains, encodeManifest, decodeManifest,
  isReplicated, replicaTarget, slotIndices, lossMargin, lowWaterMargin,
} from "./manifest-core.js";
export type { Descriptor, SignedDescriptor, Manifest } from "./manifest-core.js";

// ── scoped signing (README §16, seedkernel §12.2/§14) ────────────────────────
// The guest's SIGN op is a *scoped* oracle: the kernel signs `DOMAIN_guest ‖ scope ‖
// msg`, never the raw message, so a storage signature verifies only as a storage
// signature — never as a kernel envelope, a bundle manifest, or a channel handshake,
// nor in another app's scope. VERIFY stays raw, so the host mirror + the guest's verify
// path must reconstruct the byte-identical preimage before checking.

/** This app's name — the `app` component of the signing scope (matches the bundle
 *  manifest `app`, so a shell-run node and a host-side StorageNode derive the same
 *  scope when they share a bundle author). */
export const STORAGE_APP = "seedstore";

/** The signing scope `author_pk ‖ app_len u8 ‖ app` for a storage deployment
 *  (seedkernel `guestSignScope`). The bundle path scopes to the admitted manifest's
 *  `(author, app)`; a host-side StorageNode with no bundle scopes to `(zero, app)`. */
export function storageSignScope(authorPk: Uint8Array): Uint8Array {
  return guestSignScope(authorPk, STORAGE_APP);
}

/** The scoped preimage the author signs / a verifier checks: `DOMAIN_guest ‖ scope ‖ core`.
 *  `guestSignPrefix(scope)` is `DOMAIN_guest ‖ scope`, from the kernel, so this
 *  reconstructs the byte-identical bytes the kernel's SIGN op prepends. */
function signPreimage(scope: Uint8Array, core: Uint8Array): Uint8Array {
  return concatBytes([guestSignPrefix(scope), core]);
}

/** A signed chunk descriptor as stored alongside every block and listed in the
 *  manifest (§4.3): [authorPk 32][sig 64][core ...]. Signing stays sender-side
 *  in the host (§16) — this mirrors what the guest's scoped CAP_SIGN seam does
 *  (Ed25519 over `DOMAIN_guest ‖ scope ‖ core`). `scope` must be the cohort's
 *  signing scope, derived from the bundle author via `storageSignScope(author)`. */
export function signDescriptor(
  sodium: Sodium, d: Descriptor, authorPk: Uint8Array, authorSk: Uint8Array,
  scope: Uint8Array,
): Uint8Array {
  const core = encodeDescriptorCore(d);
  const sig = sodium.crypto_sign_detached(signPreimage(scope, core), authorSk);
  return concatBytes([authorPk, sig, core]);
}

/** Verify the author signature over the descriptor (§4.3), reconstructing the same
 *  scoped preimage the signer used. Returns the parsed signed descriptor if valid, else
 *  null. `scope` must match the signing scope the cohort was built with. */
export function verifyDescriptor(
  sodium: Sodium, env: Uint8Array, scope: Uint8Array,
): SignedDescriptor | null {
  let sd: SignedDescriptor;
  try { sd = parseSignedDescriptor(env); } catch { return null; }
  try {
    if (!sodium.crypto_sign_verify_detached(sd.sig, signPreimage(scope, sd.core), sd.authorPk)) return null;
  } catch { return null; }
  return sd;
}

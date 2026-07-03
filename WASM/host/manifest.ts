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
import { guestSignScope } from "seedkernel-wasm/cap-bridge";

export {
  BLOCK_ID_LEN, ENC_XCHACHA20,
  encodeDescriptorCore, decodeDescriptorCore, parseSignedDescriptor,
  descriptorContains, encodeManifest, decodeManifest,
} from "./manifest-core.js";
export type { Descriptor, SignedDescriptor, Manifest } from "./manifest-core.js";

// ── scoped signing (README §16, seedkernel §13.2/§15) ────────────────────────
// The guest's SIGN op is a *scoped* oracle: the kernel signs `DOMAIN_guest ‖ scope ‖
// msg`, never the raw message, so a storage signature verifies only as a storage
// signature — never as a kernel envelope, a bundle manifest, or a channel handshake,
// nor in another app's scope. VERIFY stays raw, so the host mirror + the guest's verify
// path must reconstruct the byte-identical preimage before checking.

/** This app's name — the `app` component of the signing scope (matches the bundle
 *  manifest `app`, so a shell-run node and a host-side StorageNode derive the same
 *  scope when they share a bundle author). */
export const STORAGE_APP = "seedstore";

/** The kernel's guest-signing domain tag (seedkernel cap-bridge `DOMAIN_GUEST`). It is
 *  not exported from the kernel, so it is mirrored here; it must track the kernel's
 *  string exactly, since the SIGN op prepends it and the verify path reconstructs it. */
const DOMAIN_GUEST_SIG = new TextEncoder().encode("seedkernel-guest-sig-v1\0");

/** The signing scope `author_pk ‖ app_len u8 ‖ app` for a storage deployment
 *  (seedkernel `guestSignScope`). The bundle path scopes to the admitted manifest's
 *  `(author, app)`; a host-side StorageNode with no bundle scopes to `(zero, app)`. */
export function storageSignScope(authorPk: Uint8Array): Uint8Array {
  return guestSignScope(authorPk, STORAGE_APP);
}

/** The default in-process signing scope: a host-side StorageNode has no bundle, so it
 *  scopes to `(zero author, app)` — every in-process node derives the same bytes, so a
 *  descriptor one signs verifies on another. A cohort that shares a bundle author (the
 *  shell-run / holder-guest cross-path tests) overrides this with `storageSignScope`. */
export const STORAGE_SIGN_SCOPE = storageSignScope(new Uint8Array(32));

/** The full scoped-signature prefix `DOMAIN_guest ‖ scope`. Injected into the guest
 *  (`APP.signPrefix`), which prepends it to a descriptor core before CAP_VERIFY; the
 *  kernel's SIGN op prepends the identical bytes, so the two paths agree by construction. */
export function guestSignPrefix(scope: Uint8Array): Uint8Array {
  return concatBytes([DOMAIN_GUEST_SIG, scope]);
}

/** The scoped preimage the author signs / a verifier checks: `DOMAIN_guest ‖ scope ‖ core`. */
function signPreimage(scope: Uint8Array, core: Uint8Array): Uint8Array {
  return concatBytes([DOMAIN_GUEST_SIG, scope, core]);
}

/** A signed chunk descriptor as stored alongside every block and listed in the
 *  manifest (§4.3): [authorPk 32][sig 64][core ...]. Signing stays sender-side
 *  in the host (§16) — this mirrors what the guest's scoped CAP_SIGN seam does
 *  (Ed25519 over `DOMAIN_guest ‖ scope ‖ core`), invoked directly so repair can verify
 *  a descriptor out-of-band from the author's public key. `scope` must match the scope
 *  the verifying cohort was built with (defaults to the in-process scope). */
export function signDescriptor(
  sodium: Sodium, d: Descriptor, authorPk: Uint8Array, authorSk: Uint8Array,
  scope: Uint8Array = STORAGE_SIGN_SCOPE,
): Uint8Array {
  const core = encodeDescriptorCore(d);
  const sig = sodium.crypto_sign_detached(signPreimage(scope, core), authorSk);
  return concatBytes([authorPk, sig, core]);
}

/** Verify the author signature over the descriptor (§4.3), reconstructing the same
 *  scoped preimage the signer used. Returns the parsed signed descriptor if valid, else
 *  null. Needs only the author's public key. */
export function verifyDescriptor(
  sodium: Sodium, env: Uint8Array, scope: Uint8Array = STORAGE_SIGN_SCOPE,
): SignedDescriptor | null {
  let sd: SignedDescriptor;
  try { sd = parseSignedDescriptor(env); } catch { return null; }
  try {
    if (!sodium.crypto_sign_verify_detached(sd.sig, signPreimage(scope, sd.core), sd.authorPk)) return null;
  } catch { return null; }
  return sd;
}

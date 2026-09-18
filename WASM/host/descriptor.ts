// The one object that describes a file (README §4.3): the per-chunk *signed*
// descriptor — no separate manifest object. Pure codecs live in descriptor-core.ts
// (shared with the guest); this module adds the two scoped-signature pieces:
// signing and verifying the author signature. Verified from the author's public
// key alone, never the read key, which preserves keyless repair (§9); a holder
// additionally anchors that key to a peer its cohort knows (§4.3).

import type { Sodium } from "./sodium.js";
import {
  encodeDescriptorCore, parseSignedDescriptor, type Descriptor, type SignedDescriptor,
} from "./descriptor-core.js";
import { concatBytes } from "./util.js";
import { appSigner } from "seedkernel-wasm/guest-seam";

export {
  BLOCK_ID_LEN,
  AUTH_TAG_LEN,
  encodeDescriptorCore, decodeDescriptorCore, parseSignedDescriptor,
  descriptorContains, encodeDescriptorList, decodeDescriptorList,
  copyTargets, lossMargin, lowWaterMargin,
} from "./descriptor-core.js";
export type { Descriptor, SignedDescriptor } from "./descriptor-core.js";

// ── scoped signing (README §16, seedkernel §12.2/§14) ────────────────────────
// The guest's SIGN/VERIFY ops are both *scoped*: the kernel signs and verifies
// `DOMAIN_guest ‖ scope ‖ msg`, never the raw message, so a storage signature
// verifies only as a storage signature — never as a kernel envelope, a bundle
// manifest, or a channel handshake, nor in another app's scope. This mirror goes
// through the kernel's own signer, so it never reconstructs the prefix bytes either.

/** This app's label — the bundle manifest's `app`, and so the whole of its signing
 *  scope: every node running storage under this label derives the same scope, whoever
 *  authored the bundle. */
export const STORAGE_APP = "seedstore";

/** The wire protocol id storage speaks (seedkernel §12.10), claimed by the
 *  bundle's signed manifest (`protocols`, scripts/storage-bundle.mjs) and read by
 *  the guest's NET_PROTO — stated once here rather than retyped per deployment. */
export const STORAGE_PROTO = "seedstore";

/** The host-side mirror's one seam: derives the byte-identical scope the shell
 *  derives for the admitted bundle (§16). Built per call — nothing worth caching. */
function storageSigner(sodium: Sodium, authorPk: Uint8Array, authorSk: Uint8Array) {
  return appSigner(sodium, { publicKey: authorPk, privateKey: authorSk }, STORAGE_APP);
}

/** A signed chunk descriptor as stored alongside every block and listed in the
 *  file's index (§4.3): [authorPk 32][sig 64][core ...]. Signing stays sender-side
 *  in the host (§16) — this mirrors what the guest's scoped `node/sign` seam does
 *  (Ed25519 over `DOMAIN_guest ‖ scope ‖ core`, the scope of `STORAGE_APP`). */
export function signDescriptor(
  sodium: Sodium, d: Descriptor, authorPk: Uint8Array, authorSk: Uint8Array,
): Uint8Array {
  const core = encodeDescriptorCore(d);
  const sig = storageSigner(sodium, authorPk, authorSk).sign(core);
  return concatBytes([authorPk, sig, core]);
}

/** Verify the author signature over the descriptor (§4.3), via the kernel's scoped
 *  signer — the host applies `DOMAIN_guest ‖ scope ‖ core` for us. Returns the parsed
 *  signed descriptor if valid, else null. */
export function verifyDescriptor(sodium: Sodium, env: Uint8Array): SignedDescriptor | null {
  let sd: SignedDescriptor;
  try { sd = parseSignedDescriptor(env); } catch { return null; }
  const ok = storageSigner(sodium, sd.authorPk, new Uint8Array(32))
    .verify(sd.authorPk, sd.sig, sd.core);
  return ok ? sd : null;
}

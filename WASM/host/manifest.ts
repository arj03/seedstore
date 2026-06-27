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

export {
  BLOCK_ID_LEN, ENC_XCHACHA20,
  encodeDescriptorCore, decodeDescriptorCore, parseSignedDescriptor,
  descriptorContains, encodeManifest, decodeManifest,
} from "./manifest-core.js";
export type { Descriptor, SignedDescriptor, Manifest } from "./manifest-core.js";

/** A signed chunk descriptor as stored alongside every block and listed in the
 *  manifest (§4.3): [authorPk 32][sig 64][core ...]. Signing stays sender-side
 *  in the host (§16) — this mirrors what the kernel's signature wrapper does
 *  (Ed25519 over the inner bytes), invoked directly so repair can verify a
 *  descriptor out-of-band from the author's public key. */
export function signDescriptor(sodium: Sodium, d: Descriptor, authorPk: Uint8Array, authorSk: Uint8Array): Uint8Array {
  const core = encodeDescriptorCore(d);
  const sig = sodium.crypto_sign_detached(core, authorSk);
  return concatBytes([authorPk, sig, core]);
}

/** Verify the author signature over the descriptor (§4.3). Returns the parsed
 *  signed descriptor if valid, else null. Needs only the author's public key. */
export function verifyDescriptor(sodium: Sodium, env: Uint8Array): SignedDescriptor | null {
  let sd: SignedDescriptor;
  try { sd = parseSignedDescriptor(env); } catch { return null; }
  try {
    if (!sodium.crypto_sign_verify_detached(sd.sig, sd.core, sd.authorPk)) return null;
  } catch { return null; }
  return sd;
}

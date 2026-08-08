// The one object that describes a file (README §4.3): the per-chunk *signed*
// descriptor. There is no separate manifest object — a file's index is an ordered
// list of these same descriptors, chunked and placed like any other bytes.
//
// The pure binary codecs + structural validation live in manifest-core.ts — the
// single definition of the wire format, shared with the zero-authority guest
// (stitched into its bundle at build time). This module re-exports that core and
// adds the only two pieces that need a capability: signing and verifying the
// author signature. The descriptor is signed by the file's author (the §2 identity)
// so a holder cannot forge it to misdirect repair; crucially the signature is
// checked from the author's *public* key alone, never the read key, which is what
// preserves keyless repair (§9). A holder additionally anchors that key to a peer
// its cohort knows (§4.3) — a signature that verifies against a key nobody knows
// binds authority to nothing. The descriptor names *what* blocks a chunk is made
// of, never *which* peers hold them — placement is discovered live via have/want
// (§5), so it never goes stale under churn.

import type { Sodium } from "./sodium.js";
import {
  encodeDescriptorCore, parseSignedDescriptor, type Descriptor, type SignedDescriptor,
} from "./manifest-core.js";
import { concatBytes, toHex } from "./util.js";
import { createGuestSeam, appSignScope, guestSignScope, UNRESTRICTED_NAMES } from "seedkernel-wasm/guest-seam";

// The scoped signing namespace is the KERNEL's to state, and this package's
// sign/verify go through the kernel's scoped seam: `node/sign` applies
// `DOMAIN_guest ‖ scope ‖ msg` host-side when signing, `node/verify` checks the same
// preimage for a caller-named key. Neither this host mirror nor the guest ever
// reconstructs the host-owned prefix bytes (seedkernel §12.2).
export { guestSignScope };

export {
  BLOCK_ID_LEN,
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

/** The wire protocol id storage speaks (seedkernel §12.10) — placed in every
 *  net/send frame so the receiving host routes it to this app, and CLAIMED by the
 *  bundle's signed manifest (`protocols`, scripts/storage-bundle.mjs), which is what
 *  gives the id a destination on the receiving node: the load that admits this code
 *  claims it, with no operator step in between. The id an app speaks is the app's own
 *  fact, so it is stated once here and read by the two places that need it — the
 *  bundle build and the guest's NET_PROTO — rather than retyped per deployment. */
export const STORAGE_PROTO = "seedstore";

/** The signing scope `author_pk ‖ app_len u8 ‖ app` for a storage deployment
 *  (seedkernel `guestSignScope`). The bundle path scopes to the admitted manifest's
 *  `(author, app)`; a host-side StorageNode with no bundle scopes to `(zero, app)`. */
export function storageSignScope(authorPk: Uint8Array): Uint8Array {
  return guestSignScope(authorPk, STORAGE_APP);
}

/** The host-side mirror's one seam, per (sodium, signing key, scope author): the
 *  SAME scoped names the confined guest calls, so the preimage the two sides must
 *  agree on is the kernel's to build and nothing here reconstructs it. The scope
 *  author is the deployment's — `appSignScope(key, scopeAuthor, STORAGE_APP)`
 *  derives the byte-identical scope the shell derives for the admitted bundle (§16).
 *  Cached per triple: node/verify ignores the bridge's key, so a verify-built
 *  bridge must never be the one node/sign signs with — keying on the secret key too
 *  keeps the two apart. */
const scopedBridges = new WeakMap<Sodium, Map<string, (name: string, payload: Uint8Array) => Uint8Array | Promise<Uint8Array>>>();

function scopedBridge(sodium: Sodium, authorPk: Uint8Array, authorSk: Uint8Array, scopeAuthor: Uint8Array): (name: string, payload: Uint8Array) => Uint8Array | Promise<Uint8Array> {
  let byKey = scopedBridges.get(sodium);
  if (!byKey) {
    byKey = new Map();
    scopedBridges.set(sodium, byKey);
  }
  const cacheKey = toHex(authorPk) + ":" + toHex(authorSk) + ":" + toHex(scopeAuthor);
  let bridge = byKey.get(cacheKey);
  if (!bridge) {
    const key = { publicKey: authorPk, privateKey: authorSk };
    bridge = createGuestSeam({
      platform: { sodium, identity: key, peers: () => [] },
      grants: {
        names: UNRESTRICTED_NAMES,
        signScope: appSignScope(key, scopeAuthor, STORAGE_APP),
      },
      modules: { call: () => null, has: () => false },
    });
    byKey.set(cacheKey, bridge);
  }
  return bridge;
}

/** The never-signing key verify bridges are built with — node/verify takes the key
 *  it checks from the envelope, so this half of the bridge's scope never matters. */
const DUMMY_SK = new Uint8Array(32);

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
  const sig = scopedBridge(sodium, authorPk, authorSk, scopeAuthor)("node/sign", core) as Uint8Array;
  return concatBytes([authorPk, sig, core]);
}

/** Verify the author signature over the descriptor (§4.3), via the kernel's scoped
 *  `node/verify` — the host applies `DOMAIN_guest ‖ storageSignScope(scopeAuthor) ‖
 *  core` for us. Returns the parsed signed descriptor if valid, else null.
 *  `scopeAuthor` must match the signing-scope author the cohort was built with. */
export function verifyDescriptor(
  sodium: Sodium, env: Uint8Array, scopeAuthor: Uint8Array,
): SignedDescriptor | null {
  let sd: SignedDescriptor;
  try { sd = parseSignedDescriptor(env); } catch { return null; }
  const bridge = scopedBridge(sodium, sd.authorPk, DUMMY_SK, scopeAuthor);
  try {
    const verdict = bridge("node/verify", concatBytes([sd.authorPk, sd.sig, sd.core])) as Uint8Array;
    if (verdict[0] !== 1) return null;
  } catch { return null; }
  return sd;
}

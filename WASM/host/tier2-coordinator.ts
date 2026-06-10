// The Tier-2 driver — it runs the zero-authority orchestration guest
// (host/tier2-guest.js) inside the QuickJS realm (seedkernel's safe-js) over the
// *generic* capability bridge (seedkernel's cap-bridge). Every authority the
// guest touches — crypto primitives, net.send/requestMany, fs, the installed
// codec/reputation handlers, the clock, this node's identity — is an
// application-neutral kernel primitive; the kernel has no idea it is hosting
// storage. All storage structure (placement, k-of-n selection, the wire format,
// the descriptor envelope, repair triggers) lives in the guest.
//
// This driver wires the bridge to a StorageNode and injects the guest's two
// constant blocks: the generic CAP_* op catalog and an `APP` object carrying the
// storage config + the codec/reputation kernel names. The seedkernel shell
// constructs the byte-identical bridge to run the same guest as signed content
// (the runtime split) — so a file written through Tier-2 reads back
// through the host-side reference path and vice-versa (tests/tier2-port.test.mjs).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { createCapBridge, capPreamble } from "seedkernel-wasm/cap-bridge";
import type { Fs } from "seedkernel-wasm/fs";
// The generic zero-authority sandbox lives in the kernel as `safe-js`; alias it
// back to the storage domain's "Tier2" vocabulary (README §2.1) for this module.
import {
  createSafeRealm as createTier2Realm,
  type SafeRealm as Tier2Realm,
} from "seedkernel-wasm/safe-js";
import type { Node } from "./core.js";
import type { StorageNames } from "./names.js";
import { toHex, readU32BE, concatBytes } from "./util.js";

/** What the bridge + preamble need from a node: the orchestration surface (Node)
 *  plus the installed-handler call, the raw fs backend, and the kernel names of
 *  the codec/reputation modules. StorageNode satisfies this structurally. */
export type Tier2Host = Node & {
  readonly host: { callHandler(name: Uint8Array, payload: Uint8Array): Uint8Array | null };
  readonly fs: Fs;
  readonly names: StorageNames;
};

/** A PUT result decoded from the guest's reply — same shape as Coordinator.put. */
export interface Tier2PutResult {
  manifestId: Uint8Array;
  key: Uint8Array;
  chunkCount: number;
  replicated: boolean;
}

/** Read the guest program text. It is shipped next to this module in
 *  `build/host/tier2-guest.js` (staged by scripts/copy-kernel.mjs); the source
 *  copy is the dev fallback. When seedstore is delivered as a signed bundle the
 *  guest text comes from the loaded manifest instead (the shell's runGuest), so
 *  this fs read is not reached. */
let guestCache: string | undefined;
function guestProgram(): string {
  if (guestCache !== undefined) return guestCache;
  const candidates = [
    new URL("./tier2-guest.js", import.meta.url),       // shipped: build/host/
    new URL("../../host/tier2-guest.js", import.meta.url), // dev fallback: source
  ];
  for (const url of candidates) {
    try { return (guestCache = readFileSync(fileURLToPath(url), "utf8")); } catch { /* try next */ }
  }
  throw new Error("tier2: tier2-guest.js not found (run `npm run build`)");
}

/** The `const APP = {…};` block the guest reads its config + module names from —
 *  storage's app-specific constants, injected the same way the CAP op preamble
 *  is. The seedkernel shell builds the byte-identical block from a bundle
 *  manifest's `config` field. */
export function storageAppPreamble(node: Tier2Host): string {
  const c = node.config;
  const app = {
    k: c.k, m: c.m, blockSize: c.blockSize,
    replicas: c.replicas, lowWater: c.lowWater, smallMaxBlocks: c.smallMaxBlocks,
    // The holder side's byte budget (§14) — the same quota FsBlobStore enforces,
    // surfaced so the confined `handle` path admits exactly as the host store does.
    quota: node.store.stat().quota,
    codecName: toHex(node.names.codec), repName: toHex(node.names.reputation),
  };
  return `const APP = ${JSON.stringify(app)};\n`;
}

/** The full guest source: the generic CAP op catalog + the injected APP config +
 *  the orchestration program. */
export function tier2GuestSource(appPreamble: string, guestSource = guestProgram()): string {
  return capPreamble() + appPreamble + guestSource;
}

/** Build the generic cap-bridge for one StorageNode — kernel primitives only,
 *  no storage vocabulary. codec/reputation are reached as installed handlers via
 *  host.callHandler; net via the Transport (send + requestMany); fs over the
 *  node's raw backend. */
function makeNodeCapBridge(node: Tier2Host) {
  return createCapBridge({
    sodium: node.sodium,
    identity: node.identity,
    callHandler: (name, payload) => node.host.callHandler(name, payload),
    transport: node.transport,
    peers: () => node.cohortPeers(),
    fs: node.fs,
    now: () => node.now(),
  });
}

/** Drives PUT / GET / repair through the confined realm. Holds one realm per
 *  node (the Asyncify module-global state means realms must not overlap host
 *  calls; one node orchestrates sequentially, §2.1). The holder side of the
 *  protocol stays host-side on the StorageNode — only the *initiator's*
 *  orchestration runs in Tier-2. */
export class Tier2Coordinator {
  // The realm *creation promise*, not the settled realm: two concurrent first
  // calls must await one realm. Caching the realm itself (set only after the
  // await) lets both pass the `!this.realm` guard — a second Asyncify realm leaks
  // and the two then overlap host calls, the §2.1 module-global hard-abort.
  private realm: Promise<Tier2Realm> | null = null;
  /** `guestSource` overrides the on-disk guest text — the seam for running the
   *  guest from a loaded bundle rather than the build dir. */
  constructor(private readonly node: Tier2Host, private readonly guestSource?: string) {}

  private realmInstance(): Promise<Tier2Realm> {
    if (!this.realm) {
      this.realm = createTier2Realm({
        source: tier2GuestSource(storageAppPreamble(this.node), this.guestSource),
        bridge: makeNodeCapBridge(this.node),
      });
    }
    return this.realm;
  }

  /** PUT a file (§6), orchestrated inside the realm. */
  async put(plaintext: Uint8Array): Promise<Tier2PutResult> {
    const realm = await this.realmInstance();
    const r = await realm.call("put", plaintext);
    return {
      manifestId: r.slice(0, 32),
      replicated: r[32] === 1,
      chunkCount: readU32BE(r, 33),
      key: r.slice(37, 69),
    };
  }

  /** GET a file (§7), orchestrated inside the realm. */
  async get(manifestId: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    const realm = await this.realmInstance();
    return realm.call("get", concatBytes([manifestId, key]));
  }

  /** Run one repair pass over every chunk this node holds a block of (§9). */
  async repair(): Promise<number> {
    const realm = await this.realmInstance();
    const r = await realm.call("repair", new Uint8Array(0));
    return readU32BE(r, 0);
  }

  dispose(): void {
    const pending = this.realm;
    this.realm = null;
    void pending?.then((r) => r.dispose(), () => { /* creation failed — nothing to free */ });
  }
}

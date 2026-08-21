// Shared types + deployment configuration for the storage layer (README §17).
// The protocol itself is the confined guest (host/tier2-guest.js); StorageNode
// runs it. This module only holds the identity + the durability/overhead dial
// every node agrees on.

export interface Identity {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** The durability/overhead dial, set once per deployment (§4.1, §27). */
export interface StorageConfig {
  k: number;
  m: number;
  blockSize: number;
  /** How many per-holder STORE/FETCH sub-batches a PUT/GET pushes or pulls
   *  concurrently — windows the bulk transfers when a transport's frame cap
   *  splits a holder's blocks across many messages (binds hardest on WebRTC's
   *  ~64 KB channel; a no-op on a large-cap transport like WS). PUT and GET
   *  share one window; never tuned apart in practice. */
  fanoutWindow: number;
  /** Max bytes in one batched OFFER/STORE/FETCH message — split to fit the
   *  transport's frame cap and stay within the request timeout. ~1 MB default;
   *  the browser demo drops it to ~48 KB for WebRTC's ~64 KB channel. */
  maxMessageBytes: number;
  /** Target plaintext bytes per streamed PUT/GET window (§3): the guest heap
   *  never holds the whole file. Bigger windows mean fewer inter-window barriers
   *  but a larger peak footprint (≈3× the window at RS(1,1)). When unset, derived
   *  from realmMemoryBytes (~/3); explicit override wins for benchmarking. */
  windowTargetBytes?: number;
  /** Memory budget for the guest realm's QuickJS heap; windowTargetBytes derives
   *  from it (~/3) when unset. Host-only — passed as THIS BUNDLE's realm bound
   *  (seedkernel §12.3), never shell-wide, so the transport guest doesn't get it. */
  realmMemoryBytes?: number;
  /** Misbehaving-peer test knob: when true, every FETCH answers FETCH_UNANSWERED
   *  for every id, exercising the reader's §18 no-progress invariant. Never set
   *  by a real deployment. */
  lieOnFetch?: boolean;
}

/** Default fan-out window (fanoutWindow): how many per-holder STORE/FETCH
 *  sub-batches are pushed/pulled concurrently. core.ts is the single home of the guest's
 *  config defaults — the confined guest reads the injected APP and keeps no copy of its own. */
export const DEFAULT_FANOUT_WINDOW = 16;

/** Default guest realm memory budget when the operator sets none: 64 MiB.
 *  windowTargetBytes is derived from this (~ /3) unless explicitly overridden. */
export const DEFAULT_REALM_MEMORY_BYTES = 64 * 1024 * 1024;

/** Default target plaintext bytes per streamed PUT/GET window (§3): 4 MiB, used
 *  only when realmMemoryBytes is also unset. An explicit override always wins. */
export const DEFAULT_WINDOW_TARGET_BYTES = 4 * 1024 * 1024;

/** Default committed-tier byte budget (§14) when the operator sets none: 64 MiB.
 *  Quota is operator policy, never signed into a bundle — a driver supplies it at
 *  boot and it's injected into the guest's APP; the holder alone enforces it. */
export const DEFAULT_QUOTA_BYTES = 64 * 1024 * 1024;

/** The block size a real DEPLOYMENT uses — one named constant so "production
 *  geometry" isn't a magic number copied per site. 256 KiB keeps a k=2 codec
 *  request within the deployed codec's proven scratch size. The browser demo
 *  picks its own per-transport size instead and does not use this. */
export const PRODUCTION_BLOCK_SIZE = 256 * 1024;

/** NB the bare blockSize default is TEST-SCALE — 256 bytes, so unit tests exercise
 *  multi-block chunking on tiny payloads. Anything producing a deployed config (the
 *  bundle producer, a demo page) must pass a real block size (PRODUCTION_BLOCK_SIZE);
 *  baking this default into a deployment chunks a 10 MB file into ~41k blocks. */
export function defaultConfig(k = 2, m = 2, blockSize = 256): StorageConfig {
  return {
    k,
    m,
    blockSize,
    fanoutWindow: DEFAULT_FANOUT_WINDOW,
    maxMessageBytes: 1 << 20, // ~1 MiB; a tighter-frame-cap transport (WebRTC) lowers it
    // windowTargetBytes/realmMemoryBytes left unset: derived at boot (see normaliseConfig).
  };
}

/** Every key a StorageConfig may carry, at runtime. Derived from defaultConfig() so
 *  the required set cannot drift from the interface as fields are added; only the
 *  OPTIONAL ones (which a default cannot show) are named here. */
const CONFIG_KEYS: ReadonlySet<string> = new Set([
  ...Object.keys(defaultConfig()), "realmMemoryBytes", "windowTargetBytes", "lieOnFetch",
]);

/** Reject unknown keys in a caller-supplied config (StorageConfig is a closed
 *  set). Worth a runtime check since every driver passing one is plain JS, so
 *  TypeScript's excess-property check never runs and a misspelled knob would
 *  silently no-op. `quota` gets a dedicated message: it's a genuine collision
 *  with a SIBLING option (StorageNodeOptions.quota), deliberately kept out of
 *  StorageConfig so it can never be spread into a signed bundle config. */
export function assertStorageConfig(config?: Partial<StorageConfig>): void {
  if (!config) return;
  for (const key of Object.keys(config)) {
    if (CONFIG_KEYS.has(key)) continue;
    if (key === "quota") {
      throw new Error(
        "StorageConfig has no `quota`: it is operator policy, passed as the sibling option " +
        "`quota` on StorageNode.create({ quota }) — only a seedkernel shell's per-load " +
        "config carries it inline (loadBundleBlob(blob, { localConfig: { quota } })). " +
        "Passing it here would be ignored.",
      );
    }
    throw new Error(
      `StorageConfig has no \`${key}\` — a misspelled knob would be silently ignored. ` +
      `Known keys: ${[...CONFIG_KEYS].sort().join(", ")}.`,
    );
  }
}

/** Normalise a caller-supplied partial config into a canonical shape, deriving
 *  windowTargetBytes from the realm budget when not explicitly set (§3). Called once
 *  at boot by StorageNode.create. Explicit overrides always win for benchmarking. */
export function normaliseConfig(raw: Partial<Record<string, unknown>>): Partial<StorageConfig> {
  const c: Partial<StorageConfig> = { ...raw } as Partial<StorageConfig>;

  // Peak guest heap footprint peaks at ~3× the plaintext window (RS(1,1)), so a
  // third of the realm budget is a safe window when not explicitly overridden.
  if (c.windowTargetBytes == null) {
    const realm = c.realmMemoryBytes ?? DEFAULT_REALM_MEMORY_BYTES;
    c.windowTargetBytes = Math.round(realm / 3);
  }

  return c;
}

/** peer_id is the hex of a peer's channel public key (§2) — the identity the
 *  address book is keyed on. Stated here rather than imported: the kernel's own
 *  alias lives in `core/socket-seam.ts`, not an exported entry. */
export type PeerId = string;

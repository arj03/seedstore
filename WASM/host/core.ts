// Shared types + deployment configuration for the storage layer (SPEC §17).
// The protocol itself is the confined guest (host/tier2-guest.orchestration.js); StorageNode
// runs it. This module only holds the identity + the durability/overhead dial
// every node agrees on.

export interface Identity {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** This app's label — the bundle manifest's `app`, and so the whole of its signing
 *  scope: every node running storage under this label derives the same scope, whoever
 *  authored the bundle. */
export const STORAGE_APP = "seedstore";

// The wire protocol id lives with the wire format the guest is stitched from.
export { STORAGE_PROTO } from "./protocol.js";

/** The service the network is reached through: the one the transport bundle claims, and
 *  so the one storage's bundle requires (scripts/storage-bundle.mjs, which checks it
 *  against seedkernel's transport) and its guest calls (NET_ID). */
export const NET_SERVICE = "_net";

/** The durability/overhead dial, set once per deployment (§4.1, §28). */
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
   *  never holds the whole file. Two windows are in flight at once (one placing
   *  while the next encodes, or one prefetched while the last is read). When unset,
   *  derived from realmMemoryBytes (~/6); explicit override wins for benchmarking. */
  windowTargetBytes?: number;
  /** Memory budget for the guest realm's QuickJS heap; windowTargetBytes derives
   *  from it (~/6) when unset. Host-only — passed as THIS BUNDLE's realm bound
   *  (seedkernel §12.3), never shell-wide, so the transport guest doesn't get it. */
  realmMemoryBytes?: number;
  /** How long a holder that passed a verification-fetch keeps counting as live for
   *  the blocks it advertises (§8). A repair audit re-checks holders past it, and
   *  samples a couple of the rest. */
  verifyFreshMs?: number;
  /** The latency bound on a verification-fetch (§8): a correct block answered later
   *  than this fails the check, since a holder regenerating it on demand needs k
   *  round trips and a decode where a stored block needs one disk read. */
  verifyDeadlineMs?: number;
  /** The share of quota an author this holder has no standing with may fill with its
   *  own placements (§13.2). Positive standing lifts it to the whole quota, negative
   *  drops it to nothing. 1 turns the allowance off, e.g. among one person's devices. */
  newcomerShare?: number;
}

/** Default fan-out window (fanoutWindow): how many per-holder STORE/FETCH
 *  sub-batches are pushed/pulled concurrently. core.ts is the single home of the guest's
 *  config defaults — the confined guest reads the injected APP and keeps no copy of its own. */
export const DEFAULT_FANOUT_WINDOW = 16;

/** Default guest realm memory budget when the operator sets none: 64 MiB.
 *  windowTargetBytes is derived from this (~ /6) unless explicitly overridden. */
export const DEFAULT_REALM_MEMORY_BYTES = 64 * 1024 * 1024;

/** Default committed-tier byte budget (§14) when the operator sets none: 64 MiB.
 *  Quota is operator policy, never signed into a bundle — a driver supplies it at
 *  boot and it's injected into the guest's LOCAL; the holder alone enforces it. */
export const DEFAULT_QUOTA_BYTES = 64 * 1024 * 1024;

/** Defaults for the §8 verification knobs and the §13.2 newcomer allowance. */
export const DEFAULT_VERIFY_FRESH_MS = 15 * 60 * 1000;
export const DEFAULT_VERIFY_DEADLINE_MS = 2000;
export const DEFAULT_NEWCOMER_SHARE = 0.5;

/** The block size a real DEPLOYMENT uses — one named constant so "production
 *  geometry" isn't a magic number copied per site. 256 KiB keeps a k=2 codec
 *  request within the deployed codec's proven scratch size. The browser demo
 *  picks its own per-transport size instead and does not use this. */
export const PRODUCTION_BLOCK_SIZE = 256 * 1024;

/** The block size TESTS use — small enough that a few-kB payload still exercises
 *  multi-block chunking, a real RS encode/decode and an index level, which is the
 *  cheapest coverage there is. Named for the same reason the production size is, so
 *  the two geometries are told apart at a glance rather than by magnitude. */
export const TEST_BLOCK_SIZE = 256;

/** `blockSize` is REQUIRED, and leads because of it: it is the one field whose wrong
 *  value is catastrophic rather than merely suboptimal — test geometry in a deployed
 *  config chunks a 10 MB file into ~41k blocks — so it must not be reachable by
 *  omission. Every caller names the geometry it means (PRODUCTION_BLOCK_SIZE or
 *  TEST_BLOCK_SIZE) and forgetting is a type error. `k`/`m` keep defaults because
 *  either value only trades redundancy against cost. */
export function defaultConfig(blockSize: number, k = 2, m = 2): StorageConfig {
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
 *  OPTIONAL ones (which a default cannot show) are named here. The geometry passed
 *  in is immaterial — only the KEYS of the result are read. */
const CONFIG_KEYS: ReadonlySet<string> = new Set([
  ...Object.keys(defaultConfig(TEST_BLOCK_SIZE)), "realmMemoryBytes", "windowTargetBytes",
  "verifyFreshMs", "verifyDeadlineMs", "newcomerShare",
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
    if (key === "groups") {
      throw new Error("StorageConfig has no `groups`: the roster is operator policy, passed as the sibling " +
        "option `groups` on StorageNode.create({ groups }), or set later with setGroups.");
    }
    if (key === "quota") {
      throw new Error(
        "StorageConfig has no `quota`: it is operator policy, passed as the sibling option " +
        "`quota` on StorageNode.create({ quota }) — only a seedkernel shell's per-load " +
        "config carries it inline (install(blob, { localConfig: { quota } })). " +
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
 *  at boot by StorageNode.create, and by the bundle author for the config it signs.
 *  Explicit overrides always win for benchmarking. */
export function normaliseConfig(raw: Partial<Record<string, unknown>>): Partial<StorageConfig> {
  const c: Partial<StorageConfig> = { ...raw } as Partial<StorageConfig>;

  // A PUT holds one window's blocks placing while the next window's plaintext and blocks
  // encode, with the STORE frames the host-call budget admits on top. Measured on a slow
  // link, a 64 MiB realm peaks at ~56 MiB with a sixth-sized window.
  if (c.windowTargetBytes == null) {
    const realm = c.realmMemoryBytes ?? DEFAULT_REALM_MEMORY_BYTES;
    c.windowTargetBytes = Math.round(realm / 6);
  }
  if (c.verifyFreshMs == null) c.verifyFreshMs = DEFAULT_VERIFY_FRESH_MS;
  if (c.verifyDeadlineMs == null) c.verifyDeadlineMs = DEFAULT_VERIFY_DEADLINE_MS;
  if (c.newcomerShare == null) c.newcomerShare = DEFAULT_NEWCOMER_SHARE;
  if (!(c.newcomerShare >= 0 && c.newcomerShare <= 1)) throw new Error("config: newcomerShare must lie in [0, 1]");

  return c;
}

/** peer_id is the hex of a peer's channel public key (§2) — the identity the
 *  address book is keyed on. Stated here rather than imported: seedkernel's own
 *  alias lives in `services/socket-seam.ts`, not an exported entry. */
export type PeerId = string;

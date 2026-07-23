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
  /** How many per-holder STORE sub-batches a PUT pushes concurrently (and per-holder
 *  FETCH sub-batches a GET pulls). OFFER/STORE/FETCH are batched per holder, so the
 *  round-trip count no longer scales with the file; this windows the bulk transfers
 *  when a transport's frame cap splits a holder's blocks across many messages. The
 *  window binds hardest under a small cap (WebRTC's ~64 KB channel forces ~one
 *  block per STORE/FETCH): without it those messages would go one serial round
 *  trip per block. Under a large cap (WS) each holder has only a few big batches,
 *  so it is a no-op. With the genuinely-async guest seam the guest overlaps the
 *  round trips itself — one Promise.all over NET_SEND fires W per-peer requests at
 *  once (the host driving them concurrently) — so W bounds the peak in flight.
 *  PUT and GET share one window: they have never been tuned apart in practice. */
  fanoutWindow: number;
  /** Max bytes in one batched OFFER/STORE/FETCH message. Every per-holder batch is
   *  split to stay under it, so a single message both fits the transport's frame cap
   *  AND transfers within the request timeout — and the holder (synchronous in the
   *  confined realm) only ever hashes/admits/serves one capped batch at a time. Set
   *  per transport: a WS/TCP frame holds up to 16 MB, but a multi-MB transfer can
   *  outrun a tight request timeout, so the default stays ~1 MB; a WebRTC data
   *  channel reassembles only ~64 KB, so the browser demo drops it to ~48 KB. (The
   *  browser picks the value from the connection mode.) */
  maxMessageBytes: number;
  /** Target plaintext bytes per streamed PUT/GET window (§3). The host driver feeds
   *  the guest one chunk-aligned window at a time and awaits it fully — OFFER, STORE,
   *  and acks — before the next, so the whole window's ciphertext is dropped before
   *  more plaintext crosses in and the guest heap never holds the file. Bigger windows
   *  mean fewer inter-window barriers (less link idle on a fat/low-loss path) but a
   *  larger peak guest footprint (≈ n/k× the window in ciphertext, peaking at ~3× the
   *  plaintext window at RS(1,1)). When unset the host derives it from realmMemoryBytes
   *  (≈ realmMemoryBytes / 3, rounding to the nearest chunk-aligned multiple); explicit
   *  override stays for benchmarking. The confined guest reads it from the injected APP
   *  and never keeps its own copy. */
  windowTargetBytes?: number;
  /** Memory budget for the guest realm's QuickJS heap. The host derives
   *  windowTargetBytes from it (~realmMemoryBytes / 3, since peak heap footprint is
   *  ≈ 3× the plaintext window at RS(1,1)), so the two real flow-control knobs are
   *  this (the memory number) and maxMessageBytes (the transport number). Host-only
   *  (passed to createSafeRealm, not injected into the guest APP). Default 64 MiB
   *  (the safe-js default). */
  realmMemoryBytes?: number;
}

/** Default fan-out window (fanoutWindow): how many per-holder STORE/FETCH
 *  sub-batches are pushed/pulled concurrently. core.ts is the single home of the guest's
 *  config defaults — the confined guest reads the injected APP and keeps no copy of its own. */
export const DEFAULT_FANOUT_WINDOW = 16;

/** Default guest realm memory budget when the operator sets none: 64 MiB.
 *  windowTargetBytes is derived from this (~ /3) unless explicitly overridden. */
export const DEFAULT_REALM_MEMORY_BYTES = 64 * 1024 * 1024;

/** Default target plaintext bytes per streamed PUT/GET window (§3): 4 MiB. The legacy
 *  conservative default; when realmMemoryBytes is set (explicitly or via the 64 MiB
 *  DEFAULT_REALM_MEMORY_BYTES) the host derives windowTargetBytes from it (~ /3) instead.
 *  The explicit override — set directly via cmdline or benchmark config — always wins. */
export const DEFAULT_WINDOW_TARGET_BYTES = 4 * 1024 * 1024;

/** Default committed-tier byte budget (§14) when the operator sets none: 64 MiB.
 *  Quota is OPERATOR policy, not author content, so it is not part of StorageConfig
 *  and is never signed into a bundle: a driver supplies it at boot (StorageNode's
 *  `quota` option, a shell's boot config) and it is injected into the guest's APP.
 *  The confined holder is the only thing that ENFORCES it — this is just the number
 *  a host-side node injects when its operator named none. A driver that injects
 *  nothing leaves the guest to fail closed at 0 rather than guess a generous default. */
export const DEFAULT_QUOTA_BYTES = 64 * 1024 * 1024;

/** The block size a real DEPLOYMENT uses — the single value the signed bundle and the
 *  CLI derive their geometry from, so "production geometry" is one named constant, not a
 *  magic number copied per site. 256 KiB keeps a k=2 codec request at the 512 KiB the
 *  deployed codec's scratch is proven on, and one block + framing well inside the default
 *  maxMessageBytes (the serveFetch response bound). The browser demo deliberately picks a
 *  per-transport size instead (bigger on WS, tiny on WebRTC's ~64 KiB channel), so it does
 *  NOT consume this — but see it referenced there for why those diverge. */
export const PRODUCTION_BLOCK_SIZE = 256 * 1024;

/** NB the bare blockSize default is TEST-SCALE — 256 bytes, so unit tests exercise
 *  multi-block chunking on tiny payloads. Anything producing a deployed config (the
 *  bundle producer, a demo page) must pass a real block size (PRODUCTION_BLOCK_SIZE);
 *  baking this default into a deployment chunks a 10 MB file into ~41k blocks. */
export function defaultConfig(k = 2, m = 2, blockSize = 256): StorageConfig {
  // (k, m, blockSize) is the whole of the durability dial. Everything derivable from it
  // is derived where it is used and never carried here, so it cannot drift out of step:
  // smallMaxBlocks in the guest (a write-side choice, §4.1), and the replica count
  // r = m + 1 plus the low-water mark ⌈m/2⌉ from each chunk's own SIGNED descriptor
  // (manifest-core's replicaTarget / lowWaterMargin), so a repairer needs no config
  // at all and a mixed-geometry cohort repairs each chunk to what its author signed.
  return {
    k,
    m,
    blockSize,
    fanoutWindow: DEFAULT_FANOUT_WINDOW,
    // ~1 MiB: a batch transfers well inside a typical request timeout and keeps a
    // synchronous holder's per-message work small, while still collapsing per-block
    // round trips. A transport with a tighter frame cap (WebRTC) lowers it.
    maxMessageBytes: 1 << 20,
    // windowTargetBytes and realmMemoryBytes are both unset here — the two real
    // flow-control knobs. When omitted the host derives windowTargetBytes from
    // realmMemoryBytes (≈ /3, peak guest footprint ratio), and when both are
    // omitted the host applies DEFAULT_WINDOW_TARGET_BYTES as a safe floor.
  };
}

/** Every key a StorageConfig may carry, at runtime. Derived from defaultConfig() so
 *  the required set cannot drift from the interface as fields are added; only the
 *  OPTIONAL ones (which a default cannot show) are named here. */
const CONFIG_KEYS: ReadonlySet<string> = new Set([
  ...Object.keys(defaultConfig()), "realmMemoryBytes", "windowTargetBytes",
]);

/** Reject unknown keys in a caller-supplied config (StorageConfig is a closed set).
 *
 *  Worth a runtime check because every driver that passes one is plain JS — the tests,
 *  the CLI scripts, the browser demo — so TypeScript's excess-property check never runs
 *  and a misspelled knob is silently ignored: the node runs on the default and the caller
 *  is never told their setting did nothing. That failure is invisible in exactly the way
 *  a tuning knob must not be (a wrong fanoutWindow reads as a perf result, not a bug).
 *
 *  `quota` is called out by name because it is not a typo but a genuine collision: it IS
 *  operator policy, spelled inside the opaque boot `config` a seedkernel shell takes — but
 *  here it is a SIBLING option (StorageNodeOptions.quota), deliberately outside
 *  StorageConfig so it can never be spread into an author-signed bundle config
 *  (scripts/storage-bundle.mjs). Drivers that stand up shells and StorageNodes side by
 *  side (tests/holder-guest.test.mjs) do have both spellings in view at once. */
export function assertStorageConfig(config?: Partial<StorageConfig>): void {
  if (!config) return;
  for (const key of Object.keys(config)) {
    if (CONFIG_KEYS.has(key)) continue;
    if (key === "quota") {
      throw new Error(
        "StorageConfig has no `quota`: it is operator policy, passed as the sibling option " +
        "`quota` on StorageNode.create({ quota }) — only a seedkernel shell's boot config " +
        "carries it inline (boot({ config: { quota } })). Passing it here would be ignored.",
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

  // Derive windowTargetBytes from realmMemoryBytes when not explicitly set. Peak guest
  // heap footprint is ≈ n/k× the window in ciphertext, peaking at ~3× the plaintext
  // window at RS(1,1), so a third of the realm budget is a safe window. The caller can
  // always pass an explicit windowTargetBytes (or --wtarget) for benchmarking.
  if (c.windowTargetBytes == null) {
    const realm = c.realmMemoryBytes ?? DEFAULT_REALM_MEMORY_BYTES;
    c.windowTargetBytes = Math.round(realm / 3);
  }

  return c;
}

/** peer_id is the hex of a peer's kernel public key (§2). */
export { type PeerId } from "seedkernel-wasm/net";

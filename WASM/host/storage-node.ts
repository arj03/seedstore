// StorageNode — a single storage peer running *on* the seedkernel (README §19
// bootstrap). It is now a THIN host: the entire storage protocol lives in the
// confined guest (host/tier2-guest.js), run inside ONE seedkernel safe-js realm
// over the generic capability bridge. StorageNode stands up the shared
// platform-neutral `createShell()` from seedkernel (the §12.9 move) and loads the
// signed bundles — the ONE install path (§12.4): first the kernel-shipped
// **transport bundle** (the signed program that IS the node's network, §12.6),
// then the seedstore bundle.
//
// The raw-bind `host.installWasmHandler` path is gone: handlers arrive via the
// verified bundle loader, under the admission policy, and the kernel names are
// derived from the manifest author — exactly as a shell-run node does it. The
// `ZERO_AUTHOR` default is gone: the signing scope comes from the bundle's
// verified author.
//
// StorageNode only:
//   - creates the platform seam (fs, channels/socket seam, freshnessStore,
//     identity, sodium) and loads the transport bundle through the shared shell
//   - calls createShell() + loadBundleBlob() to wire the shared shell
//   - runs the guest's *initiator* entrypoints (put / get / repair) via
//     shell.runGuest()
//   - serves the guest's *holder* entrypoint via shell.serve()
//
// A caller that already stands a shell up (a WebRTC/WS node, whose socket seam is
// a host-managed transport handing channels to the driver's openLink) passes that
// shell in with `shell`; StorageNode then loads only the seedstore bundle on it.

import type { PeerId } from "seedkernel-wasm/net";
import type { Fs } from "seedkernel-wasm/fs";
import { MemoryFs, scopedFs } from "seedkernel-wasm/fs";
import { TransportHost } from "seedkernel-wasm/transport-host";
import { TRANSPORT_BUNDLE_B64 } from "seedkernel-wasm/transport-bundle";
import { FsBlobView, type BlobView } from "./store-view.js";
import { Crypto } from "./crypto.js";
import {
  type Identity, type StorageConfig, defaultConfig, assertStorageConfig, normaliseConfig, DEFAULT_QUOTA_BYTES,
} from "./core.js";
import { STORAGE_APP, storageSignScope } from "./manifest.js";
import { encodeScoreReq } from "./reputation-core.js";
import { toHex, readU32BE, readU64BE, writeU64BE, concatBytes } from "./util.js";
import {
  createShell, KernelHost, type Shell, type KernelTable, type RealmFactory,
} from "seedkernel-wasm/shell-core";
import { FreshnessMarks, kernelNameFor, appScopeFor, verifyBundle, type LoadedBundle } from "seedkernel-wasm/bundle";
import type { HostTransport } from "seedkernel-wasm/transport-host";
import type { ChannelFactoryLike } from "./loopback.js";
import type { Sodium } from "./sodium.js";

const NO_ARG = new Uint8Array(0);

function u64be(n: number): Uint8Array { const b = new Uint8Array(8); writeU64BE(b, 0, n); return b; }

const createRealm: RealmFactory = async (o) => (await import("seedkernel-wasm/safe-js")).createSafeRealm(o);

/** The kernel-shipped transport bundle, as raw bytes (seedkernel §12.6): the
 *  channel AKE, the record layer, link routing and the request/response layer
 *  run as a confined guest program, signed into a `role: "transport"` bundle and
 *  embedded in the host. Admitting it below stands the shell's transport driver
 *  up; the storage bundle is an ordinary app on top of it. */
function transportBlob(): Uint8Array {
  const bin = atob(TRANSPORT_BUNDLE_B64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Decode the guest's PUT result — the single result format every driver reads
 *  (`encodePutResult` in tier2-guest.orchestration.js). */
function decodePutResult(r: Uint8Array): PutResult {
  const blockIds: Uint8Array[] = [];
  const idCount = readU32BE(r, 76);
  for (let i = 0; i < idCount; i++) blockIds.push(r.slice(80 + i * 32, 80 + (i + 1) * 32));
  return {
    manifestId: r.slice(0, 32),
    chunkCount: readU32BE(r, 32),
    key: r.slice(36, 68),
    replicasLanded: readU32BE(r, 68),
    replicasIntended: readU32BE(r, 72),
    blockIds,
  };
}

export interface PutResult {
  manifestId: Uint8Array;
  key: Uint8Array;
  chunkCount: number;
  blockIds: Uint8Array[];
  replicasLanded: number;
  replicasIntended: number;
}

export interface StorageNodeOptions {
  /** A pre-built seedkernel shell with the transport bundle already admitted and
   *  its driver started (a WebRTC/WS node — the socket seam is host-managed, so
   *  the driver is standing and the RTC/WS network hands it channels). Absent,
   *  StorageNode builds its own shell from `channels`/`listen` below. */
  shell?: Shell;
  sodium: Sodium;
  /** The signed seedstore bundle blob (seedstore.skb). The ONE install path:
   *   the shared shell loads it through the §12.4 bundle loader — verify
   *   manifest, govern policy, integrity-check modules, install handlers —
   *   exactly as a shell-run node does. Handlers are NOT raw-bound. */
  bundleBlob: Uint8Array;
  identity?: Identity;
  config?: Partial<StorageConfig>;
  fs?: Fs;
  store?: BlobView;
  quota?: number;
  clock?: () => number;
  timeoutMs?: number;
  /** The socket seam the transport driver dials and listens through (seedkernel
   *  §12.6). A shared in-process fabric for tests/demos; a NodeChannelFactory for
   *  real TCP. Absent for a host-managed-transport-only node (WebRTC/browser WS),
   *  which hands channels to the driver's openLink instead. */
  channels?: ChannelFactoryLike;
  listen?: { host: string; port: number };
  wsListen?: { host: string; port: number };
  /** Optional deployment secret — the gate a caller must produce before this
   *  node's inbound side opens (seedkernel §12.6.3). */
  contactSecret?: Uint8Array;
  /** Optional network key — which network this node belongs to (an isolation
   *  boundary, not a gate; §12.6). Absent ⇒ the public network. */
  networkKey?: Uint8Array;
  /** Optional whitelist gate for the transport slot, called with a
   *  signature-verified peer key during the handshake. Absent ⇒ admit all. */
  admitPeer?: (pk: Uint8Array) => boolean;
  /** Parallel connections per dialed peer (default 1) — the transport's dial
   *  fan-out. */
  connsPerPeer?: number;
  /** The signed transport bundle blob. Defaults to the one shipped in the
   *  seedkernel artifact; an operator who pins a different transport author
   *  builds their own. Only read when StorageNode builds its own shell. */
  transportBlob?: Uint8Array;
  /** Override the cohort's signing scope author: sign descriptors under this
   *  author instead of the loaded bundle's (used when joining a cohort whose
   *  holders run a DIFFERENT bundle's author — the browser demo's override). */
  signAuthor?: Uint8Array;
}

export class StorageNode {
  readonly peerId: PeerId;
  readonly identity: Identity;
  /** The transport driver — the node's Network (shell.net). The transport is a
   *  signed bundle; this is its host-side face. */
  readonly net: TransportHost;
  /** The request/response face of the same driver. */
  readonly transport: HostTransport;
  readonly fs: Fs;
  readonly store: BlobView;
  readonly quota: number;
  readonly crypto: Crypto;
  readonly sodium: Sodium;
  readonly config: StorageConfig;
  /** The handler table, exposed through KernelTable (callHandler + isBound)
   *   without installWasmHandler — the bind is solely the bundle loader's job. */
  readonly host: KernelTable;

  private readonly shell: Shell;
  private readonly clockFn: () => number;
  private readonly signAuthor: Uint8Array;
  /** The cohort's signing scope (§16), derived from the verified bundle author.
   *   Exposed so host-side callers can produce descriptors that the guest's
   *   holder path will verify — signDescriptor() with this scope as the 5th
   *   argument matches what the guest's verifyPrefix checks. */
  readonly signScope: Uint8Array;
  /** This app's fs keyspace prefix (seedkernel §12.2). Every key the holder writes is
   *   `appScope + key` on the raw backend, so tooling that opens a node's directory
   *   *cold* — outside a running node, where `this.fs` is already scoped — has to wrap
   *   the backend in `scopedFs(raw, appScope)` to see the same blocks. Without it a
   *   read view finds nothing at all: FsBlobView drops any key whose hex is not 64
   *   chars, so a prefixed key is skipped rather than misread. */
  readonly appScope: string;
  private readonly modules: { codec: string; reputation: string };
  /** Durable cohort roster: the set of peers this node has a storage relationship
   *   with. The network owns connectivity; the cohort is app state — independent
   *   of who is currently online — and feeds the guest's NET_PEERS cap. */
  readonly cohort: Set<PeerId>;
  private repairLoopOn = false;
  private repairTimer: ReturnType<typeof setTimeout> | null = null;
  private inFlight: Promise<unknown> = Promise.resolve();
  private closed = false;
  private readonly ownsShell: boolean;

  private constructor(
    opts: StorageNodeOptions,
    shell: Shell,
    identity: Identity,
    loaded: LoadedBundle,
    cohort: Set<PeerId>,
    ownsShell: boolean,
  ) {
    this.sodium = opts.sodium;
    this.shell = shell;
    this.host = shell.host;
    this.identity = identity;
    this.peerId = toHex(identity.publicKey);
    this.fs = opts.fs ?? new MemoryFs();
    this.quota = opts.quota ?? DEFAULT_QUOTA_BYTES;
    this.store = opts.store ?? new FsBlobView(this.fs);
    this.clockFn = opts.clock ?? (() => Date.now());
    this.crypto = new Crypto(opts.sodium);
    this.net = shell.net as unknown as TransportHost;
    this.transport = shell.transport;
    this.cohort = cohort;
    this.ownsShell = ownsShell;

    // Derive signing scope and kernel names from the verified bundle author —
    // the same derivation a shell-run node uses. `signAuthor` lets a caller join
    // a cohort whose holders run a DIFFERENT bundle's author (descriptors are
    // scoped to the deployment, §16); the fs keyspace and kernel names stay the
    // loaded bundle's.
    this.signAuthor = opts.signAuthor ?? loaded.author;
    this.signScope = storageSignScope(this.signAuthor);
    this.appScope = appScopeFor(opts.sodium, loaded.author, STORAGE_APP);
    this.modules = {
      codec: kernelNameFor(loaded.author, STORAGE_APP, "codec"),
      reputation: kernelNameFor(loaded.author, STORAGE_APP, "reputation"),
    };

    // `this.config` is the geometry a caller can inspect (p2p-cli reads config.k/.m for
    // its wire estimate), so it must equal what the guest ACTUALLY runs: the bundle's
    // signed guest.config with the operator override merged OVER it — the same precedence
    // shell-core applies when it builds the guest APP. Reconstructing from defaultConfig()
    // alone would only agree when the override happened to name every field. guest.config
    // is untyped JSON (Record<string,string|number>), so coerce it to the config shape at
    // this boundary — the bundle producer writes the numeric geometry.
    const override = normaliseConfig(opts.config ?? {});
    assertStorageConfig(override);
    const signed = (loaded.manifest.guest?.config ?? {}) as unknown as Partial<StorageConfig>;
    const merged: Partial<StorageConfig> = { ...signed, ...override };
    this.config = { ...defaultConfig(merged.k, merged.m, merged.blockSize), ...merged };
  }

  /** Boot a storage node: stand up the shared shell (or take the caller's), load
   *   the transport bundle (unless a shell was handed in), load the signed
   *   seedstore bundle, and wire the holder realm. The raw-bind install path is
   *   gone — handlers arrive solely via the §12.4 bundle loader. */
  static async create(opts: StorageNodeOptions): Promise<StorageNode> {
    await opts.sodium.ready;

    const identity = opts.identity ?? (() => {
      const kp = opts.sodium.crypto_sign_keypair();
      return { publicKey: kp.publicKey, privateKey: kp.privateKey };
    })();

    const cohort = new Set<PeerId>();

    // The shell to load the storage bundle onto: the caller's (its transport
    // bundle is already admitted and its driver standing — the RTC/WS path) or
    // one built here from the socket seam below. The fs instance the shell was
    // built with comes back too, so the host read view and the guest's writes
    // share ONE backend.
    const ownsShell = opts.shell === undefined;
    const built = opts.shell ? null : await buildShell(opts, identity, cohort);
    const shell = opts.shell ?? built!.shell;
    // The fs the shell was built with — the guest's writes land there. A caller's own
    // fs wins; a pre-built shell brings its own (bootTransportShell created it).
    const fs = opts.fs ?? (opts.shell?.fs ?? built!.fs) ?? new MemoryFs();

    const loaded = await shell.loadBundleBlob(opts.bundleBlob);
    await shell.serve();

    // The guest does NOT reach the backend directly: the shell hands it
    // `scopedFs(fs, appScopeFor(author, app))`, so every key the holder writes lands
    // under this app's opaque prefix (seedkernel §12.2). The host's read view has to
    // enter through the same door, or `store.list()` walks past the guest's writes and
    // reads back scope-prefixed keys as if they were block ids. One keyspace per app,
    // one handle to it — the scope is derived here rather than passed in because it
    // depends on the *verified* bundle author, which only exists after the load above.
    const appFs = scopedFs(fs, appScopeFor(opts.sodium, loaded.author, STORAGE_APP));
    const withFs = { ...opts, fs: appFs }; // share the one fs instance with the constructor below

    return new StorageNode(withFs, shell, identity, loaded, cohort, ownsShell);
  }

  // ── cohort membership (§5.1) ───────────────────────────────────────────
  now(): number { return this.clockFn(); }
  cohortPeers(): PeerId[] { return [...this.cohort]; }

  addPeer(peerId: PeerId): void {
    this.cohort.add(peerId);
  }
  removePeer(peerId: PeerId): void {
    this.cohort.delete(peerId);
  }

  /** Connect two nodes into one cohort: add each to the other's cohort set AND
   *  teach each driver the other's address, then dial (the transport's `ready`
   *  fires the handshake and resolves once every known peer authenticated or its
   *  deadline passed). Async — links must be up before PUT/GET reach the peer. */
  static async connect(a: StorageNode, b: StorageNode): Promise<void> {
    a.addPeer(b.peerId);
    b.addPeer(a.peerId);
    a.net.addPeerAddr(b.peerId, { host: "127.0.0.1", port: b.net.port, transport: "tcp" });
    b.net.addPeerAddr(a.peerId, { host: "127.0.0.1", port: a.net.port, transport: "tcp" });
    await Promise.all([a.net.ready(), b.net.ready()]);
  }

  // ── PUT / GET / repair / share — all run through shell.runGuest() ──────
  private runExclusive<T>(body: () => Promise<T>): Promise<T> {
    if (this.closed) return Promise.reject(new Error("storage node closed"));
    const p = this.inFlight.then(body);
    this.inFlight = p.then(() => {}, () => {});
    return p;
  }

  /** PUT a file (§6), orchestrated in the guest, STREAMED. */
  async put(plaintext: Uint8Array): Promise<PutResult> {
    return this.runExclusive(async () => {
      const meta = await this.shell.runGuest("putStart", u64be(plaintext.length));
      const windowBytes = readU32BE(meta, 0);
      for (let off = 0; ; off += windowBytes) {
        await this.shell.runGuest("putWindow", plaintext.subarray(off, Math.min(off + windowBytes, plaintext.length)));
        if (off + windowBytes >= plaintext.length) break;
      }
      return decodePutResult(await this.shell.runGuest("putFinish", NO_ARG));
    });
  }

  /** GET a file (§7), orchestrated in the guest, STREAMED. */
  async get(manifestId: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    return this.runExclusive(async () => {
      const fileSize = readU64BE(await this.shell.runGuest("getStart", concatBytes([manifestId, key])), 0);
      const out = new Uint8Array(fileSize);
      let written = 0;
      while (written < fileSize) {
        const part = await this.shell.runGuest("getNext", NO_ARG);
        if (part.length === 0) throw new Error(`get: stream ended ${written}/${fileSize} bytes in`);
        out.set(part, written); written += part.length;
      }
      return out;
    });
  }

  /** Pre-warm the realm's codec + crypto caps. */
  async warm(): Promise<void> {
    await this.runExclusive(() => this.shell.runGuest("warm", NO_ARG));
  }

  /** Run one repair pass over every chunk this node holds a block of (§9). */
  async runRepair(): Promise<number> {
    return readU32BE(await this.runExclusive(() => this.shell.runGuest("repair", NO_ARG)), 0);
  }

  /** Decayed reciprocity score this node holds for a peer (§13). */
  score(peerPk: Uint8Array): number {
    const res = this.host.callHandler(this.modules.reputation, encodeScoreReq(peerPk, this.now()));
    if (!res || res.length < 8) return 0;
    return new DataView(res.buffer, res.byteOffset, 8).getFloat64(0, true);
  }

  /** Share a file: seal K to a recipient's kernel key (§4.4). */
  shareKey(K: Uint8Array, recipientPk: Uint8Array): Uint8Array { return this.crypto.seal(K, recipientPk); }
  /** Open a sealed K addressed to this node. */
  openKey(sealed: Uint8Array): Uint8Array | null {
    return this.crypto.sealOpen(sealed, this.identity.publicKey, this.identity.privateKey);
  }

  // ── repair loop (§9) ──────────────────────────────────────────────────
  startRepairLoop(opts: { intervalMs?: number; jitter?: number; onPass?: (replaced: number) => void } = {}): void {
    if (this.repairLoopOn) return;
    this.repairLoopOn = true;
    const intervalMs = opts.intervalMs ?? 30_000;
    const jitter = opts.jitter ?? 0.5;
    const arm = () => {
      this.repairTimer = setTimeout(tick, intervalMs * (1 + Math.random() * jitter));
      (this.repairTimer as { unref?: () => void }).unref?.();
    };
    const tick = async () => {
      let replaced = 0;
      try { replaced = await this.runRepair(); }
      catch { /* transient pass failure — next tick retries */ }
      if (!this.repairLoopOn) return;
      opts.onPass?.(replaced);
      arm();
    };
    arm();
  }

  stopRepairLoop(): void {
    this.repairLoopOn = false;
    if (this.repairTimer) { clearTimeout(this.repairTimer); this.repairTimer = null; }
  }

  close(): void {
    // Reject any initiator operation raised after this cleanly (runExclusive checks
    // `closed`) rather than letting it reach a torn-down realm. shell.close() closes the
    // transport so any parked round trip settles, then defers realm disposal until its
    // in-flight chain drains — so a repair pass caught mid-await here is never resumed
    // into a freed realm (a QuickJS use-after-free). An in-flight stream keeps running.
    this.closed = true;
    this.stopRepairLoop();
    this.shell.close();
  }

  /** True if both pure handlers are installed on the kernel (§19). */
  handlersInstalled(): boolean {
    return this.host.isBound(this.modules.codec) && this.host.isBound(this.modules.reputation);
  }
}

/** Build the shell a StorageNode loads its bundles onto: the platform seam (fs,
 *  the socket seam, the realm factory) + the transport bundle admitted first —
 *  the node's network — with the driver's listeners started. Returns the shell
 *  AND the fs instance it was built with (a caller with no fs of its own must
 *  read the same backend the guest writes). */
export async function bootTransportShell(
  opts: {
    sodium: Sodium; identity: Identity;
    fs?: Fs; channels?: ChannelFactoryLike;
    listen?: { host: string; port: number };
    wsListen?: { host: string; port: number };
    networkKey?: Uint8Array; contactSecret?: Uint8Array;
    admitPeer?: (pk: Uint8Array) => boolean; connsPerPeer?: number;
    timeoutMs?: number; transportBlob?: Uint8Array;
    livePeers?: () => PeerId[];
    createRealm?: RealmFactory;
    /** Operator app config (quota, geometry overrides) merged over the bundle's
     *  signed guest.config into the guest's APP — opaque to the shell. */
    config?: Record<string, string | number>;
    /** Operator quota — injected into the guest APP, never author-signed. */
    quota?: number;
    /** QuickJS heap limit for the guest realm, in bytes. */
    realmMemoryBytes?: number;
    now?: () => number;
  },
): Promise<{ shell: Shell; fs: Fs }> {
  const fs = opts.fs ?? new MemoryFs();

  // The transport slot is author-pinned to the artifact's own author (derived
  // from the blob, never restated): the operator handing us the storage bundle is
  // the trust decision for THAT; the transport bundle is the kernel's, and no
  // other transport-role bundle may claim the slot on this node.
  const blob = opts.transportBlob ?? transportBlob();
  const transportAuthorHex = toHex(verifyBundle(opts.sodium, blob).author);

  const shell = createShell({
    platform: {
      sodium: opts.sodium,
      identity: opts.identity,
      kernel: new KernelHost(),
      fs,
      freshnessStore: new FreshnessMarks(),
      channels: opts.channels,
      listen: opts.listen,
      wsListen: opts.wsListen,
      networkKey: opts.networkKey,
      contactSecret: opts.contactSecret,
      admitPeer: opts.admitPeer,
      connsPerPeer: opts.connsPerPeer,
      createRealm: opts.createRealm ?? createRealm,
      now: opts.now,
      // LEAVE IT UNSET when the caller has none: `livePeers` feeds the guest's
      // NET_PEERS cap, and the shell's own default for an absent one is the
      // transport's `linkedPeers()` — the authenticated links, which is what a
      // caller that tracks no roster of its own means. Defaulting to `() => []`
      // here instead spelled "this node never has peers", and because it is a
      // *present* closure it shadowed the shell's fallback rather than deferring
      // to it. That is silent and total: the guest sees an empty cohort, PUT
      // sends no OFFER at all, and the failure surfaces as "landed 0/N distinct
      // blocks — holders declined" with no holder verdict behind it, pointing at
      // quota or §16 scope on peers that were never contacted. Every in-repo
      // caller passed one (buildShell passes the cohort, p2p-cli its link set),
      // so only an external embedder — browser/p2p.html — ever hit it.
      ...(opts.livePeers ? { livePeers: opts.livePeers } : {}),
    },
    // The transport bundle is admitted by author pin; an app bundle is admitted
    // because its operator handed it to us — the choice of bundle is the trust
    // decision, so there is no author allow-list to clear (the manifest signature
    // + module hashes are still verified by loadBundleBlob).
    admit: (v) => (v.manifest.role === "transport"
      ? toHex(v.author) === transportAuthorHex
      : true),
    timeoutMs: opts.timeoutMs,
    config: { ...(opts.config ?? {}), ...(opts.quota != null ? { quota: opts.quota } : {}) },
    realmMemoryBytes: opts.realmMemoryBytes,
  });

  // Load the transport bundle: the node's network (phase 3). This stands the
  // driver up over the socket seam; the listeners bind below.
  await shell.loadBundleBlob(blob);
  const driver = shell.net as unknown as TransportHost;
  await driver.start();

  return { shell, fs };
}

/** Build the shell a StorageNode loads its bundles onto — the socket seam,
 *  the realm factory, the transport bundle admitted first — with the driver's
 *  listeners started. Returns the shell AND the fs instance it was built with
 *  (a caller with no fs of its own must read the same backend the guest writes). */
async function buildShell(opts: StorageNodeOptions, identity: Identity, cohort: Set<PeerId>): Promise<{ shell: Shell; fs: Fs }> {
  // Normalise the operator override: derive windowTargetBytes from realmMemoryBytes
  // when not explicitly set (§3). realmMemoryBytes is host-only (the QuickJS heap
  // bound) — split it out of the config that becomes the guest's APP, and pass it to
  // the shell as the realm limit. The rest of opts.config is the operator override
  // merged OVER the bundle's signed guest.config; quota is operator policy (§14),
  // never author-signed, added here.
  const norm = normaliseConfig(opts.config ?? {});
  const { realmMemoryBytes, ...guestOverride } = norm;

  return bootTransportShell({
    sodium: opts.sodium, identity, fs: opts.fs, channels: opts.channels,
    listen: opts.listen, wsListen: opts.wsListen, networkKey: opts.networkKey,
    contactSecret: opts.contactSecret, admitPeer: opts.admitPeer,
    connsPerPeer: opts.connsPerPeer, timeoutMs: opts.timeoutMs,
    transportBlob: opts.transportBlob, livePeers: () => [...cohort],
    now: opts.clock,
    config: { ...guestOverride, quota: opts.quota ?? DEFAULT_QUOTA_BYTES },
    realmMemoryBytes,
  });
}

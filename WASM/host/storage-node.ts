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
//   - serves the guest's *holder* entrypoint via shell.serve() — the storage
//     protocol needs no wiring here: the bundle's manifest claims it and the load
//     is what routes it (§12.10)
//
// A caller that already stands a shell up (a WebRTC/WS node, whose socket seam is
// a host-managed transport handing channels to the driver's openLink) passes that
// shell in with `shell`; StorageNode then loads only the seedstore bundle on it.

import type { Fs } from "seedkernel-wasm/fs";
// The backend, not the seam: `MemoryFs` is host code alongside `NodeFs`, while
// `seedkernel-wasm/fs` stays the `Fs` contract plus the key rule. The scoping
// wrapper (`scopedFs`) is shell logic now and lives in `shell-core` below.
import { MemoryFs } from "seedkernel-wasm/fs-memory";
import { TransportHost } from "seedkernel-wasm/transport-host";
import { TRANSPORT_BUNDLE_B64 } from "seedkernel-wasm/transport-bundle";
import { FsBlobView, type BlobView } from "./store-view.js";
import { Crypto } from "./crypto.js";
import {
  type Identity, type PeerId, type StorageConfig, defaultConfig, assertStorageConfig, normaliseConfig, DEFAULT_QUOTA_BYTES,
} from "./core.js";
import { STORAGE_APP } from "./manifest.js";
import { encodeScoreReq } from "./reputation-core.js";
import { toHex, fromHex, readU32BE, readU64BE, concatBytes } from "./util.js";
import {
  createShell, ModuleTable, scopedFs, byPrivilege, requireTransport, type Shell, type ModuleLookup, type RealmFactory,
} from "seedkernel-wasm/shell-core";
import { FreshnessMarks, appKeyFor, appScopeFor, verifyBundle, type LoadedBundle } from "seedkernel-wasm/bundle";
import type { ChannelFactoryLike } from "./loopback.js";
import type { Sodium } from "./sodium.js";

const NO_ARG = new Uint8Array(0);

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
 *  (`encodePutResult` in tier2-guest.orchestration.js):
 *    [K 32][chunkCount u32][placed u32][intended u32][rootLen u32][root ...][idCount u32]{id 32} */
function decodePutResult(r: Uint8Array): PutResult {
  const rootLen = readU32BE(r, 44);
  const tail = 48 + rootLen;
  const blockIds: Uint8Array[] = [];
  const idCount = readU32BE(r, tail);
  for (let i = 0; i < idCount; i++) blockIds.push(r.slice(tail + 4 + i * 32, tail + 4 + (i + 1) * 32));
  return {
    key: r.slice(0, 32),
    root: r.slice(48, tail),
    chunkCount: readU32BE(r, 32),
    replicasLanded: readU32BE(r, 36),
    replicasIntended: readU32BE(r, 40),
    blockIds,
  };
}

export interface PutResult {
  /** The file's ROOT DESCRIPTOR (§4.3) — the signed envelope a reader is handed, which
   *  replaced the old 32-byte manifest_id when the manifest stopped being an object. It
   *  is variable-length: a one-chunk file's root is that chunk's own descriptor. */
  root: Uint8Array;
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
  /** Optional peer whitelist — the 32-byte channel keys this node will talk to,
   *  shipped to the transport at init and applied there (seedkernel §12.6.3). A LINT, not a
   *  gate: a list is what a config can carry to a confined occupant, where a host-side
   *  predicate over the attribution the occupant reported was only ever checking a key
   *  the occupant supplied. Absent ⇒ admit every peer that completes the handshake. */
  admitPeers?: Uint8Array[];
  /** Parallel connections per dialed peer (default 1) — the transport's dial
   *  fan-out. */
  connsPerPeer?: number;
  /** The signed transport bundle blob. Defaults to the one shipped in the
   *  seedkernel artifact; an operator who pins a different transport author
   *  builds their own. Only read when StorageNode builds its own shell. */
  transportBlob?: Uint8Array;
  /** The shell's own inbound seam (seedkernel §12.10), consulted on each arriving frame
   *  before the routing table; `null` falls through to the app that claims the protocol.
   *  A node serving no protocol of its own needs none — the storage tests use it to see
   *  and delay inbound requests, which is the one place an app-level request is visible
   *  host-side now that the wire is the record layer's. */
  answer?: (from: PeerId, proto: string, payload: Uint8Array) => Promise<Uint8Array> | null;
  /** Override the cohort's signing scope author: sign descriptors under this
   *  author instead of the loaded bundle's (used when joining a cohort whose
   *  holders run a DIFFERENT bundle's author — the browser demo's override). */
  signAuthor?: Uint8Array;
}

export class StorageNode {
  readonly peerId: PeerId;
  readonly identity: Identity;
  /** The socket driver (shell.transport) — sockets, addresses, listeners, and nothing
   *  else. The transport itself is a signed bundle; this is the host side that hands it
   *  descriptors. There is no request face here any more: an app's send is a call to the
   *  id the transport claims, so requests leave from the GUEST (see `netSend` in
   *  host/tier2-guest.orchestration.js) and never through this object. */
  readonly net: TransportHost;
  readonly fs: Fs;
  readonly store: BlobView;
  readonly quota: number;
  readonly crypto: Crypto;
  readonly sodium: Sodium;
  readonly config: StorageConfig;
  /** The module table, exposed through ModuleLookup (callModule + isBound)
   *   without any install path — the bind is solely the bundle loader's job. */
  readonly host: ModuleLookup;

  /** The shell this node runs on: the module table, the bundle loader, the routing and
   *  the guest realms. Public because a driver sometimes has to reach the runtime
   *  directly — the latency harness dispatches an inbound frame itself to time it — and
   *  because a caller that PASSED a shell in already holds this object. */
  readonly shell: Shell;
  private readonly clockFn: () => number;
  /** The cohort's signing-scope author (§16), derived from the verified bundle author.
   *   Exposed so host-side callers can produce descriptors that the guest's
   *   holder path will verify — signDescriptor() with this key as the 5th argument
   *   derives the byte-identical scope the guest's node/verify checks. */
  readonly signAuthor: Uint8Array;
  /** This app's fs keyspace prefix (seedkernel §12.2). Every key the holder writes is
   *   `appScope + key` on the raw backend, so tooling that opens a node's directory
   *   *cold* — outside a running node, where `this.fs` is already scoped — has to wrap
   *   the backend in `scopedFs(raw, appScope)` to see the same blocks. Without it a
   *   read view finds nothing at all: FsBlobView drops any key whose hex is not 64
   *   chars, so a prefixed key is skipped rather than misread. */
  readonly appScope: string;
  /** This app's table key (§5.1). Its modules live in a map under it, at the logical
   *   names the manifest declares ("codec", "reputation"), so there is no per-module
   *   name to derive or hold. */
  private readonly appKey: string;
  /** Durable cohort roster: the set of peers this node has a storage relationship
   *   with. The network owns connectivity; the cohort is app state — independent of who
   *   is currently online — and it is what `connect` teaches each driver an address for.
   *
   *   It no longer feeds the guest. The guest asks the TRANSPORT who it is linked to (the
   *   `peers` op behind `_net`), which is the authenticated set — a fact about links, and
   *   links are the transport's. Handing the guest a host-side roster instead was two copies
   *   of one fact, and the copy that could be wrong was this one: a peer on the roster
   *   with no link is a peer every OFFER to it times out against. */
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
    // A shell passed in must already have its transport admitted and standing (the
    // doc on `shell`).
    this.net = requireTransport(shell, "a StorageNode shell must have the transport bundle standing");
    this.cohort = cohort;
    this.ownsShell = ownsShell;

    // Derive signing scope and kernel names from the verified bundle author —
    // the same derivation a shell-run node uses. `signAuthor` lets a caller join
    // a cohort whose holders run a DIFFERENT bundle's author (descriptors are
    // scoped to the deployment, §16); the fs keyspace and app key stay the
    // loaded bundle's.
    this.signAuthor = opts.signAuthor ?? loaded.author;
    this.appScope = appScopeFor(opts.sodium, loaded.author, STORAGE_APP);
    this.appKey = appKeyFor(loaded.author, STORAGE_APP);

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
    const built = opts.shell ? null : await buildShell(opts, identity);
    const shell = opts.shell ?? built!.shell;
    // The fs the shell was built with — the guest's writes land there. A caller's own
    // fs wins; a pre-built shell brings its own (bootTransportShell created it).
    const fs = opts.fs ?? (opts.shell?.fs ?? built!.fs) ?? new MemoryFs();

    // Everything from here on can fail — a blob that does not verify, a config the
    // constructor refuses — and a factory that throws must not leave what it built
    // running. Without this, each failure stranded a whole shell: a listening socket, a
    // transport realm, and (past loadBundleBlob) the storage realm, live for the
    // process's life with nothing holding a reference to close them. Only a shell we
    // stood up ourselves; a caller's shell is the caller's to close.
    try {
      // The load is the whole of it (seedkernel §12.10): the manifest claims
      // STORAGE_PROTO, so admitting the bundle is what points inbound storage frames at
      // it. Nothing here routes anything — a node that installed storage serves storage.
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
    } catch (err) {
      if (ownsShell) shell.close();
      throw err;
    }
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

  /** One of THIS app's guest entrypoints, by name.
   *
   *  The app key is not optional any more. A node with a network has at least two apps
   *  loaded — the storage bundle and the transport, which is an ordinary app that claims the
   *  reserved id `_net` (seedkernel §12.10) — so "the only loaded app" is not something a
   *  StorageNode can mean, and omitting the key is an ambiguity error rather than a
   *  default. One place says which app we are, instead of six call sites repeating it. */
  private run(entry: string, payload: Uint8Array): Promise<Uint8Array> {
    return this.shell.runGuest(entry, payload, this.appKey);
  }

  private runExclusive<T>(body: () => Promise<T>): Promise<T> {
    if (this.closed) return Promise.reject(new Error("storage node closed"));
    const p = this.inFlight.then(body);
    this.inFlight = p.then(() => {}, () => {});
    return p;
  }

  /** PUT a file (§6), orchestrated in the guest, STREAMED. */
  async put(plaintext: Uint8Array): Promise<PutResult> {
    return this.runExclusive(async () => {
      const meta = await this.run("putStart", NO_ARG);
      const windowBytes = readU32BE(meta, 0);
      for (let off = 0; ; off += windowBytes) {
        await this.run("putWindow", plaintext.subarray(off, Math.min(off + windowBytes, plaintext.length)));
        if (off + windowBytes >= plaintext.length) break;
      }
      return decodePutResult(await this.run("putFinish", NO_ARG));
    });
  }

  /** GET a file (§7), orchestrated in the guest, STREAMED. `root` is the signed root
   *  descriptor from the PUT (or shared alongside `key`); K leads the argument so the
   *  variable-length root can be its tail. */
  async get(root: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    return this.runExclusive(async () => {
      const fileSize = readU64BE(await this.run("getStart", concatBytes([key, root])), 0);
      const out = new Uint8Array(fileSize);
      let written = 0;
      while (written < fileSize) {
        const part = await this.run("getNext", NO_ARG);
        if (part.length === 0) throw new Error(`get: stream ended ${written}/${fileSize} bytes in`);
        out.set(part, written); written += part.length;
      }
      return out;
    });
  }

  /** Issue ONE control-plane message to a peer and answer with its reply (§18).
   *  `body` is `[type u8][payload]` — the same bytes a holder's `handle` decodes.
   *
   *  It runs through this node's own guest (`request`), because that is where a send
   *  lives now: the driver holds sockets and nothing else, and an app reaches the network
   *  by calling the id the transport claims. So a console probe or a wire-level test asks the
   *  app to ask, which is also what makes it exact — the frame it puts on the wire is the
   *  one the placement engine puts there.
   *
   *  Throws if the peer was unreachable within the request window; a peer that answered,
   *  including a decline, comes back as its response bytes. */
  async request(peer: PeerId, body: Uint8Array): Promise<Uint8Array> {
    const r = await this.runExclusive(() => this.run("request", concatBytes([fromHex(peer), body])));
    if (r[0] !== 1) throw new Error(`request: peer ${peer.slice(0, 8)}… unreachable within the request window`);
    return r.slice(1);
  }

  /** Pre-warm the realm's codec + crypto caps. */
  async warm(): Promise<void> {
    await this.runExclusive(() => this.run("warm", NO_ARG));
  }

  /** Run one repair pass over every chunk this node holds a block of (§9). */
  async runRepair(): Promise<number> {
    return readU32BE(await this.runExclusive(() => this.run("repair", NO_ARG)), 0);
  }

  /** Decayed reciprocity score this node holds for a peer (§13). */
  score(peerPk: Uint8Array): number {
    const res = this.host.callModule(this.appKey, "reputation", encodeScoreReq(peerPk, this.now()));
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
    return this.host.isBound(this.appKey, "codec") && this.host.isBound(this.appKey, "reputation");
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
    admitPeers?: Uint8Array[]; connsPerPeer?: number;
    timeoutMs?: number; transportBlob?: Uint8Array;
    createRealm?: RealmFactory;
    /** The shell's own inbound seam — see `StorageNodeOptions.answer`. */
    answer?: (from: PeerId, proto: string, payload: Uint8Array) => Promise<Uint8Array> | null;
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
      table: new ModuleTable(),
      fs,
      freshnessStore: new FreshnessMarks(),
      channels: opts.channels,
      listen: opts.listen,
      wsListen: opts.wsListen,
      networkKey: opts.networkKey,
      contactSecret: opts.contactSecret,
      admitPeers: opts.admitPeers,
      connsPerPeer: opts.connsPerPeer,
      createRealm: opts.createRealm ?? createRealm,
      now: opts.now,
    },
    // ONE admission predicate (§12.5), keyed on the privileges the manifest's
    // `requires` reach, said with `byPrivilege`: the `base` branch admits an
    // app that reaches no privilege, the `link` grant admits the transport
    // bundle by author pin — the operator handing us the storage bundle is the
    // trust decision for THAT; an app bundle is admitted because its operator
    // handed it to us — the choice of bundle is the trust decision, so there is
    // no author allow-list to clear (the manifest signature + module hashes are
    // still verified by loadBundleBlob, and revocation + the downgrade guard are
    // composed by the shell around whatever we pass here).
    admit: byPrivilege({
      base: () => true,
      grants: { link: (v) => toHex(v.author) === transportAuthorHex },
    }),
    answer: opts.answer,
    requestDeadlineMs: opts.timeoutMs,
    config: { ...(opts.config ?? {}), ...(opts.quota != null ? { quota: opts.quota } : {}) },
    realmMemoryBytes: opts.realmMemoryBytes,
  });

  // Load the transport bundle: the node's network (phase 3). This stands the
  // driver up over the socket seam; the listeners bind below.
  await shell.loadBundleBlob(blob);
  const driver = requireTransport(shell, "the loaded transport bundle did not stand a driver");
  await driver.start();

  return { shell, fs };
}

/** Build the shell a StorageNode loads its bundles onto — the socket seam,
 *  the realm factory, the transport bundle admitted first — with the driver's
 *  listeners started. Returns the shell AND the fs instance it was built with
 *  (a caller with no fs of its own must read the same backend the guest writes). */
async function buildShell(opts: StorageNodeOptions, identity: Identity): Promise<{ shell: Shell; fs: Fs }> {
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
    contactSecret: opts.contactSecret, admitPeers: opts.admitPeers,
    connsPerPeer: opts.connsPerPeer, timeoutMs: opts.timeoutMs,
    transportBlob: opts.transportBlob, answer: opts.answer,
    now: opts.clock,
    config: { ...guestOverride, quota: opts.quota ?? DEFAULT_QUOTA_BYTES },
    realmMemoryBytes,
  });
}

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
//   - creates the platform seam (fs, the channel adapter, freshnessStore,
//     identity, sodium) and loads the transport bundle through the shared shell
//   - calls createShell() + loadBundleBlob() to wire the shared shell
//   - runs the guest's *initiator* ops (put / get / repair) via
//     shell.invoke() — a loopback into the app's one `handle`
//   - serves the guest's *holder* entrypoint without wiring anything: the load
//     stands the guest and the manifest's claim is what routes inbound storage
//     frames to it (§12.10)
//
// A caller that already stands a shell up (a WebRTC/WS node, whose socket seam is
// a host-managed transport handing channels to the driver's openLink) passes that
// shell in with `shell`, together with the `transport` adapter it built the shell
// on; StorageNode then loads only the seedstore bundle on it.

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
import { Op, decodeStats, type RequestStats } from "./protocol.js";
import { toHex, fromHex, readU32BE, readU64BE, concatBytes } from "./util.js";
import {
  createShell, scopedFs, byPrivilege, type Shell, type RealmFactory,
} from "seedkernel-wasm/shell-core";
// The JS target's builder for a bundle's private pure modules (seedkernel §4): a slot's
// modules are its own now, so the host hands the shell a builder rather than a table it
// could call into.
import { ModuleTable } from "seedkernel-wasm/module-table";
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
   *  its listeners started (a WebRTC/WS node — the socket seam is host-managed, so
   *  the adapter is attached and the RTC/WS network hands it channels). Absent,
   *  StorageNode builds its own shell from `channels`/`listen` below. */
  shell?: Shell;
  /** The channel adapter that shell was built on. Required alongside `shell` and
   *  meaningless without it: the adapter is the PLATFORM's — the shell only points it
   *  at whichever bundle owns the raw-link binding and no longer exposes it — so a
   *  caller that built the shell is the only one who can hand it over
   *  (`bootTransportShell` returns both). It is the whole of `node.net`. */
  transport?: TransportHost;
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
  /** Override the cohort's signing scope author: sign descriptors under this
   *  author instead of the loaded bundle's (used when joining a cohort whose
   *  holders run a DIFFERENT bundle's author — the browser demo's override). */
  signAuthor?: Uint8Array;
}

export class StorageNode {
  readonly peerId: PeerId;
  readonly identity: Identity;
  /** The channel adapter — sockets, addresses, listeners, and nothing else. The
   *  transport itself is a signed bundle; this is the host side that hands it
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
  /** The logical names of the modules this deployment's bundle installs — read off the
   *  verified manifest, which is the whole of what a host may know about them now: a
   *  slot's modules are private to its guest, so there is no table to ask. */
  readonly moduleNames: ReadonlySet<string>;

  /** The shell this node runs on: the bundle loader, the routing and
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
   *   `peers` op behind its local service name `_net`), which is the authenticated set — a
   *   fact about links, and links are the transport's. Handing the guest a host-side roster
   *   instead was two copies of one fact, and the copy that could be wrong was this one: a
   *   peer on the roster with no link is a peer every OFFER to it times out against. */
  readonly cohort: Set<PeerId>;
  private repairLoopOn = false;
  private repairTimer: ReturnType<typeof setTimeout> | null = null;
  private inFlight: Promise<unknown> = Promise.resolve();
  private closed = false;
  private readonly ownsShell: boolean;

  private constructor(
    opts: StorageNodeOptions,
    shell: Shell,
    net: TransportHost,
    identity: Identity,
    loaded: LoadedBundle,
    cohort: Set<PeerId>,
    ownsShell: boolean,
  ) {
    this.sodium = opts.sodium;
    this.shell = shell;
    this.moduleNames = new Set(loaded.manifest.modules.map((m) => m.name));
    this.identity = identity;
    this.peerId = toHex(identity.publicKey);
    this.fs = opts.fs ?? new MemoryFs();
    this.quota = opts.quota ?? DEFAULT_QUOTA_BYTES;
    this.store = opts.store ?? new FsBlobView(this.fs);
    this.clockFn = opts.clock ?? (() => Date.now());
    this.crypto = new Crypto(opts.sodium);
    this.net = net;
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

    // `this.config` is the geometry a caller can inspect (p2p-cli reads config.k/.m), so
    // it must equal what the guest runs. The guest decides that now, so this MIRRORS its
    // `CFG` rule and must not drift from it. guest.config is untyped JSON, so coerce it
    // here — the bundle producer writes the numeric geometry.
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
    if (opts.shell && !opts.transport) {
      throw new Error(
        "StorageNode: a caller-supplied `shell` must come with the `transport` adapter it was built on " +
        "— the shell does not expose one (seedkernel §12.6); bootTransportShell() returns both.");
    }
    const built = opts.shell ? null : await buildShell(opts, identity);
    const shell = opts.shell ?? built!.shell;
    const net = opts.transport ?? built!.transport;
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
      // The load stands the guest, so there is nothing to arm afterwards: the node has
      // been answerable for STORAGE_PROTO since this line returned.
      // The operator's settings ride WITH this load as its `LOCAL` (seedkernel §12.4),
      // not on the shell, which also hosts the transport. This is also what makes them
      // reach a CALLER's shell (the browser/RTC nodes), which a shell-wide config missed.
      const loaded = await shell.loadBundleBlob(opts.bundleBlob, { localConfig: localConfigFor(opts) });

      // The guest does NOT reach the backend directly: the shell hands it
      // `scopedFs(fs, appScopeFor(author, app))`, so every key the holder writes lands
      // under this app's opaque prefix (seedkernel §12.2). The host's read view has to
      // enter through the same door, or `store.list()` walks past the guest's writes and
      // reads back scope-prefixed keys as if they were block ids. One keyspace per app,
      // one handle to it — the scope is derived here rather than passed in because it
      // depends on the *verified* bundle author, which only exists after the load above.
      const appFs = scopedFs(fs, appScopeFor(opts.sodium, loaded.author, STORAGE_APP));
      const withFs = { ...opts, fs: appFs }; // share the one fs instance with the constructor below

      return new StorageNode(withFs, shell, net, identity, loaded, cohort, ownsShell);
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

  // ── PUT / GET / repair / share — all local ops through shell.invoke() ──────

  /** One LOCAL op into this app's one entrypoint, `handle` (seedkernel §12.2): name the
   *  op and loop back through the shell's `invoke`, which writes the host's caller id and
   *  the op envelope — so storage has one op vocabulary, not an entrypoint per initiator
   *  operation.
   *
   *  It frames nothing itself. The envelope is the guest ABI's, written by `opCall` and
   *  read by the preamble's `readOp` (seedkernel `host/guest-seam.ts`); a copy here would
   *  be the same layout maintained on both sides of a seam this file is only a caller of.
   *
   *  The app key is not optional any more. A node with a network has at least two apps
   *  loaded — the storage bundle and the transport, an ordinary app serving the local
   *  service name `_net` (seedkernel §12.10) — so "the only loaded app" is not something
   *  a StorageNode can mean, and omitting the key is an ambiguity error rather than a
   *  default. One place says which app we are, instead of six call sites repeating it. */
  private invoke(op: string, payload: Uint8Array): Promise<Uint8Array> {
    return this.shell.invoke(op, payload, this.appKey);
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
      const meta = await this.invoke(Op.PUT_START, NO_ARG);
      const windowBytes = readU32BE(meta, 0);
      for (let off = 0; ; off += windowBytes) {
        await this.invoke(Op.PUT_WINDOW, plaintext.subarray(off, Math.min(off + windowBytes, plaintext.length)));
        if (off + windowBytes >= plaintext.length) break;
      }
      return decodePutResult(await this.invoke(Op.PUT_FINISH, NO_ARG));
    });
  }

  /** GET a file (§7), orchestrated in the guest, STREAMED. `root` is the signed root
   *  descriptor from the PUT (or shared alongside `key`); K leads the argument so the
   *  variable-length root can be its tail. */
  async get(root: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    return this.runExclusive(async () => {
      const fileSize = readU64BE(await this.invoke(Op.GET_START, concatBytes([key, root])), 0);
      const out = new Uint8Array(fileSize);
      let written = 0;
      while (written < fileSize) {
        const part = await this.invoke(Op.GET_NEXT, NO_ARG);
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
    const r = await this.runExclusive(() => this.invoke(Op.REQUEST, concatBytes([fromHex(peer), body])));
    if (r[0] !== 1) throw new Error(`request: peer ${peer.slice(0, 8)}… unreachable within the request window`);
    return r.slice(1);
  }

  /** Pre-warm the realm's codec + crypto caps. */
  async warm(): Promise<void> {
    await this.runExclusive(() => this.invoke(Op.WARM, NO_ARG));
  }

  /** Run one repair pass over every chunk this node holds a block of (§9). */
  async runRepair(): Promise<number> {
    return readU32BE(await this.runExclusive(() => this.invoke(Op.REPAIR, NO_ARG)), 0);
  }

  /** Decayed reciprocity score this node holds for a peer (§13). The reputation module
   *  is the app's own — private to its slot since the kernel collapsed an app into one
   *  bundle slot — so the reading comes from the guest that holds it, through the same
   *  loopback op vocabulary every other initiator call uses. It is the same module
   *  instance the placement ranker scores against, which a second host-side one would
   *  not have been. */
  async score(peerPk: Uint8Array): Promise<number> {
    const res = await this.invoke(Op.SCORE, peerPk);
    if (!res || res.length < 8) return 0;
    return new DataView(res.buffer, res.byteOffset, 8).getFloat64(0, true);
  }

  /** This node's request statistics since the last read, keyed by MsgType (host/
   *  protocol.ts `RequestStats`): how many of each request it SENT, the peak number
   *  in flight at once (the window/fan-out signal), and what it RECEIVED as a holder
   *  (count, payload bytes, and total processing ms inside the guest's `handle`).
   *
   *  The kernel removed the host-side inbound seam the old harnesses timed, so the
   *  counters live in the guest, where the requests are — this is the read-and-clear
   *  op over `shell.invoke`. A caller clears by reading once before the measured
   *  phase and reads again after.
   */
  async stats(): Promise<Map<number, RequestStats>> {
    return decodeStats(await this.invoke(Op.STATS, NO_ARG));
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

  /** True if both pure handlers are installed on the kernel (§19). Read off the verified
   *  manifest: a bundle load builds every module or none (seedkernel §12.4), so the
   *  names the loaded manifest declares ARE the modules the guest holds. */
  handlersInstalled(): boolean {
    return this.moduleNames.has("codec") && this.moduleNames.has("reputation");
  }
}

/** Build the shell a StorageNode loads its bundles onto: the platform seam (fs, the
 *  channel adapter, the realm factory) + the transport bundle admitted first — the
 *  node's network — with the adapter's listeners started.
 *
 *  Returns all three things the platform now owns: the shell, the `TransportHost` (the
 *  shell does not expose it — it is the platform's, and `StorageNode.transport` wants it
 *  back), and the fs instance it was built with (a caller with no fs of its own must read
 *  the same backend the guest writes). */
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
    /** QuickJS heap limit for the guest realm, in bytes. */
    realmMemoryBytes?: number;
    now?: () => number;
  },
): Promise<{ shell: Shell; transport: TransportHost; fs: Fs }> {
  const fs = opts.fs ?? new MemoryFs();

  // The channel adapter is CONSTRUCTED here rather than by the shell: every knob on it
  // (which addresses to bind, the dial fan-out, the peer list) is this deployment's
  // answer. The shell's whole part is pointing it at whichever bundle owns the raw-link
  // binding, and shell.close() closes it, so there is still one teardown.
  const transport = new TransportHost({
    identity: opts.identity,
    networkKey: opts.networkKey,
    contactSecret: opts.contactSecret,
    requestDeadlineMs: opts.timeoutMs,
    connsPerPeer: opts.connsPerPeer,
    admitPeers: opts.admitPeers,
    channels: opts.channels,
    listen: opts.listen,
    wsListen: opts.wsListen,
  });

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
      modules: new ModuleTable(),
      fs,
      freshnessStore: new FreshnessMarks(),
      networkKey: opts.networkKey,
      transportHost: transport,
      createRealm: opts.createRealm ?? createRealm,
      now: opts.now,
    },
    // ONE admission predicate (§12.5), keyed on the privileges the manifest's
    // `requires` reach, said with `byPrivilege`: the `base` branch admits an
    // app that reaches no privilege, the `link` and `route` grants admit the
    // transport bundle by author pin — the kernel-shipped transport reaches BOTH
    // (it holds the raw links and submits attributed inbound requests, seedkernel
    // §12.5), and `byPrivilege` refuses a bundle reaching a privilege with no
    // grant entry. The operator handing us the storage bundle is the trust
    // decision for THAT; an app bundle is admitted because its operator
    // handed it to us — the choice of bundle is the trust decision, so there is
    // no author allow-list to clear (the manifest signature + module hashes are
    // still verified by loadBundleBlob, and revocation + the downgrade guard are
    // composed by the shell around whatever we pass here).
    admit: byPrivilege({
      base: () => true,
      grants: {
        link: (v) => toHex(v.author) === transportAuthorHex,
        route: (v) => toHex(v.author) === transportAuthorHex,
      },
    }),
    // No app config here: this loads ONE bundle, the transport. App config travels with
    // the load that wants it (§12.4 `localConfig`) — passing it shell-wide put a storage
    // node's settings in the transport guest's APP too.
    realmMemoryBytes: opts.realmMemoryBytes,
  });

  // Load the transport bundle: the node's network (phase 3). This is what points the
  // adapter at a claimant; the listeners bind below.
  await shell.loadBundleBlob(blob);
  await transport.start();

  return { shell, transport, fs };
}

/** Build the shell a StorageNode loads its bundles onto — the channel adapter, the realm
 *  factory, the transport bundle admitted first — with the listeners started. Returns
 *  what `bootTransportShell` returns: the shell, the adapter, and the fs instance it was
 *  built with (a caller with no fs of its own must read the same backend the guest
 *  writes). */
async function buildShell(opts: StorageNodeOptions, identity: Identity): Promise<{ shell: Shell; transport: TransportHost; fs: Fs }> {
  // realmMemoryBytes is the only thing from `config` a SHELL takes — host-owned resource
  // policy, shell-wide by nature. The rest is the app's; see localConfigFor.
  return bootTransportShell({
    sodium: opts.sodium, identity, fs: opts.fs, channels: opts.channels,
    listen: opts.listen, wsListen: opts.wsListen, networkKey: opts.networkKey,
    contactSecret: opts.contactSecret, admitPeers: opts.admitPeers,
    connsPerPeer: opts.connsPerPeer, timeoutMs: opts.timeoutMs,
    transportBlob: opts.transportBlob,
    now: opts.clock,
    realmMemoryBytes: normaliseConfig(opts.config ?? {}).realmMemoryBytes,
  });
}

/** This installation's settings for the storage bundle, as the `LOCAL` the guest reads
 *  (seedkernel §12.4); the guest picks precedence against signed `APP` — see `CFG` there.
 *
 *  `realmMemoryBytes` is split back out (the realm's bound, not the guest's), but the
 *  `windowTargetBytes` normaliseConfig derives from it stays — the guest reads that.
 *  `quota` can never be signed, so this is its only door; a node naming none gets the
 *  default rather than leaving the holder to fail closed at 0. */
function localConfigFor(opts: StorageNodeOptions): Record<string, string | number> {
  const { realmMemoryBytes, ...guestOverride } = normaliseConfig(opts.config ?? {});
  return {
    ...(guestOverride as Record<string, string | number>),
    quota: opts.quota ?? DEFAULT_QUOTA_BYTES,
  };
}

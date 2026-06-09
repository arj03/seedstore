// StorageNode — a single storage peer running *on* the seedkernel (README §19
// bootstrap). It composes the reference onion: storage app handlers → cohort +
// repair → storage bridges → installer → signature → kernel.
//
//   - loads kernel.wasm + bootstrap.wasm and wires signature + installer
//   - registers the storage bridges (crypto.* no-cap; store/net/clock/rand
//     cap-gated) onto the kernel host
//   - installs the pure codec + reputation handlers via signed install messages
//   - holds the host-side cohort / coordinator / repair orchestration
//   - serves the holder side of the protocol (HAVE / OFFER / STORE / FETCH)
//
// The same class runs in Node and the browser; only the BlobStore backend and
// the Network implementation differ (§1, §12).

// Import the kernel host from seedkernel's *browser* subpath: it is the same
// platform-neutral KernelHost, but without the node:fs shims node.js pulls in,
// so this module loads unchanged in both Node and the browser (§1, §20 "browser
// nodes and long-running peers run the same protocol").
import { KernelHost, referencePolicy, CURRENT_VERSION } from "seedkernel-wasm/browser";

import type { Sodium } from "./sodium.js";
import type { Network, PeerId } from "seedkernel-wasm/net";
import { Transport } from "seedkernel-wasm/net";
import { MemoryFs, type Fs } from "seedkernel-wasm/fs";
import { type BlobStore } from "./store-local.js";
import { FsBlobStore } from "./store-fs.js";
import { Crypto } from "./crypto.js";
import { CodecClient } from "./codec-client.js";
import { ReputationClient } from "./reputation-client.js";
import { storageNames, type StorageNames } from "./names.js";
import { registerStorageBridges } from "./bridges.js";
import { Cohort } from "./cohort.js";
import { Coordinator, type PutResult } from "./coordinator.js";
import { Repair } from "./repair.js";
import {
  MsgType, decodeHaveReq, encodeHaveRes, decodeOffer, OFFER_ACCEPT, OFFER_DECLINE,
  decodeStore, STORE_OK, STORE_FAIL, encodeFetchRes,
} from "./protocol.js";
import { verifyDescriptor, descriptorContains } from "./manifest.js";
import { type Node, type Identity, type StorageConfig, defaultConfig } from "./core.js";
import { toHex, fromHex, bytesEqual } from "./util.js";

export interface StorageNodeOptions {
  network: Network;
  sodium: Sodium;
  kernelBytes: Uint8Array;
  bootstrapBytes: Uint8Array;
  codecBytes: Uint8Array;
  reputationBytes: Uint8Array;
  identity?: Identity;
  config?: Partial<StorageConfig>;
  /** Raw-byte `fs.*` backend (§12; seedkernel's Fs). Defaults to an in-RAM
   *  MemoryFs; a server node passes a NodeFs, the browser an OPFS-backed one. The
   *  default store is an FsBlobStore over this, and the Tier-2 cap-bridge serves
   *  `fs.*` from it — so it must back whatever `store` is, if one is supplied. */
  fs?: Fs;
  /** Donated blob store (§12). Defaults to an FsBlobStore over `fs` with a
   *  `quota`-byte budget; a custom store must layer over the same `fs`. */
  store?: BlobStore;
  quota?: number;
  clock?: () => number;
  /** net.send timeout — how long before a peer is treated as unreachable (§8). */
  timeoutMs?: number;
}

export class StorageNode implements Node {
  readonly peerId: PeerId;
  readonly identity: Identity;
  readonly transport: Transport;
  readonly fs: Fs;
  readonly store: BlobStore;
  readonly codec!: CodecClient;
  readonly crypto: Crypto;
  readonly reputation!: ReputationClient;
  readonly sodium: Sodium;
  readonly config: StorageConfig;
  readonly host: KernelHost;
  readonly names: StorageNames;

  readonly cohort: Cohort;
  readonly coordinator: Coordinator;
  readonly repair: Repair;

  private readonly network: Network;
  private readonly peers = new Set<PeerId>();
  private readonly liveness = new Map<PeerId, number>();
  private readonly clockFn: () => number;
  private installSeq = 0;

  private constructor(opts: StorageNodeOptions, host: KernelHost, identity: Identity, codec: CodecClient, reputation: ReputationClient) {
    this.network = opts.network;
    this.sodium = opts.sodium;
    this.host = host;
    this.identity = identity;
    this.peerId = toHex(identity.publicKey);
    this.config = { ...defaultConfig(), ...opts.config };
    this.clockFn = opts.clock ?? (() => Date.now());
    this.crypto = new Crypto(opts.sodium);
    this.fs = opts.fs ?? new MemoryFs();
    this.store = opts.store ?? new FsBlobStore(this.fs, opts.quota ?? 64 * 1024 * 1024);
    (this as { codec: CodecClient }).codec = codec;
    (this as { reputation: ReputationClient }).reputation = reputation;
    this.names = storageNames(host);
    this.transport = new Transport(this.peerId, opts.network, opts.timeoutMs ?? 200);

    this.cohort = new Cohort(this);
    this.coordinator = new Coordinator(this, this.cohort);
    this.repair = new Repair(this, this.cohort, this.coordinator);

    this.transport.onRequest((from, type, payload) => this.handleRequest(from, type, payload));
  }

  /** Boot a storage node: load the kernel, wire signature + installer, register
   *  bridges, and install the codec + reputation handlers (§19). */
  static async create(opts: StorageNodeOptions): Promise<StorageNode> {
    await opts.sodium.ready;
    const host = await KernelHost.load(
      opts.kernelBytes as BufferSource, opts.bootstrapBytes as BufferSource, opts.sodium as never,
    );
    host.registerSignature(host.deriveBootstrapName("signature"));
    host.registerInstaller(
      host.deriveBootstrapName("install"),
      host.deriveBootstrapName("installer.lookup"),
      host.deriveBootstrapName("installer.caps_of"),
    );
    // Single-deployment reference posture: accept audited handler bytes and
    // acknowledge their declared caps. A real deployment narrows this to a
    // content-hash allowlist + closed author set (§19).
    host.setApproveInstall(referencePolicy(host, () => true, () => true));

    const identity = opts.identity ?? (() => {
      const kp = opts.sodium.crypto_sign_keypair();
      return { publicKey: kp.publicKey, privateKey: kp.privateKey };
    })();

    const crypto = new Crypto(opts.sodium);
    const names = storageNames(host);
    const codec = await CodecClient.load(opts.codecBytes, crypto, names.cryptoHash);
    const reputation = await ReputationClient.load(opts.reputationBytes);

    const node = new StorageNode(opts, host, identity, codec, reputation);
    node.registerBridges();
    node.installHandlers(opts.codecBytes, opts.reputationBytes);
    return node;
  }

  // ── Node surface ───────────────────────────────────────────────────────
  now(): number { return this.clockFn(); }
  cohortPeers(): PeerId[] { return [...this.peers]; }
  markSeen(peer: PeerId): void { this.liveness.set(peer, this.now()); }
  lastSeen(peer: PeerId): number { return this.liveness.get(peer) ?? 0; }

  // ── cohort membership (§5.1) ───────────────────────────────────────────
  /** Add a peer to this node's cohort. Reciprocal — call on both nodes, or use
   *  connect() for a symmetric link. */
  addPeer(peerId: PeerId): void {
    if (peerId !== this.peerId) this.peers.add(peerId);
  }
  removePeer(peerId: PeerId): void { this.peers.delete(peerId); }

  /** Make a symmetric cohort link between two nodes. */
  static connect(a: StorageNode, b: StorageNode): void {
    a.addPeer(b.peerId);
    b.addPeer(a.peerId);
  }

  // ── PUT / GET / share (§6, §7, §4.4) ────────────────────────────────────
  put(plaintext: Uint8Array): Promise<PutResult> { return this.coordinator.put(plaintext); }
  get(manifestId: Uint8Array, key: Uint8Array): Promise<Uint8Array> { return this.coordinator.get(manifestId, key); }

  /** Share a file: seal K to a recipient's kernel key (§4.4). */
  shareKey(K: Uint8Array, recipientPk: Uint8Array): Uint8Array { return this.crypto.seal(K, recipientPk); }
  /** Open a sealed K addressed to this node. */
  openKey(sealed: Uint8Array): Uint8Array | null {
    return this.crypto.sealOpen(sealed, this.identity.publicKey, this.identity.privateKey);
  }

  /** Run one repair pass over every chunk this node holds a block of (§9). */
  runRepair(): Promise<number> { return this.repair.repairHeldChunks(); }

  /** Tear down the transport (test cleanup). */
  close(): void { this.transport.close(); }

  // ── holder side of the protocol (§5, §6, §7) ────────────────────────────
  private handleRequest(from: PeerId, type: number, payload: Uint8Array): Uint8Array | null {
    this.markSeen(from);
    switch (type) {
      case MsgType.HAVE: {
        const ids = decodeHaveReq(payload);
        return encodeHaveRes(ids.map((id) => this.store.has(id)));
      }
      case MsgType.OFFER: {
        const o = decodeOffer(payload);
        return this.admit(o.descriptor, o.blockId, o.size) ? OFFER_ACCEPT : OFFER_DECLINE;
      }
      case MsgType.STORE: {
        const s = decodeStore(payload);
        return this.acceptStore(s.blockId, s.descriptor, s.bytes) ? STORE_OK : STORE_FAIL;
      }
      case MsgType.FETCH: {
        const sb = this.store.get(payload.slice(0, 32));
        return encodeFetchRes(sb ? sb.bytes : null);
      }
      default:
        return null;
    }
  }

  /** Admission control (§6 sibling rule, §14 quota). A holder enforces the
   *  no-two-blocks-of-a-chunk rule itself, so the §10 invariant survives a
   *  careless or malicious placer (a repairer included), not just an honest
   *  coordinator. */
  private admit(descriptor: Uint8Array | null, blockId: Uint8Array, size: number): boolean {
    if (this.store.stat().free < size) return false; // quota (committed tier full)
    if (descriptor) {
      const sd = verifyDescriptor(this.sodium, descriptor);
      if (!sd) return false;                                   // forged/unsigned → reject (§4.3)
      if (!descriptorContains(sd.descriptor, blockId)) return false; // block not of this chunk
      for (const sib of sd.descriptor.blockIds) {              // sibling rule (§6)
        if (bytesEqual(sib, blockId)) continue;
        if (this.store.has(sib)) return false;
      }
    }
    return true;
  }

  private acceptStore(blockId: Uint8Array, descriptor: Uint8Array | null, bytes: Uint8Array): boolean {
    // Content addressing: the bytes must hash to the claimed id (§4.2), checked
    // by every holder on every hop — a strictly wider guarantee than a MAC.
    if (!bytesEqual(this.crypto.hash(bytes), blockId)) return false;
    if (!this.admit(descriptor, blockId, bytes.length)) return false;
    try { this.store.put(blockId, bytes, descriptor); return true; }
    catch { return false; }
  }

  // ── bootstrap wiring (§19) ──────────────────────────────────────────────
  private registerBridges(): void {
    registerStorageBridges(this.host, this.names, {
      crypto: this.crypto,
      store: this.store,
      clockNow: () => this.now(),
      randBytes: (n) => this.sodium.randombytes_buf(n),
      // net.send bridge → the loopback/data-channel transport. Orchestration
      // uses the Transport directly; this is the WASM-reachable surface (§16).
      netSend: (peerId, bytes) => this.network.send(this.peerId, peerId, bytes),
    });
  }

  private installHandlers(codecBytes: Uint8Array, reputationBytes: Uint8Array): void {
    // The two pure handlers declare no capabilities, so the structural sandbox
    // guarantees they reach neither disk nor network even if buggy (§17).
    this.installOne(this.names.codec, codecBytes);
    this.installOne(this.names.reputation, reputationBytes);
    // Plant the crypto.hash name on the installed codec so its block-id op can
    // call the bridge (the same configure the host bakes in at install, §16).
    const cfg = new Uint8Array(1 + this.names.cryptoHash.length);
    cfg[0] = this.names.cryptoHash.length; cfg.set(this.names.cryptoHash, 1);
    this.host.callDynamicExport(this.names.codec, "configure", cfg);
  }

  private installOne(name: Uint8Array, wasm: Uint8Array): void {
    const seq = ++this.installSeq;
    const payload = this.host.encodeInstallPayload(seq, name, [], null, wasm);
    this.host.dispatch(this.host.wrapAndEncode(
      this.identity.privateKey, this.identity.publicKey, CURRENT_VERSION, this.host.deriveBootstrapName("install"), payload,
    ));
  }

  /** True if both pure handlers are installed on the kernel (§19). */
  handlersInstalled(): boolean {
    return this.host.isRegistered(this.names.codec) && this.host.isRegistered(this.names.reputation);
  }

  pubkeyOf(peerId: PeerId): Uint8Array { return fromHex(peerId); }
}

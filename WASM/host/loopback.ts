// LoopbackNetwork — the in-process network fabric for tests and single-process
// demos (the successor of the old seedkernel LoopbackNetwork, which sat under a
// hand-rolled Transport). The transport is now a signed bundle driven by the
// shared TransportHost over the ChannelFactory seam (seedkernel §12.6): this file
// is that seam — a loopback fabric, one `view()` per node — plus the
// online/offline control the storage tests and the in-page demo need.
//
// The base fabric (LoopbackChannel/LoopbackChannels) used to ship inside
// seedkernel's shared host bundle, exported from `seedkernel-wasm/transport-host`.
// It is test/demo infrastructure, so seedkernel moved it out of the runtime (it
// lives in seedkernel's own tests/ now, and is no longer an exported entry). This
// app's tests and browser demo run on it, so the fabric is vendored here: the
// `ChannelFactory` it implements is the same seam a real deployment's sockets
// satisfy, and nothing about the transport changes because the bottom is
// in-process.
//
// The old LoopbackNetwork had `setOnline(peerId, bool)`/`isOnline(peerId)` and
// dropped frames to/from an offline peer. Here a node going offline is made real:
// every link it holds (dialed or accepted) is killed, so its side of each
// authenticated channel closes and the transport forgets it, and a later dial to
// its port draws a dead channel (the ECONNREFUSED of the fabric's own dead-port
// dial). Requests to an offline peer then fail within the transport's stall
// window, exactly as a real offline peer would.
//
// There is no re-online in the tests (a node that returns boots a fresh
// transport), so going back online is only a bookkeeping toggle here.

/** The structural RawLink shape this file needs (socket-seam.ts is not an
 *  exported entry, so the shape is stated here rather than imported). `framing`
 *  says which wire codec the transport bundle runs over the link — the closed set
 *  of socket-seam.ts's `FRAMING` (0 PLATFORM, 1 LENGTH, 2 WS_CLIENT, 3 WS_SERVER),
 *  restated as the literal union so it still assigns to the kernel's `Framing`.
 *  The fabric's channels are `PLATFORM`: one `send` is one delivery, so there is
 *  nothing for the bundle to frame. */
export interface RawLinkLike {
  send(bytes: Uint8Array): void;
  onData(cb: (bytes: Uint8Array) => void): void;
  onClose(cb: () => void): void;
  close(graceful: boolean): void;
  readonly framing: 0 | 1 | 2 | 3;
  readonly authority?: string;
  readonly remoteAddr?: string;
}

/** The structural ChannelFactory shape (socket-seam.ts `ChannelFactory`). */
export interface ChannelFactoryLike {
  connect(addr: { host: string; port: number; transport: "tcp" | "ws"; contactSecret?: Uint8Array }): RawLinkLike;
  listen(
    tcp: { host: string; port: number } | undefined,
    ws: { host: string; port: number } | undefined,
    onAccept: (channel: RawLinkLike) => void,
  ): Promise<{ port: number; wsPort: number }>;
  close(): void;
}

/** One end of an in-process socket pair. Delivery is asynchronous (a microtask, or a
 *  `setTimeout(delayMs)` when the fabric models a latency-bearing link), mirroring a
 *  real socket; closing one end fires the other's onClose — the close semantics of
 *  BufferedChannel's fail() path, which is how a real channel reports the far side
 *  going away. */
class LoopbackChannel implements RawLinkLike {
  /** A socket pair with `send` as the boundary: one send is one delivery. */
  readonly framing = 0 as const; // FRAMING.PLATFORM — nothing for the bundle to frame
  peer: LoopbackChannel | null = null;
  msg: ((bytes: Uint8Array) => void) | null = null;
  cls: (() => void) | null = null;
  dead = false;
  readonly remoteAddr: string;
  /** Wire latency per delivered message (ms). 0 = the zero-latency fabric. */
  readonly delayMs: number;

  constructor(remoteAddr: string, delayMs = 0) {
    this.remoteAddr = remoteAddr;
    this.delayMs = delayMs;
  }

  static pair(remoteAddr: string, delayMs = 0): [LoopbackChannel, LoopbackChannel] {
    const a = new LoopbackChannel(remoteAddr, delayMs);
    const b = new LoopbackChannel(remoteAddr, delayMs);
    a.peer = b;
    b.peer = a;
    return [a, b];
  }

  send(bytes: Uint8Array): void {
    if (this.dead) return;
    const p = this.peer;
    if (this.delayMs > 0) {
      setTimeout(() => { if (p && !p.dead) p.msg?.(bytes); }, this.delayMs);
    } else {
      queueMicrotask(() => { if (p && !p.dead) p.msg?.(bytes); });
    }
  }
  onData(cb: (bytes: Uint8Array) => void): void { this.msg = cb; }
  onClose(cb: () => void): void { this.cls = cb; }
  close(): void {
    if (this.dead) return;
    this.dead = true;
    const p = this.peer;
    queueMicrotask(() => { if (p && !p.dead) p.cls?.(); });
  }
  /** The far end went away / this end failed: notify our own onClose (the
   *  BufferedChannel.fail() path — how a socket reports being cut). */
  kill(): void {
    if (this.dead) return;
    this.dead = true;
    this.cls?.();
  }
}

/** In-process socket fabric for the transport driver: `listen` registers a
 *  listener per port and `connect` opens a microtask-delivered pipe pair into
 *  it. The fabric is SHARED by every driver in a process (like a real network),
 *  so closing one driver only clears the listeners — it does not poison the
 *  fabric for the others. */
class LoopbackChannels implements ChannelFactoryLike {
  private listeners = new Map<number, (channel: RawLinkLike) => void>();
  private nextPort = 10000;
  private readonly delayMs: number;

  constructor(delayMs = 0) {
    this.delayMs = delayMs;
  }

  /** The bound ports (set by a driver's start()). */
  port = 0;
  wsPort = 0;

  async listen(
    tcp: { host: string; port: number } | undefined,
    ws: { host: string; port: number } | undefined,
    onAccept: (channel: RawLinkLike) => void,
  ): Promise<{ port: number; wsPort: number }> {
    let port = 0, wsPort = 0;
    if (tcp) { port = this.bind(tcp.port, onAccept); }
    if (ws) { wsPort = this.bind(ws.port, onAccept); }
    this.port = port;
    this.wsPort = wsPort;
    return { port, wsPort };
  }

  private bind(requested: number, onAccept: (channel: RawLinkLike) => void): number {
    const port = requested > 0 ? requested : this.nextPort++;
    if (this.listeners.has(port)) throw new Error("LoopbackChannels: port already bound");
    this.listeners.set(port, onAccept);
    return port;
  }

  connect(addr: { host: string; port: number }): RawLinkLike {
    const onAccept = this.listeners.get(addr.port);
    if (!onAccept) {
      // A dial to a dead port: the channel fails immediately on the DIAL side
      // (mirroring ECONNREFUSED → the socket's error/close events), so the
      // transport forgets the link instead of holding it until the deadline.
      const [dial] = LoopbackChannel.pair(addr.host, this.delayMs);
      queueMicrotask(() => dial.kill());
      return dial;
    }
    // The address's host is the "far end" both sides see — it is what the
    // half-open limiter buckets accepts by (the per-source cap; §12.6.1).
    const [dial, accepted] = LoopbackChannel.pair(addr.host, this.delayMs);
    queueMicrotask(() => onAccept(accepted));
    return dial;
  }

  close(): void {
    this.listeners.clear();
  }

  /** A per-node view of this fabric: it dials and listens through the same registry,
   *  but its `close` unbinds only the ports *it* bound.
   *
   *  Sharing one `LoopbackChannels` between nodes is a test convenience — in
   *  production each shell holds its own `NodeChannelFactory` — and the whole-fabric
   *  `close` above is right for teardown and wrong for anything else. An in-place
   *  transport upgrade closes the outgoing driver and re-binds its port, so on the
   *  shared object that would unbind every other node in the test. This is the shape
   *  the file header already claimed: closing one driver clears its listeners without
   *  poisoning the fabric for the others. */
  view(): ChannelFactoryLike {
    const fabric = this;
    const mine: number[] = [];
    return {
      connect: (addr) => fabric.connect(addr),
      async listen(tcp, ws, onAccept) {
        const r = await fabric.listen(tcp, ws, onAccept);
        if (r.port) mine.push(r.port);
        if (r.wsPort) mine.push(r.wsPort);
        return r;
      },
      close() {
        for (const p of mine.splice(0)) fabric.unbind(p);
      },
    };
  }

  /** Release one bound port. The per-node `view()` is the only caller — the fabric's
   *  own `close` drops everything. */
  private unbind(port: number): void {
    this.listeners.delete(port);
  }
}

/** A channel that dies immediately — what a dial to an offline peer's port draws,
 *  mirroring the fabric's own dead-port dial (the dial side's onClose fires and
 *  the transport forgets the link before it ever authenticates). */
function deadChannel(): RawLinkLike {
  const cbHolder: { cb?: () => void } = {};
  queueMicrotask(() => cbHolder.cb?.());
  return {
    send: () => {},
    onData: () => {},
    onClose: (cb) => { cbHolder.cb = cb; },
    close: () => {},
    framing: 0, // FRAMING.PLATFORM — it dies before a byte crosses either way
    remoteAddr: "offline",
  };
}

export class LoopbackNetwork {
  private readonly fabric: LoopbackChannels;
  /** Bound port → the peer that owns it (for offline dial refusal). */
  private readonly portOf = new Map<number, string>();
  private readonly offline = new Set<string>();
  /** Every live channel of a peer (dialed and accepted) — killed on offline. */
  private readonly links = new Map<string, RawLinkLike[]>();

  /** `delayMs` > 0 makes every delivered message take `delayMs` ms to arrive — a
   *  wire-level round-trip latency (one request/response costs 2×delayMs), the model
   *  the latency/concurrency harnesses use now that the kernel's shell has no host
   *  side inbound seam to time against. */
  constructor(delayMs = 0) {
    this.fabric = new LoopbackChannels(delayMs);
  }

  /** The peers' bound ports, for dial wiring. A node binds at most one tcp and
   *  one ws port on the fabric. */
  portOfPeer(peerId: string): { port: number; wsPort: number } | null {
    let found: { port: number; wsPort: number } | null = null;
    for (const [port, owner] of this.portOf) {
      if (owner !== peerId) continue;
      if (!found) { found = { port, wsPort: 0 }; }
      else if (found.port !== port) { found.wsPort = port; }
    }
    return found;
  }

  /** A per-node view of the fabric — hand it to a node as its `channels`. */
  view(peerId: string): ChannelFactoryLike {
    const inner = this.fabric.view();
    const net = this;
    return {
      connect: (addr) => {
        if (addr.transport === "tcp" && net.isOfflinePort(addr.port)) return deadChannel();
        const ch = inner.connect(addr);
        net.track(peerId, ch);
        return ch;
      },
      listen: async (tcp, ws, onAccept) => {
        const r = await inner.listen(tcp, ws, (ch) => {
          net.track(peerId, ch);
          onAccept(ch);
        });
        if (r.port) net.portOf.set(r.port, peerId);
        if (r.wsPort) net.portOf.set(r.wsPort, peerId);
        return r;
      },
      close: () => inner.close(),
    };
  }

  /** Take a peer offline (its links die; dials to it draw nothing) or back online. */
  setOnline(peerId: string, online: boolean): void {
    if (online) {
      this.offline.delete(peerId);
      return;
    }
    this.offline.add(peerId);
    const links = this.links.get(peerId);
    if (links) {
      this.links.delete(peerId);
      for (const ch of links) {
        try { (ch as { kill?: () => void }).kill?.(); } catch { /* already gone */ }
      }
    }
  }

  isOnline(peerId: string): boolean { return !this.offline.has(peerId); }

  /** The shared fabric, for teardown. */
  close(): void { this.fabric.close(); }

  private isOfflinePort(port: number): boolean {
    const owner = this.portOf.get(port);
    return owner !== undefined && this.offline.has(owner);
  }

  private track(peerId: string, ch: RawLinkLike): void {
    let list = this.links.get(peerId);
    if (!list) this.links.set(peerId, (list = []));
    list.push(ch);
  }
}

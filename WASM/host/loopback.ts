// LoopbackNetwork — the in-process network fabric for tests and single-process
// demos. The transport is a signed bundle driven by the shared TransportHost over
// the ChannelFactory seam (seedkernel §12.6); this file is that seam (a loopback
// fabric, one `view()` per node) plus offline/online control. Vendored here
// because seedkernel moved this test/demo infra out of its own runtime.
//
// Going offline kills every link a node holds (dialed or accepted), so the
// transport forgets it and a later dial draws a dead channel (ECONNREFUSED-like) —
// requests then fail within the transport's stall window like a real offline peer.
// There is no re-online in the tests, so going back online is a bookkeeping toggle.

// A destination is opaque to everything above the factory (seedkernel §12.10), so the
// kernel's own parser takes one apart here rather than a second copy of the grammar:
// this fabric routes `tcp://host:port` and nothing else.
import { parseDest } from "seedkernel-wasm/peer-addr";

/** The structural RawLink shape this file needs (socket-seam.ts is not an
 *  exported entry). `framing` restates socket-seam.ts's `FRAMING` (0 PLATFORM,
 *  1 LENGTH, 2 WS_CLIENT, 3 WS_SERVER) as a literal union. The fabric's channels
 *  are PLATFORM by default. Tests may model a chunked byte stream (LENGTH) to
 *  exercise transports such as WebRTC that split a larger logical record. */
export interface RawLinkLike {
  send(bytes: Uint8Array): void;
  onData(cb: (bytes: Uint8Array) => void): void;
  onClose(cb: () => void): void;
  close(graceful: boolean): void;
  readonly framing: 0 | 1 | 2 | 3;
  readonly authority?: string;
  readonly remoteAddr?: string;
  readonly weDialed?: boolean;
  readonly expectPeerId?: string;
}

/** The structural ChannelFactory shape (socket-seam.ts `ChannelFactory`). */
export interface ChannelFactoryLike {
  connect?(dest: string): RawLinkLike | null;
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
  /** A socket pair with `send` as the boundary. In byte-stream mode a send is
   *  split into `chunkBytes`-sized deliveries so LENGTH framing must reassemble it. */
  readonly framing: 0 | 1;
  peer: LoopbackChannel | null = null;
  msg: ((bytes: Uint8Array) => void) | null = null;
  cls: (() => void) | null = null;
  dead = false;
  readonly remoteAddr: string;
  /** Wire latency per delivered message (ms). 0 = the zero-latency fabric. */
  readonly delayMs: number;
  readonly chunkBytes: number;

  constructor(remoteAddr: string, delayMs = 0, chunkBytes = 0) {
    this.remoteAddr = remoteAddr;
    this.delayMs = delayMs;
    this.chunkBytes = chunkBytes;
    this.framing = chunkBytes > 0 ? 1 : 0;
  }

  static pair(remoteAddr: string, delayMs = 0, chunkBytes = 0): [LoopbackChannel, LoopbackChannel] {
    const a = new LoopbackChannel(remoteAddr, delayMs, chunkBytes);
    const b = new LoopbackChannel(remoteAddr, delayMs, chunkBytes);
    a.peer = b;
    b.peer = a;
    return [a, b];
  }

  send(bytes: Uint8Array): void {
    if (this.dead) return;
    const p = this.peer;
    const step = this.chunkBytes > 0 ? this.chunkBytes : Math.max(1, bytes.length);
    const deliver = (chunk: Uint8Array) => {
      if (this.delayMs > 0) {
        setTimeout(() => { if (p && !p.dead) p.msg?.(chunk); }, this.delayMs);
      } else {
        queueMicrotask(() => { if (p && !p.dead) p.msg?.(chunk); });
      }
    };
    if (bytes.length === 0) {
      deliver(bytes);
      return;
    }
    for (let off = 0; off < bytes.length; off += step) {
      deliver(bytes.subarray(off, Math.min(bytes.length, off + step)));
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
  private readonly chunkBytes: number;

  constructor(delayMs = 0, chunkBytes = 0) {
    this.delayMs = delayMs;
    this.chunkBytes = chunkBytes;
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

  /** Dial an opaque destination, as a real `ChannelFactory` does: this fabric speaks
   *  `tcp://host:port`, and anything else is a destination it cannot route. */
  connect(dest: string): RawLinkLike | null {
    const d = parseDest(dest);
    if (!d || d.scheme !== "tcp") return null;
    const onAccept = this.listeners.get(d.port);
    if (!onAccept) {
      // A dial to a dead port: the channel fails immediately on the DIAL side
      // (mirroring ECONNREFUSED → the socket's error/close events), so the
      // transport forgets the link instead of holding it until the deadline.
      const [dial] = LoopbackChannel.pair(d.host, this.delayMs, this.chunkBytes);
      queueMicrotask(() => dial.kill());
      return dial;
    }
    // The destination's host is the "far end" both sides see — it is what the
    // half-open limiter buckets accepts by (the per-source cap; §12.6.2).
    const [dial, accepted] = LoopbackChannel.pair(d.host, this.delayMs, this.chunkBytes);
    queueMicrotask(() => onAccept(accepted));
    return dial;
  }

  close(): void {
    this.listeners.clear();
  }

  /** A per-node view of this fabric: dials/listens through the same registry, but
   *  its `close` unbinds only the ports *it* bound — an in-place transport upgrade
   *  closing its driver must not unbind every other node sharing this fabric. */
  view(): ChannelFactoryLike {
    const fabric = this;
    const mine: number[] = [];
    return {
      connect: (dest) => fabric.connect(dest),
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
  constructor(delayMs = 0, chunkBytes = 0) {
    this.fabric = new LoopbackChannels(delayMs, chunkBytes);
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
      connect: (dest) => {
        const d = parseDest(dest);
        if (d?.scheme === "tcp" && net.isOfflinePort(d.port)) return deadChannel();
        const ch = inner.connect!(dest); // this fabric is dial-capable; ChannelFactory need not be
        // A destination the fabric does not route opened nothing, so there is no
        // channel to hold against this peer's offline switch.
        if (ch) net.track(peerId, ch);
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

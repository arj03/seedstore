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
// seedkernel's own parser takes one apart here rather than a second copy of the grammar:
// this fabric routes `tcp://` and `ws://` by port, and nothing else (`wss://` asks
// for a TLS stack no in-process pair has).
import { parseDest } from "seedkernel-wasm/peer-addr";
import type { ChannelFactory, ListenAddress, RawLink } from "seedkernel-wasm/socket-seam";

/** One end of an in-process socket pair. Delivery is asynchronous (a microtask, or a
 *  `setTimeout(delayMs)` when the fabric models a latency-bearing link), mirroring a
 *  real socket; closing one end fires the other's onClose — the close semantics of
 *  MessageChannel's fail() path, which is how a real channel reports the far side
 *  going away. */
class LoopbackChannel implements RawLink {
  /** A socket pair with `send` as the boundary. In byte-stream mode a send is
   *  split into `chunkBytes`-sized deliveries for the guest to reassemble. */
  readonly stream: boolean;
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
    this.stream = chunkBytes > 0;
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
   *  MessageChannel.fail() path — how a socket reports being cut). */
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
class LoopbackChannels implements ChannelFactory {
  private listeners = new Map<number, (channel: RawLink) => void>();
  private nextPort = 10000;
  private readonly delayMs: number;
  private readonly chunkBytes: number;

  constructor(delayMs = 0, chunkBytes = 0) {
    this.delayMs = delayMs;
    this.chunkBytes = chunkBytes;
  }

  /** One port per address. Framing selection belongs to the transport guest; the socket
   *  factory says only which listener accepted, by its label. */
  async listen(
    addrs: readonly ListenAddress[],
    onAccept: Parameters<ChannelFactory["listen"]>[1],
  ): Promise<number[]> {
    return addrs.map((a) => this.bind(a.port, (ch) => onAccept(ch, { listener: a.label })));
  }

  private bind(requested: number, onAccept: (channel: RawLink) => void): number {
    const port = requested > 0 ? requested : this.nextPort++;
    if (this.listeners.has(port)) throw new Error("LoopbackChannels: port already bound");
    this.listeners.set(port, onAccept);
    return port;
  }

  /** Dial an opaque destination, as a real `ChannelFactory` does: this fabric speaks
   *  `tcp://host:port` and `ws://host:port`, and anything else it cannot route. The
   *  scheme is the DIALER's half of the framing decision (the acceptor's is the
   *  listener label `listen` hands out), so a ws dial has to name the ws port — the
   *  two ends would otherwise pick different codecs for the same pipe. */
  connect(dest: string): RawLink | null {
    const d = parseDest(dest);
    if (!d || (d.scheme !== "tcp" && d.scheme !== "ws")) return null;
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
  view(): ChannelFactory {
    const fabric = this;
    const mine: number[] = [];
    return {
      connect: (dest) => fabric.connect(dest),
      async listen(addrs, onAccept) {
        const ports = await fabric.listen(addrs, onAccept);
        mine.push(...ports);
        return ports;
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
function deadChannel(): RawLink {
  const cbHolder: { cb?: () => void } = {};
  queueMicrotask(() => cbHolder.cb?.());
  return {
    send: () => {},
    onData: () => {},
    onClose: (cb) => { cbHolder.cb = cb; },
    close: () => {},
    remoteAddr: "offline",
  };
}

export class LoopbackNetwork {
  private readonly fabric: LoopbackChannels;
  /** Bound port → the peer that owns it (for offline dial refusal). */
  private readonly portOf = new Map<number, string>();
  private readonly offline = new Set<string>();
  /** Every live channel of a peer (dialed and accepted) — killed on offline. */
  private readonly links = new Map<string, RawLink[]>();

  /** `delayMs` > 0 makes every delivered message take `delayMs` ms to arrive — a
   *  wire-level round-trip latency (one request/response costs 2×delayMs), the model
   *  the latency/concurrency harnesses use now that the host's shell has no host
   *  side inbound seam to time against. */
  constructor(delayMs = 0, chunkBytes = 0) {
    this.fabric = new LoopbackChannels(delayMs, chunkBytes);
  }

  /** A per-node view of the fabric — hand it to a node as its `channels`. */
  view(peerId: string): ChannelFactory {
    const inner = this.fabric.view();
    const net = this;
    return {
      connect: (dest) => {
        const d = parseDest(dest);
        // Any port this fabric bound, under whichever scheme names it — only ports it
        // owns are in `portOf`, so a destination it cannot route still falls through.
        if (d && net.isOfflinePort(d.port)) return deadChannel();
        const ch = inner.connect!(dest); // this fabric is dial-capable; ChannelFactory need not be
        // A destination the fabric does not route opened nothing, so there is no
        // channel to hold against this peer's offline switch.
        if (ch) net.track(peerId, ch);
        return ch;
      },
      listen: async (addrs, onAccept) => {
        const ports = await inner.listen(addrs, (ch, arrival) => {
          net.track(peerId, ch);
          onAccept(ch, arrival);
        });
        for (const port of ports) net.portOf.set(port, peerId);
        return ports;
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

  private track(peerId: string, ch: RawLink): void {
    let list = this.links.get(peerId);
    if (!list) this.links.set(peerId, (list = []));
    list.push(ch);
  }
}

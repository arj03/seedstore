// A Network (seedkernel's transport fabric, host/net.ts) that injects a fixed
// per-send delay, plus instrumentation of how many requests are in flight at
// once. This is the piece every benchmark in the repo was missing.
//
// Why it matters: the LoopbackNetwork delivers frames on a queueMicrotask — it
// models a link with *zero* latency. bench.mjs / bench-wasm.mjs measure only the
// RS codec + crypto compute, and the integration tests run on that same loopback,
// so a PUT that issues ~1,280 *serial* round trips completes in ~0 ms in every
// test. The cost that actually bit us on a real cross-machine cohort — wall-clock
// = round-trip-count × RTT — was therefore invisible to the whole suite. Give the
// link a real RTT and it shows up.
//
// One control request/response is two sends, so the round-trip latency a caller
// observes is 2 × delayMs. Frame layout (host/net.ts): [kind u8][corr u32][type
// u8][payload…]. We read `kind` to pair a request (KIND_REQ) with its response
// (KIND_RES), and `type` to separate the disc.have/want discovery fan-out (which
// is *inherently* concurrent, MsgType.HAVE) from the placement/fetch work whose
// concurrency the coordinator's window actually controls.

const KIND_REQ = 0, KIND_RES = 1;
const TYPE_HAVE = 1; // MsgType.HAVE — discovery fan-out, excluded from the "work" signal

export class LatencyNetwork {
  constructor(delayMs = 2) {
    this.delayMs = delayMs;
    this.sinks = new Map();
    this.offline = new Set();
    this.framesDelivered = 0;
    this.reset();
  }

  /** Zero the concurrency counters between measured runs. */
  reset() {
    this.inflight = 0;          // control requests sent but not yet answered
    this.maxInflight = 0;       // peak of the above (all request types)
    this.inflightWork = 0;      // ditto, excluding the have/want fan-out
    this.maxInflightWork = 0;   // the concurrency the put/get window drove
    this.requests = 0;          // total control requests issued
    this.framesDelivered = 0;
  }

  register(peerId, sink) { this.sinks.set(peerId, sink); }
  unregister(peerId) { this.sinks.delete(peerId); }
  setOnline(peerId, online) { if (online) this.offline.delete(peerId); else this.offline.add(peerId); }
  isOnline(peerId) { return this.sinks.has(peerId) && !this.offline.has(peerId); }

  send(from, to, frame) {
    if (this.offline.has(from) || this.offline.has(to)) return; // dropped
    const sink = this.sinks.get(to);
    if (!sink) return;
    const copy = frame.slice();
    const kind = copy[0], isWork = copy[5] !== TYPE_HAVE;
    if (kind === KIND_REQ) {
      this.requests++;
      if (++this.inflight > this.maxInflight) this.maxInflight = this.inflight;
      if (isWork && ++this.inflightWork > this.maxInflightWork) this.maxInflightWork = this.inflightWork;
    }
    setTimeout(() => {
      if (this.offline.has(from) || this.offline.has(to)) return;
      if (kind === KIND_RES) { this.inflight--; if (isWork) this.inflightWork--; } // requester got its answer
      this.framesDelivered++;
      sink(from, copy);
    }, this.delayMs);
  }
}

// A LoopbackNetwork with a real per-message wire latency — the fabric the
// concurrency/bench harnesses run their cohorts on. Every message the fabric
// delivers takes `delayMs` to arrive, so one request/response round trip costs
// exactly 2×delayMs (pass RTT/2). Request counts/in-flight peaks live in the
// guest instead, read via `StorageNode.stats()` — no network hook needed here.

import { LoopbackNetwork } from "../build/host/loopback.js";

export class LatencyNetwork extends LoopbackNetwork {
  constructor(delayMs = 2, chunkBytes = 0) {
    super(delayMs, chunkBytes);
  }
}

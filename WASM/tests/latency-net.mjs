// A LoopbackNetwork with a real per-message wire latency — the fabric the
// concurrency/bench harnesses run their cohorts on.
//
// WHERE THE MEASUREMENT STANDS has moved twice, and this is the shape the kernel's
// `route/deliver` move left. It began at the receiving shell's host-side inbound seam
// (`createShell({ answer })`), which counted and delayed each arriving app request.
// That seam is gone: the shell delivers an inbound request straight to the app's slot
// and the host no longer sees the request at all (the wire below is the transport
// bundle's record layer — ciphertext, so per-type counting is impossible host-side
// either).
//
// What is left, and what this file is: the LATENCY itself, at the wire. Every message
// the fabric delivers — any direction, any layer, the AKE handshake included — takes
// `delayMs` to arrive, so one request/response round trip costs exactly 2×delayMs
// (which is why the caller passes RTT/2). The request COUNTS and in-flight peaks moved
// into the guest, where the requests are: the seedstore guest tracks them and the
// harness reads them off `StorageNode.stats()` (the `Op.STATS` local op, host/
// protocol.ts `RequestStats`) — clear by reading once before a phase, read after.
//
// So a latency-bearing cohort is just a delayed LoopbackNetwork; the counting needs
// no network hook at all.

import { LoopbackNetwork } from "../build/host/loopback.js";

export class LatencyNetwork extends LoopbackNetwork {
  constructor(delayMs = 2) {
    super(delayMs);
  }
}

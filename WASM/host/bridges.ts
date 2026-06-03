// Storage bridges (README §16). Each bridge is bound to exactly one capability
// and runs the caller-capability check before touching I/O, so only handlers
// that declared the cap at install time can reach it (§8.2). crypto.hash is the
// one no-cap service (§16) — hashing performs no I/O.
//
// These are the kernel.call-facing wrappers (the WASM-reachable surface). The
// node's own host-side orchestration (coordinator/cohort/repair, §17) holds the
// same backends directly and is trusted, exactly as seedkernel keeps its
// installer host-side; the cap gate exists to contain a compromised WASM
// handler, which is where the check earns its keep.

import type { KernelHost, Handler } from "seedkernel-wasm";
import type { Crypto } from "./crypto.js";
import type { BlobStore } from "./store-local.js";
import type { StorageNames } from "./names.js";
import { bytesEqual, writeU32BE, readU32BE, toHex } from "./util.js";

// store.local op tags (§12).
const SL_PUT = 1, SL_GET = 2, SL_HAS = 3, SL_DELETE = 4, SL_STAT = 6;

export interface BridgeBackends {
  crypto: Crypto;
  store: BlobStore;
  clockNow: () => number;
  randBytes: (n: number) => Uint8Array;
  netSend: (peerId: string, bytes: Uint8Array) => void;
}

function callerHasCap(host: KernelHost, capId: Uint8Array): boolean {
  const caller = host.currentCaller;
  if (!caller) return false; // a bridge must be reached through a declaring handler
  return host.getHandlerDeclaredCaps(caller).some((c) => bytesEqual(c, capId));
}

/** Wire all storage bridges onto a KernelHost for one node. Returns nothing —
 *  the backends are owned by the caller (the StorageNode), which uses them
 *  directly for orchestration. */
export function registerStorageBridges(
  host: KernelHost,
  names: StorageNames,
  backends: BridgeBackends,
): void {
  // ── crypto.hash — no capability (§16) ──────────────────────────────────
  const hashHandler: Handler = (_n, payload) => backends.crypto.hash(payload);
  host.register(names.cryptoHash, hashHandler);

  // ── store.local — cap.store (§12) ──────────────────────────────────────
  const storeHandler: Handler = (_n, payload) => {
    if (!callerHasCap(host, names.capStore)) return null;
    if (payload.length < 1) return null;
    const op = payload[0];
    if (op === SL_STAT) {
      const s = backends.store.stat();
      const out = new Uint8Array(12);
      writeU32BE(out, 0, s.quota); writeU32BE(out, 4, s.used); writeU32BE(out, 8, s.free);
      return out;
    }
    if (payload.length < 33) return null;
    const id = payload.slice(1, 33);
    if (op === SL_HAS) return new Uint8Array([backends.store.has(id) ? 1 : 0]);
    if (op === SL_DELETE) return new Uint8Array([backends.store.delete(id) ? 1 : 0]);
    if (op === SL_GET) {
      const v = backends.store.get(id);
      if (!v) return new Uint8Array([0]);
      const dlen = v.descriptor ? v.descriptor.length : 0;
      const out = new Uint8Array(1 + 4 + dlen + v.bytes.length);
      out[0] = 1; writeU32BE(out, 1, dlen);
      if (v.descriptor) out.set(v.descriptor, 5);
      out.set(v.bytes, 5 + dlen);
      return out;
    }
    if (op === SL_PUT) {
      if (payload.length < 37) return null;
      const dlen = readU32BE(payload, 33);
      if (payload.length < 37 + dlen) return null;
      const desc = dlen > 0 ? payload.slice(37, 37 + dlen) : null;
      const bytes = payload.slice(37 + dlen);
      try { backends.store.put(id, bytes, desc); return new Uint8Array([1]); }
      catch { return new Uint8Array([0]); }
    }
    return null;
  };
  host.register(names.storeLocal, storeHandler);

  // ── net.send — cap.net (§16) ───────────────────────────────────────────
  const netHandler: Handler = (_n, payload) => {
    if (!callerHasCap(host, names.capNet)) return null;
    if (payload.length < 1) return null;
    const idLen = payload[0];
    if (payload.length < 1 + idLen) return null;
    const peerId = toHex(payload.slice(1, 1 + idLen));
    backends.netSend(peerId, payload.slice(1 + idLen));
    return new Uint8Array([1]);
  };
  host.register(names.netSend, netHandler);

  // ── clock.now — cap.clock (§16) ────────────────────────────────────────
  const clockHandler: Handler = () => {
    if (!callerHasCap(host, names.capClock)) return null;
    const ms = backends.clockNow();
    const out = new Uint8Array(8);
    // u64 ms, big-endian; JS numbers are exact to 2^53 so the high word fits.
    const hi = Math.floor(ms / 0x100000000);
    writeU32BE(out, 0, hi); writeU32BE(out, 4, ms >>> 0);
    return out;
  };
  host.register(names.clockNow, clockHandler);

  // ── rand — cap.rand (§16) ──────────────────────────────────────────────
  const randHandler: Handler = (_n, payload) => {
    if (!callerHasCap(host, names.capRand)) return null;
    const n = payload.length >= 4 ? readU32BE(payload, 0) : 0;
    if (n <= 0 || n > 0x10000) return null;
    return backends.randBytes(n);
  };
  host.register(names.rand, randHandler);
}

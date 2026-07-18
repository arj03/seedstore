// reputation — the second pure-compute handler (README §13, §17, "no caps").
//
// Each node keeps, per peer, a small *decayed* reciprocity balance built only
// from things it has witnessed directly: verification-fetch passes (the peer
// reliably served data it holds for me) raise its score; misses decay it; and
// old observations fade so a peer that stops serving fades and the state never
// grows without bound (§13.1). The whole computation is arithmetic over
// locally-witnessed events, so it lives here in the pure sandbox — it can never
// reach disk or network even if buggy, which is exactly where you want the
// trust math (§17). Portable/transitive reputation (§20) is a swap-in for this
// handler, not part of the base.
//
// ABI (same scratch discipline as codec):
//   request  = [op u8] [args ...]
//   OP_OBSERVE (1) [pk 32][now u64 BE][result u8]  → [score f64 LE]
//   OP_SCORE   (2) [pk 32][now u64 BE]             → [score f64 LE]
//   OP_COUNT   (3)                                  → [count u32 BE]
//   OP_RESET   (4)                                  → []

const OP_OBSERVE: i32 = 1;
const OP_SCORE: i32 = 2;
const OP_COUNT: i32 = 3;
const OP_RESET: i32 = 4;

// Half-life of the local score (§13.1 recency / §27 tuning knob): 7 days.
const HALF_LIFE_MS: f64 = 7.0 * 24.0 * 3600.0 * 1000.0;
const LN2: f64 = 0.6931471805599453;
// A miss costs more standing than a pass earns, so an unreliable holder decays
// below an honest one quickly (§10 "withholding is detected and routed around").
const PASS_WEIGHT: f64 = 1.0;
const MISS_PENALTY: f64 = 2.0;

// 128 KB — the host reserves at least DEFAULT_SCRATCH_SIZE of scratch headroom
// for an installed handler, even though our ops use only a few dozen bytes of it.
const SCRATCH_SIZE: i32 = 1 << 17;

export let scratch: i32 = 0;
scratch = heap.alloc(SCRATCH_SIZE) as i32;

// Per-peer decayed accumulators, parallel arrays keyed by pubkey.
const pks: Array<Uint8Array> = [];
const serve: Array<f64> = []; // decayed successful-service mass
const miss: Array<f64> = [];  // decayed miss mass
const last: Array<f64> = [];  // last-update timestamp (ms)

function readU64BE(p: i32): f64 {
  // Two big-endian u32 halves combined into an exact f64 (ms fits < 2^53).
  const hi = ((load<u8>(p) as u32) << 24) | ((load<u8>(p + 1) as u32) << 16) |
             ((load<u8>(p + 2) as u32) << 8) | (load<u8>(p + 3) as u32);
  const lo = ((load<u8>(p + 4) as u32) << 24) | ((load<u8>(p + 5) as u32) << 16) |
             ((load<u8>(p + 6) as u32) << 8) | (load<u8>(p + 7) as u32);
  return (hi as f64) * 4294967296.0 + (lo as f64);
}

function findPeer(p: i32): i32 {
  for (let i = 0; i < pks.length; i++) {
    const pk = pks[i];
    let eq = true;
    for (let j = 0; j < 32; j++) {
      if (pk[j] != load<u8>(p + j)) { eq = false; break; }
    }
    if (eq) return i;
  }
  return -1;
}

function addPeer(p: i32): i32 {
  const pk = new Uint8Array(32);
  for (let j = 0; j < 32; j++) pk[j] = load<u8>(p + j);
  pks.push(pk);
  serve.push(0.0);
  miss.push(0.0);
  last.push(0.0);
  return pks.length - 1;
}

// Decay a peer's accumulators forward to `now`.
function decayTo(i: i32, now: f64): void {
  const dt = now - last[i];
  if (dt <= 0.0) { last[i] = now; return; }
  const factor = Math.exp(-LN2 * dt / HALF_LIFE_MS);
  serve[i] = serve[i] * factor;
  miss[i] = miss[i] * factor;
  last[i] = now;
}

// Evict peers whose reciprocity mass, decayed forward to `now`, has fallen below
// 2^-16 of a single observation (≈ 16 half-lives ≈ 16 weeks for a once-seen peer).
// Called only when OBSERVE is about to append a never-seen peer — the one event
// that grows the arrays — so re-observing a known peer pays nothing extra, and a
// faded peer is reclaimed just before the new one lands. The threshold is checked
// against the *decayed* mass: the stored mass is only current as of last[i] (decay
// is applied lazily, per peer, on the next touch), so testing the raw stored mass
// would never evict a peer seen a few times and then gone forever — exactly the
// churn case this guards. Shift-compact the four parallel arrays in place to shrink
// their logical length: the WASM handler can't free heap, but a shorter array
// bounds findPeer/decay cost and prevents unbounded growth (§7).
function prunePeers(now: f64): void {
  const threshold: f64 = (1.0 / 65536.0);
  let w = 0;
  for (let i = 0; i < pks.length; i++) {
    const dt = now - last[i];
    const factor = dt > 0.0 ? Math.exp(-LN2 * dt / HALF_LIFE_MS) : 1.0;
    if ((serve[i] + miss[i]) * factor > threshold) {
      if (w != i) { pks[w] = pks[i]; serve[w] = serve[i]; miss[w] = miss[i]; last[w] = last[i]; }
      w++;
    }
  }
  pks.length = w; serve.length = w; miss.length = w; last.length = w;
}

function scoreOf(i: i32): f64 {
  const s = serve[i] * PASS_WEIGHT - miss[i] * MISS_PENALTY;
  return s;
}

function writeF64(p: i32, v: f64): void {
  // little-endian f64 for easy DataView reads on the host
  const bits = reinterpret<u64>(v);
  for (let j = 0; j < 8; j++) store<u8>(p + j, ((bits >> (8 * j)) & 0xff) as u8);
}

function writeU32BE(p: i32, v: u32): void {
  store<u8>(p, (v >> 24) as u8);
  store<u8>(p + 1, (v >> 16) as u8);
  store<u8>(p + 2, (v >> 8) as u8);
  store<u8>(p + 3, v as u8);
}

export function handle(input_len: i32): i32 {
  if (input_len < 1) return 0;
  const op = load<u8>(scratch) as i32;

  if (op == OP_RESET) {
    pks.length = 0; serve.length = 0; miss.length = 0; last.length = 0;
    return 0;
  }

  if (op == OP_COUNT) {
    writeU32BE(scratch, pks.length as u32);
    return 4;
  }

  if (op == OP_OBSERVE) {
    if (input_len < 1 + 32 + 8 + 1) return 0;
    const pkPtr = scratch + 1;
    const now = readU64BE(scratch + 33);
    const result = load<u8>(scratch + 41) as i32;
    let i = findPeer(pkPtr);
    if (i < 0) { prunePeers(now); i = addPeer(pkPtr); } // prune only when growing
    decayTo(i, now);
    if (result != 0) serve[i] = serve[i] + 1.0;
    else miss[i] = miss[i] + 1.0;
    writeF64(scratch, scoreOf(i));
    return 8;
  }

  if (op == OP_SCORE) {
    if (input_len < 1 + 32 + 8) return 0;
    const pkPtr = scratch + 1;
    const now = readU64BE(scratch + 33);
    const i = findPeer(pkPtr);
    if (i < 0) { writeF64(scratch, 0.0); return 8; }
    decayTo(i, now);
    writeF64(scratch, scoreOf(i));
    return 8;
  }

  return 0;
}

// reputation — the second pure-compute handler (README §13, §17, "no caps").
//
// Each node keeps, per peer, a small *decayed* reciprocity balance built only
// from things it has witnessed directly: verification-fetch passes raise the
// score, misses decay it, and old observations fade so state never grows
// unbounded (§13.1). Living here in the pure sandbox means the trust math can
// never reach disk or network even if buggy (§17).
//
// ABI (same scratch discipline as codec): a PURE TRANSFORM of accumulated
// state — the caller holds the per-peer accumulator and passes it in each
// call, since a WASM module is a restartable transform that discards its
// memory on any timeout.
//   request  = [op u8] [args ...]
//   OP_OBSERVE (1) [serve f64 LE][miss f64 LE][last u64 BE][now u64 BE][result u8]
//     → [serve f64 LE][miss f64 LE][last u64 BE][score f64 LE]
//   OP_SCORE   (2) [serve f64 LE][miss f64 LE][last u64 BE][now u64 BE]
//     → [score f64 LE]

const OP_OBSERVE: i32 = 1;
const OP_SCORE: i32 = 2;

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

function readU64BE(p: i32): f64 {
  // Two big-endian u32 halves combined into an exact f64 (ms fits < 2^53).
  const hi = ((load<u8>(p) as u32) << 24) | ((load<u8>(p + 1) as u32) << 16) |
             ((load<u8>(p + 2) as u32) << 8) | (load<u8>(p + 3) as u32);
  const lo = ((load<u8>(p + 4) as u32) << 24) | ((load<u8>(p + 5) as u32) << 16) |
             ((load<u8>(p + 6) as u32) << 8) | (load<u8>(p + 7) as u32);
  return (hi as f64) * 4294967296.0 + (lo as f64);
}

function readF64(p: i32): f64 {
  // little-endian f64
  const bits = load<u64>(p);
  return reinterpret<f64>(bits);
}

// Decay a peer's accumulators forward to `now` — pure function of elapsed time.
// serve & miss are scaled by exp(-LN2 * dt / HALF_LIFE_MS); last is set to now.
function decayTo(serve: f64, miss: f64, last: f64, now: f64): f64[] {
  const dt = now - last;
  if (dt <= 0.0) return [serve, miss, now];
  const factor = Math.exp(-LN2 * dt / HALF_LIFE_MS);
  return [serve * factor, miss * factor, now];
}

function scoreOf(serve: f64, miss: f64): f64 {
  return serve * PASS_WEIGHT - miss * MISS_PENALTY;
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

function writeU64BE(p: i32, v: f64): void {
  // Convert f64 (safe up to 2^53 - 1) to u64 big-endian.
  // Split v into hi (high 32 bits) and lo (low 32 bits).
  const hi = (Math.floor(v / 0x100000000)) as u32;
  const lo = ((v - (hi as f64) * 4294967296.0) as u32);
  writeU32BE(p, hi);
  writeU32BE(p + 4, lo);
}

export function handle(input_len: i32): i32 {
  if (input_len < 1) return 0;
  const op = load<u8>(scratch) as i32;

  if (op == OP_OBSERVE) {
    // Input: [op u8][serve f64 LE][miss f64 LE][last u64 BE][now u64 BE][result u8]
    // Output: [serve f64 LE][miss f64 LE][last u64 BE][score f64 LE]
    if (input_len < 1 + 8 + 8 + 8 + 8 + 1) return 0;
    let serve = readF64(scratch + 1);
    let miss = readF64(scratch + 9);
    let last = readU64BE(scratch + 17);
    const now = readU64BE(scratch + 25);
    const result = load<u8>(scratch + 33) as i32;

    const decayed = decayTo(serve, miss, last, now);
    serve = decayed[0];
    miss = decayed[1];
    last = decayed[2];

    if (result != 0) serve = serve + 1.0;
    else miss = miss + 1.0;

    const score = scoreOf(serve, miss);

    writeF64(scratch, serve);
    writeF64(scratch + 8, miss);
    writeU64BE(scratch + 16, last);
    writeF64(scratch + 24, score);
    return 32;
  }

  if (op == OP_SCORE) {
    // Input: [op u8][serve f64 LE][miss f64 LE][last u64 BE][now u64 BE]
    // Output: [score f64 LE]
    if (input_len < 1 + 8 + 8 + 8 + 8) return 0;
    const serve = readF64(scratch + 1);
    const miss = readF64(scratch + 9);
    const last = readU64BE(scratch + 17);
    const now = readU64BE(scratch + 25);

    const decayed = decayTo(serve, miss, last, now);
    const decayedServe = decayed[0];
    const decayedMiss = decayed[1];

    // Read-only: no write-back of accumulators.
    const score = scoreOf(decayedServe, decayedMiss);
    writeF64(scratch, score);
    return 8;
  }

  return 0;
}

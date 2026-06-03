# seed store — WASM implementation

An AssemblyScript + TypeScript implementation of **Part I** of the [seed
store](../README.md) spec: a durable, private, self-healing peer-to-peer storage
layer that runs *on* the [seedkernel](https://github.com/arj03/seedkernel). A
node built here runs the same protocol in Node and in the browser.

It composes the reference onion from the spec (§2):

```
storage app handlers (codec, reputation)        ← WASM, pure, no caps
  → cohort + coordinator + repair               ← host orchestration (caps: store/net/clock/rand)
    → storage bridges (crypto.*, store.local, net.send, clock.now, rand)
      → installer → signature → kernel           ← seedkernel, taken verbatim
```

## What lives where, and why

The spec is explicit that the **only** cryptographic-grade algorithm in storage
WASM is Reed–Solomon — libsodium has no erasure coding (§2, §16) — and that the
two pure handlers (`codec`, `reputation`) declare **no capabilities** so the
structural sandbox guarantees they touch neither disk nor network even if buggy
(§17). So:

| Component | Where | Spec |
| --- | --- | --- |
| `codec` — GF(2⁸) + systematic Reed–Solomon RS(k,m) encode/decode, block-id | **WASM** (`assembly/codec`) | §4.1, §4.2, §9 |
| `reputation` — decayed per-peer reciprocity counters | **WASM** (`assembly/reputation`) | §13 |
| `crypto.*` (hash/stream/seal), `store.local`, `net.send`, `clock.now`, `rand` | host bridges (`host/`) | §16, §12 |
| `cohort` (have/want, liveness, verification-fetch) | host (`host/cohort.ts`) | §5, §8 |
| `store.coordinator` (PUT/GET, placement, manifest) | host (`host/coordinator.ts`) | §6, §7 |
| `repair` (self-healing loop) | host (`host/repair.ts`) | §9 |
| manifest + signed chunk descriptor | host (`host/manifest.ts`) | §4.3 |

Hashing, the length-preserving stream cipher (`crypto_stream_xchacha20_xor`),
and key-sealing are **reused** from libsodium (the sumo build, which exposes the
raw stream cipher) — never bundled — exactly as §16 requires. Descriptor signing
uses the same Ed25519 the kernel signs with, invoked sender-side in the host.

The orchestration (cohort/coordinator/repair) is host-side TypeScript rather than
WASM, mirroring how seedkernel keeps its *installer* host-side: it is the
cap-holding logic above the bridges, and a host-side reference makes the async
placement/transfer/repair protocol tractable and deterministically testable. The
codec is **also** installed as a kernel handler on every node (§19), reachable
via `kernel.call`, and the node's fast path drives an in-process copy of it.

## Build

The kernel is a **path dependency** on the sibling seedkernel checkout — this
project runs a node on it, it does not re-implement it. Build seedkernel first:

```sh
(cd ../../seedkernel/WASM && npm install && npm run build)
```

Then, here:

```sh
npm install        # libsodium-wrappers-sumo + assemblyscript + typescript
npm run build      # copy kernel.wasm/bootstrap.wasm, compile codec+reputation WASM, compile host TS
npm test           # build + run the full test suite
```

`npm run build` produces `build/codec.wasm`, `build/reputation.wasm`, the copied
`build/kernel.wasm` + `build/bootstrap.wasm`, and the compiled host in
`build/host/`.

## Run a node

```js
import { createConnectedCohort, loadSodium, loadWasmBytes, LoopbackNetwork } from "./build/host/node.js";

const sodium = await loadSodium();
const wasm = await loadWasmBytes();
const net = new LoopbackNetwork();
const nodes = await createConnectedCohort({ count: 6, network: net, sodium, wasm, config: { k: 2, m: 2, blockSize: 64 } });

const data = new TextEncoder().encode("hello, cohort");
const put = await nodes[0].put(data);                 // chunk → encrypt → RS → place → manifest
const got = await nodes[0].get(put.manifestId, put.key); // locate → fetch any k → decode → decrypt
```

`LoopbackNetwork` wires nodes in one process; a real deployment supplies a
`Network` backed by a WebRTC data channel (the chat demo's transport is one
example, §2). The `BlobStore` backend is in-memory here; a server uses a
directory, a browser uses OPFS/IndexedDB (§12).

## Browser

The host is platform-neutral (it imports seedkernel's `node:fs`-free browser
host). Stage and serve the demo:

```sh
npm run build && npm run build:browser-demo
npx http-server build/browser-demo -p 8080   # then open http://localhost:8080
```

The page boots a cohort of nodes in one browser tab, stores a file with
client-side encryption + erasure coding across them, reads it back, and lets you
take peers offline and watch repair restore redundancy. (Sumo libsodium is
pulled from a CDN via the page's import map; vendor an ESM build to run offline.)

## Tests

`npm test` runs (`tests/run.mjs`):

- **codec** — exhaustive any-*k*-of-*n* recovery across every loss pattern for
  several codes, deterministic encode (keyless repair), systematic pass-through,
  block-id ≡ libsodium SHA-3-256, re-encode regenerates byte-identical blocks.
- **bridges** — crypto host services, the `store.local` backend, and the
  capability gate end-to-end via seedkernel's forwarder fixture (§8.2).
- **manifest** — descriptor/manifest round trips, author signature is
  tamper-evident, manifest encrypt + `manifest_id` stability.
- **reputation** — passes raise / misses penalize / scores decay with a half-life.
- **storage** (multi-node loopback) — PUT→GET, small-file replication, offline
  tolerance (any *k* of *n*), repair restoring redundancy after loss, sharing a
  sealed key, crypto-shredding, reciprocity from served fetches.
- **browser** — the same node booted through the `fetch`-based browser entry.

## Performance

100 MB, RS(10,6), 64 KB blocks, single-threaded (Node 20):

| | time | rate | |
|---|---:|---:|---|
| **write** — full (encrypt + hash + RS encode) | ~0.47 s | ~210 MB/s | |
| &nbsp;&nbsp;↳ xchacha20 encrypt | ~0.18 s | ~545 MB/s | now the largest single piece |
| &nbsp;&nbsp;↳ RS encode (SIMD) | ~0.15 s | ~670 MB/s | |
| &nbsp;&nbsp;↳ BLAKE2b block-ids | ~0.14 s | ~1.1 GB/s | hashes all *n* blocks (1.6×) |
| **read** — all data present (systematic) | ~0.03 s | ~3 GB/s | common path — a concat, no GF |
| **read** — one block missing (decode, SIMD) | ~0.16 s | ~625 MB/s | the common failure, §6/§21 |

Three optimizations got here. (1) The codec multiplies via a precomputed 256×256
GF(2⁸) table — one indexed load per byte — making encode **~26× faster** than the
naive exp/log multiply. (2) Block-ids hash with **BLAKE2b** instead of SHA-3,
**~6× faster** (~0.83 s of SHA-3 was the original write bottleneck) and, like
everything else, already in the libsodium the kernel loads — **no new bytes**
(§16). (3) The RS multiply-accumulate loops use **WASM SIMD** — the GF(2⁸)
split-table / `i8x16.swizzle` trick does 16 multiplies per instruction — for
another **~3.4×** on encode/decode. With all three, the write is balanced across
encrypt / encode / hash (each ~0.15 s, no single bottleneck) and reads cost
nothing on the codec unless a block is actually missing. (SIMD needs a runtime
with the WASM simd feature — Node 16+ and every current browser.) `node
tests/bench.mjs` reproduces these.

**The SIMD split-table trick (GF(2⁸) "PSHUFB").** For a fixed coefficient *c*,
`c·x` is split into two 4-bit lookups: `c·(x & 0x0F) ⊕ c·(x >> 4)`, each a 16-byte
table. WASM's `i8x16.swizzle` is a 16-lane parallel table lookup, so one
instruction multiplies 16 bytes at once; output accumulators stay in `v128`
registers across the *k* inputs (register blocking), with a scalar tail for a
block whose size is not a multiple of 16. This is the same kernel native RS
libraries use, and it lines up with the uniform *B*-byte blocks — the same shape
that would let a BLAKE3 `hash_many` vectorize the block-id hashing next.

**Block-id hash choice (BLAKE2b, and the BLAKE3 next step).** Block-ids are
content addressing *internal* to storage — they never cross into the kernel — so
they need not be the kernel's SHA-3 genesis hash; the content hash is a `Crypto`
constructor argument (`sha3-256` stays available for genesis-identical ids,
`blake2b-256` is the default). The next step up is **BLAKE3**: its tree of
equal-size leaves lines up with the layer's own uniform *B*-byte block splitting,
so a vectorized `hash_many` produces all *n* block-ids of a chunk across parallel
SIMD lanes, and the independent per-block hashes thread trivially — projected
multi-GB/s. Reusing BLAKE3 *interior tree nodes* as block-ids, by contrast, does
**not** fit: content-addressed ids must be position-independent (a holder
re-verifies `hash(bytes) == id` with no context, §4.2; a bulk frame is
`[id ∥ bytes]`, §3), while BLAKE3 interior chaining values are position-dependent
— and that path would re-introduce the Merkle-path machinery the spec deliberately
avoids (§8).

## Footprint

Source — the storage layer itself:

| | LOC |
|---|---:|
| **codec** WASM — GF(2⁸) + Reed–Solomon (`gf256` + `rs` + `index`) | 352 |
| **reputation** WASM — decayed reciprocity | 146 |
| **host** TypeScript — bridges, crypto, manifest, cohort/coordinator/repair, node (19 files) | 1,951 |
| **total** | **2,449** |

(plus ~990 LOC of tests and ~210 of scripts + the browser demo.)

Runtime artifacts a node loads:

| artifact | size | gzipped |
|---|---:|---:|
| `codec.wasm` (incl. SIMD RS + GF tables) | 6.9 KB | — |
| `reputation.wasm` | 6.9 KB | — |
| `kernel.wasm` + `bootstrap.wasm` (from seedkernel) | 12.7 KB | — |
| host JS — this project + seedkernel `KernelHost` | 130 KB | **34 KB** |
| libsodium (sumo) — reused, not bundled | 278 KB | — |

So the whole storage layer is **~14 KB of WASM + ~34 KB of gzipped JS**, riding on
the kernel and the libsodium the deployment already carries (§2, §16: "logic + RS,
tens of KB, no second copy of a crypto library"). The host JS is unminified (doc
comments preserved); a bundler/minifier shrinks it further.

## Layout

```
assembly/codec/        gf256.ts, rs.ts, index.ts   — Reed–Solomon WASM handler
assembly/reputation/   index.ts                    — decayed reciprocity WASM handler
host/                  bridges, crypto, store-local, net, manifest, codec/reputation
                       clients, cohort, coordinator, repair, storage-node, node/browser
browser/index.html     in-browser demo page
scripts/               copy-kernel, build-browser-demo
tests/                 codec / bridges / manifest / reputation / storage / browser
```

## Scope

This implements **Part I** (the complete minimal system). The Part II extensions
— verifiable/transitive reputation (§20), LRC (§21), dedicated bulk channel
(§22), less-trusted-cohort hardening (§23), convergent encryption (§24),
tombstones (§25), and Shamir key recovery (§26) — are deliberately out of scope;
each is an add-on reached for only when a specific assumption changes.

A few Part I behaviours are modelled in a deliberately simple reference form and
called out in the code: the Suspected/Lost grace window (§8) is represented by
"verified-live vs not", admission/eviction (§14) is quota + the sibling rule
rather than the full eviction-score, and the bulk plane (§3) rides the same
awaited request/response channel rather than a separate unsigned frame stream.

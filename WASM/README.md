# seed store — WASM implementation

An AssemblyScript + TypeScript implementation of **Part I** of the [seed
store](../README.md) spec: a durable, private, self-healing peer-to-peer storage
layer that runs *on* the [seedkernel](https://github.com/arj03/seedkernel). A
node runs the same protocol in Node, in Bun, and in the browser.

## seed store is content, not a binary

The deployable artifact is the **generic seedkernel runtime** (the "shell"). It
exposes only **raw-byte capabilities** — crypto, `net.*`, `fs.*`, an
installed-handler call, a clock — and knows nothing about storage. seed store
ships as **signed content** that the shell loads and *becomes* a storage node:

```
seed store bundle (seedstore.skb — one signed blob, verified at load) ─────────────────┐
  codec.wasm  reputation.wasm        pure RS + reputation math, declare no capabilities │
  guest.js                           PUT/GET/repair (initiator) + HAVE/OFFER/STORE/      │
                                     FETCH (holder): zero-authority JS, no ambient I/O   │
        │  reaches I/O only through ↓ the single capability seam                        │
  cap-bridge   crypto · net · fs · module-call · clock · identity  ── generic primitives ┘
        │
  seedkernel runtime (the shell)     bundle loader → admission policy → kernel  +  the raw-byte caps
```

Everything with *structure* — content-addressing, the signed chunk descriptor,
the HAVE/OFFER/STORE/FETCH wire format, Reed–Solomon, the nonce convention, the
quota — is **seed store's**, and lives in the bundle. The kernel only moves
opaque bytes. So the same shell can host storage or any other signed app, and a
storage upgrade is new content, not a new binary (spec §2.1, §17). The runtime
side of this — the shell, the capability vocabulary, the confinement realms, and
the bundle format — is documented in
[seedkernel](https://github.com/arj03/seedkernel)'s README ("The runtime as an
app host").

## What lives where, and why

The spec is explicit that the **only** cryptographic-grade algorithm in storage
WASM is Reed–Solomon — libsodium has no erasure coding (§2, §16) — and that the
two pure handlers (`codec`, `reputation`) declare **no capabilities** so the
structural sandbox guarantees they touch neither disk nor network even if buggy
(§17). Under the runtime split, *all* storage logic is confined Tier-2 content:

| Component | Where it runs | Form | Spec |
| --- | --- | --- | --- |
| `codec` — GF(2⁸) + systematic Reed–Solomon RS(k,m) encode/decode, block-id | installed kernel handler | **WASM**, no caps (`assembly/codec`) | §4.1, §4.2, §9 |
| `reputation` — decayed per-peer reciprocity counters | installed kernel handler | **WASM**, no caps (`assembly/reputation`) | §13 |
| coordinator (PUT/GET, placement, manifest) + cohort (have/want, verification-fetch) + repair | confined QuickJS realm — **async** `call()` | zero-authority JS (`host/tier2-guest.js`) | §5–§9 |
| holder side — admission, sibling rule, content-addressing, quota, the store writes | the **same** realm — **sync** `callSync()` | zero-authority JS (`host/tier2-guest.js`) | §6, §10, §14 |
| the capability seam the guest reaches I/O through | seedkernel runtime | `cap-bridge` (generic primitives) | §16 |
| `crypto.*`, `net.*`, `fs.*`, `clock` backends | seedkernel runtime | raw-byte capabilities | §12, §16 |

Hashing, the length-preserving stream cipher (`crypto_stream_xchacha20_xor`),
and signatures are **reused** from the runtime's libsodium (the sumo build, which
exposes the raw stream cipher) — never bundled — exactly as §16 requires; the
guest reaches them as generic `cap-bridge` primitives and builds its own
descriptor envelope and nonce convention on top of the scoped `SIGN`
(seedkernel §12.2) — how storage prefixes and checks it is below.

**The one realm.** Storage runs its whole guest in a single confined realm
seedkernel provides (§12.3), over its genuinely-async seam: the initiator
(PUT/GET/repair) is async — it fans out over `net` and awaits *real* net promises
(`await Promise.all(...)`) — through the realm's `call()`, while the holder side
answers from local `fs` + crypto without yielding, through the same realm's
synchronous `callSync()`, so it can serve a request *while this node's own
initiator is parked mid-`await`* in that realm — a suspended async function is
just heap state, and `callSync` never pumps the job queue, so it cannot advance
the parked initiator. `StorageNode` (`host/storage-node.ts`) keeps a host-side
copy of both sides as the reference/parity path — the role the host-side classes
play in the tests — but the **shipped** node runs the confined guest.

## Signing scope, existence, and bundle versioning

Three seedkernel runtime contracts reach into the storage code, and each has a
seedstore-side counterpart worth pinning down. The contracts themselves are
documented on the runtime side — the **scoped `SIGN`** op (a guest signature is
over `DOMAIN_guest ‖ scope ‖ msg`, the `scope` host-derived from the admitted
manifest; `VERIFY` stays raw — seedkernel §12.2), **existence-by-size** (no
`FS_HAS`; a key exists iff `FS_SIZE ≥ 0`, and `./fs` is
`get`/`put`/`size`/`list`/`delete`/`stat` — seedkernel §12.1–§12.2), and the
**monotonic bundle `version`** that refuses a downgrade (seedkernel §12.4). The
spec-side story is in the [seed store spec](../README.md) (§16). This section is
the code map for where each lands in this repo — the guest, the host parity
mirror, and the bundle producer:

1. **Signatures are scoped on both paths**
   (`host/tier2-guest.orchestration.js`). The descriptor envelope stays
   `[authorPk 32][sig 64][core ..]` — the prefix is preimage-only, never stored
   — but `signCore` passes the bare core to the scoped `CAP_SIGN`, which signs
   `DOMAIN_guest ‖ scope ‖ core`, and `verifyEnv` reconstructs that same preimage
   before the raw `CAP_VERIFY`. The host mirror
   (`signDescriptor`/`verifyDescriptor` in `host/manifest.ts`) produces and
   checks byte-identical preimages, so the `tier2-port`/`holder-guest` parity
   tests hold. The guest gets the scope bytes host-derived, and never from
   author-written config: both drivers inject them through seedkernel's shared
   `bundlePreamble` as `BUNDLE.signPrefix` — the shell from the admitted
   manifest's `(author, app)`, an in-process `StorageNode` from its `signAuthor`
   (the zero author by default). One derivation, so the two cannot disagree; a
   hand-baked copy in the signed config could, and would fail as signatures that
   verify nowhere.
2. **The descriptor's leading byte is the signed-format tag** (spec §16). The
   descriptor core leads with `TAG_DESCRIPTOR = 0x01` (`manifest-core.ts`), and
   the Part II signed formats reserve their own values before they exist
   (`TAG_TOMBSTONE = 0x02`, `TAG_HEAD = 0x03`). The tag sits inside `core`, so
   it is already under the signature and inside the scoped preimage.
3. **`storeHas` answers from `FS_SIZE ≥ 0`**
   (`host/tier2-guest.orchestration.js`): the `fsSize` seam distinguishes absent
   (the bridge's −1 sentinel) from present-but-empty, so there is no `has` call
   to make. Same move host-side — `store-fs.ts` asks `fs.size(...) >= 0` — with
   the seedstore `BlobStore.has` iface itself unchanged, only its backing call.
4. **The bundle carries an integer, monotonic `version`**
   (`scripts/storage-bundle.mjs`): guarded by `Number.isInteger` and bumped on
   every publish, so the shell's freshness check (§12.4) has a real high-water
   mark to enforce.
5. **The tests that pin this**: `manifest` (tamper-evidence over the tagged,
   scoped preimage), `tier2-port` / `holder-guest` (parity across the scoped
   sign/verify paths), `shell-run` (bundle version freshness — a downgrade is
   refused), `net` (`FsBlobStore` existence via `size ≥ 0`, riding the encrypted
   record layer transparently).

**Purely storage-side, independent of all this:** the codec and reputation
WASM, the HAVE/OFFER/STORE/FETCH wire format and its windowing, content
addressing, the nonce convention, and the quota. The storage *structure* is the
app's own; only how signatures are prefixed, how existence is asked, and how the
bundle versions itself follow the kernel contracts above.

## Build

The kernel is a **path dependency** on the sibling seedkernel checkout — this
project runs a node on it, it does not re-implement it. Build seedkernel first:

```sh
(cd ../../seedkernel/WASM && npm install && npm run build)
```

Then, here:

```sh
npm install        # one dependency: the sibling seedkernel-wasm (sumo libsodium + QuickJS live there)
npm run build      # compile codec+reputation WASM, stage the guest, compile host TS
npm test           # build + run the full test suite (Node); `bun tests/run.mjs` runs it on Bun
```

`npm run build` produces `build/codec.wasm`, `build/reputation.wasm`, the staged
`build/host/tier2-guest.js`, and the compiled host in `build/host/`.

## Run a node from the command line

A node is the generic seedkernel **shell** plus the signed seed store **bundle**.
First build the bundle once (the offline producer holds the app author key):

```sh
npm run build:bundle      # → ./bundle/ (manifest + codec/reputation wasm + installs + guest),
                          #   signed by ./seedstore-author.key (minted on first run; keep it secret)
```

The shell admits content only from authors named in its policy file
(seedkernel §12.5). Take the author public key it printed (`author …`) and allow
it:

```sh
echo '{ "authors": ["<author-pubkey-hex>"] }' > allowed-keys.json
```

Now run the shell from the seedkernel checkout. A **serving** node that has loaded
a bundle becomes a full storage node — it installs the modules, runs the confined
guest, and serves the holder side (HAVE/OFFER/STORE/FETCH) over TCP (and WebSocket
for browsers):

```sh
SHELL=../../seedkernel/WASM/build/host/main.js     # the generic runtime

# a holder: verifies + installs the bundle, then serves the confined holder side
node "$SHELL" --policy allowed-keys.json --bundle ./bundle/seedstore.skb \
     --dir ./data-A --key ./A.key --listen 127.0.0.1:7401
#   seedkernel-shell <peer-pubkey>
#     bundle seedstore v1 → installed codec, reputation
#     holder serving the app's request side from the confined guest
#     tcp    listening on :7401
```

Start a few holders on different ports/dirs (each prints its `<peer-pubkey>`), then
PUT a file from a client that lists them as `--peers` (`<pubkey>@host:port`, comma-
separated). The client orchestrates PUT inside the confined guest and places blocks
across the cohort:

```sh
node "$SHELL" --policy allowed-keys.json --bundle ./bundle/seedstore.skb --dir ./client \
     --peers "<pkA>@127.0.0.1:7401,<pkB>@127.0.0.1:7402,<pkC>@127.0.0.1:7403,<pkD>@127.0.0.1:7404" \
     --put ./notes.txt
#   PUT ok: 8 chunk(s)                 ← a ~4 KB file at the default RS(2,2)/256 B blocks
#     --get bdbc41…:74a32f…            ← manifest-id : content-key K

node "$SHELL" --policy allowed-keys.json --bundle ./bundle/seedstore.skb --dir ./client \
     --peers "<pkA>@…,<pkB>@…,<pkC>@…,<pkD>@…" \
     --get bdbc41…:74a32f… --out ./restored.txt
#   GET ok: 4000 B → ./restored.txt
```

`--get` is `<manifest-id>:<key>` — the pair PUT printed; without `--out` the bytes
go to stdout. The manifest-id locates the file; the key `K` decrypts it (lose `K`
and the holders keep only permanent noise, §11). The shell flags themselves
(`--listen`/`--ws-listen`/`--peers`/`--dir`/`--key`/`--timeout`) are the generic
ones (seedkernel §12.8); `--put`, `--get`, and the storage bundle are what this
node adds. A node with no listener is a pure client; one with
`--listen`/`--ws-listen` keeps serving until Ctrl-C.

> A self-contained single-file binary is `bun build --compile` of the shell
> (`seedkernel/WASM/host/main-bun.ts`) with kernel + signature embedded; it loads
> the same bundle. The shell is application-neutral, so this binary can host any
> signed app, not just storage.

### As a library (in-process)

For tests and embedding, drive nodes directly over an in-process network:

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

`LoopbackNetwork` wires nodes in one process. There is one protocol
implementation: `put`/`get`/`repair` always run the *confined* guest
(`host/tier2-guest.orchestration.js`) inside a QuickJS realm, and the holder side
(HAVE/OFFER/STORE/FETCH) runs the same guest in a synchronous realm —
`StorageNode` is just the host that boots the kernel and drives it (§19, §2.1).
The `BlobStore` backend is in-memory by default; a server uses a directory
(`new NodeFs(dir)`), a browser uses OPFS/IndexedDB (§12).

## Browser

The host is platform-neutral (it imports seedkernel's `node:fs`-free browser
host). One build stages both browser pages into `build/browser-demo`:

```sh
npm run build && npm run build:browser-demo
npx http-server build/browser-demo -p 3000
#   in-tab cohort:          http://localhost:3000/index.html
#   real P2P (relay+STUN):  http://localhost:3000/p2p.html    (relay + holders, below)
```

**`index.html`** boots a cohort of nodes in one browser tab, stores a file with
client-side encryption + erasure coding across them, reads it back, and lets you
take peers offline and watch repair restore redundancy.

**`p2p.html`** makes each *tab* a full storage node. Tabs — and **console nodes** —
find each other through a WebSocket signaling relay (`npm run demo:relay`) and then
talk **directly, peer-to-peer over WebRTC**: the relay only introduces peers, STUN
punches the path through NAT, and no server sits in the data path. A file dropped in
one is encrypted and erasure-coded (RS(1,1)) across the others; any node rebuilds it
from the retrieval token. Run the cohort either as **3+ tabs** in the same room, or
as one tab plus **console holders** — the same `RtcNetwork`, driven on the Node/Bun
side by werift's pure-JS WebRTC (§12.6):

```sh
npm run demo:relay          # the signaling relay (Node), ws://localhost:8080
npm run serve:rtc-holder    # a real StorageNode joining the room over relay+STUN (Bun); run two
#   then open http://localhost:3000/p2p.html  (relay ws://localhost:8080, room "seedstore-demo")
```

(`npm run smoke:rtc` proves the same PUT→GET path headless — owner + holders, no relay
process or browser.)

(Sumo libsodium is pulled from a CDN via the pages' import maps; vendor an ESM
build to run offline. Public STUN lets tabs on different machines/NATs find a
path; same-machine tabs connect on host candidates without it.)

## Tests

`npm test` runs (`tests/run.mjs`):

- **codec** — exhaustive any-*k*-of-*n* recovery across every loss pattern for
  several codes, deterministic encode (keyless repair), systematic pass-through,
  block-id ≡ libsodium BLAKE2b-256, re-encode regenerates byte-identical blocks.
- **bridges** — crypto host services, the `store.local` backend, and the
  capability gate end-to-end via seedkernel's forwarder fixture (§8.2).
- **manifest** — descriptor/manifest round trips, author signature is
  tamper-evident, manifest encrypt + `manifest_id` stability, and the one-model
  descriptor math: coded vs. replicated by id count, `r` = *m*+1, the placement
  slots, and the loss margin agreeing for both kinds at production geometry.
- **protocol** — the batched OFFER/FETCH wire (`host/protocol.ts`): self-delimiting
  offer entries, the per-block accept mask, FETCH present/absent blocks, and a
  holder admitting a whole OFFER batch at once — the §6 sibling rule declines a
  sibling offered alongside, the §14 quota declines the tail once the budget is spent.
  The signed chunk descriptor is mandatory on both OFFER and STORE (§4.3): a
  descriptor-less entry fails to decode, and one that is forged, of another chunk, or
  disagrees with the bytes in hand is declined by the holder.
- **reputation** — passes raise / misses penalize / scores decay with a half-life.
- **storage** (multi-node loopback) — PUT→GET, small-file replication, offline
  tolerance (any *k* of *n*), repair restoring redundancy after loss (including a
  mixed-geometry cohort, where a holder configured RS(1,1) still heals an RS(1,4)
  chunk back to the *r* = 5 its descriptor signs), sharing a sealed key,
  crypto-shredding, reciprocity from served fetches.
- **concurrency** — PUT/GET round-trip economy over a *latency-bearing* link:
  OFFER/STORE/FETCH are batched and windowed *per holder* rather than issued per
  block, so wall-clock tracks round-trip-count × RTT — the cost the zero-latency
  loopback hides (asserted as request counts, not just wall-clock).
- **net** — networking + filesystem integration: `FsBlobStore` persisting across
  reopen, a full cohort over real TCP sockets with blocks landing on holders'
  disks, and a browser-like node reaching a server over a real WebSocket.
- **tier2-port** — the same PUT/GET/replication/offline/repair/crypto-shredding
  matrix driven *inside* the confined QuickJS realm over the generic `cap-bridge`,
  with cross-path parity proving the confined and host-side paths are byte-compatible.
- **shell-run** — a generic seedkernel-shell (no seed store imports) loads the
  signed bundle and runs the guest as the PUT/GET *initiator* against a cohort.
- **holder-guest** — a cohort of generic shells runs storage end-to-end with the
  *holder* side confined too; a guest initiator and a host-side initiator place
  concurrently (so a shell serves its holder side via `callSync` while its own
  initiator is parked mid-await in that same realm); and a host-side initiator →
  confined shell holders round-trips (parity).
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

**End to end, the link bounds throughput, not the codec.** A multi-MB file is
many blocks, and a WebRTC data channel caps a message at ~one 32 KiB block, so a
naïve transfer pays one round trip *per block*. The coordinator avoids that by
**windowing** — `putWindow`/`getWindow` keep many blocks per holder in
flight at once — so wall-clock tracks `RTT × (chunks ÷ window)`, not `RTT ×
blocks`. Over a 10 ms-RTT, WebRTC-capped link (4 MB, RS(2,2), 32 KiB blocks,
window 32):

| | time | rate | |
|---|---:|---:|---|
| **PUT** | ~370 ms | ~11 MB/s | ships the 2× erasure overhead — RS(2,2) is 2 data + 2 parity |
| **GET** | ~240 ms | ~17 MB/s | downloads any *k* of *n* — 1× the file |

`node tests/bench-net.mjs 10 4 32` reproduces this and sweeps the window; over a
real browser↔browser WebRTC link the `p2p.html` demo reports ~13 MB/s both ways.

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
they are storage's own choice, not something the kernel imposes, and storage hashes
them with **BLAKE2b** (`crypto_generichash`) — fast and already in libsodium.
(seedkernel has since standardized on BLAKE2b-256 as its own genesis hash too, so
the two now coincide — but independently, not because one constrains the other.) The next step up is **BLAKE3**: its tree of
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
| **codec** WASM — GF(2⁸) + Reed–Solomon (`gf256` + `rs` + `index`) | 417 |
| **reputation** WASM — decayed reciprocity | 152 |
| **host** TypeScript — crypto.hash bridge, crypto, manifest (+core), protocol, store, storage-node, node (15 files) | 1,292 |
| **tier2-guest.js** — the confined PUT/GET/repair + holder guest (the whole protocol) | 896 |
| **total** | **2,757** |

(plus ~2,100 LOC of tests and ~530 of scripts + the browser demo.)

Runtime artifacts. A shipped node is the generic seedkernel **shell** plus the
signed **bundle**: the shell verifies the bundle, installs the two wasm cores, and
runs the guest. So the *seedstore* content a bundle node loads is just the two
cores and the guest — it never loads a line of the host-side TypeScript:

| artifact | size | gzipped |
|---|---:|---:|
| `codec.wasm` (incl. SIMD RS + GF tables) | 8.5 KB | — |
| `reputation.wasm` | 6.7 KB | — |
| `guest.js` — the confined guest, shipped minified in the bundle | 29 KB | **7.6 KB** |

riding on the seedkernel shell it shares with any app — the `KernelHost` JS
(28 KB / **5 KB gz**, handler table included: the kernel is host code, not a
module) and the sumo libsodium (278 KB, reused not bundled). So **seedstore's own runtime
footprint is ~15 KB of WASM + ~8 KB of gzipped JS (the guest)** (§2, §16: "logic +
RS, tens of KB, no second copy of a crypto library").

The host-side TypeScript (`build/host`, minified to `build/host-min`) is a
*separate* path — the **in-process library** (it boots the kernel and runs the same
guest in-process) that the browser demo and the `createConnectedCohort` tests load
*instead* of the shell+bundle. Minified it is **21 KB gz** (14 KB gz without its own
copy of the guest), debug 42 KB gz — so a browser-demo node carries ~26 KB gz of JS
(host + the shared `KernelHost`) against a bundle node's ~13 KB (the 8 KB guest +
the 5 KB `KernelHost`).

`npm run build` emits the host **twice**: the readable `build/host` (doc comments
intact, for debugging) and a comment-stripped `build/host-min` (for the in-process
library + browser demo).
Over half the gzipped host bytes were doc comments — the source is heavily
annotated — so stripping them roughly halves the wire size (42 → 21 KB gz). The
"minifier" is a ~70-line dependency-free comment stripper (`scripts/minify.mjs`),
**not** a bundler or terser: it preserves string/template contents and gates every
emitted file through `node --check`, so a stripper mistake fails the build rather
than shipping broken JS. The same step runs in seedkernel too, shrinking that
shared host from 11 to ~5 KB gz; `npm run build:browser` stages both minified
hosts (`build/host-min`) into the demo.

## Layout

```
assembly/codec/        gf256.ts, rs.ts, index.ts   — Reed–Solomon WASM handler
assembly/reputation/   index.ts                    — decayed reciprocity WASM handler
host/  tier2-guest.js          the confined guest: the WHOLE protocol (PUT/GET/repair + holder)
       storage-node.ts         the host that holds the handler table + drives the guest in one realm
       manifest (+core)/crypto/protocol/store-fs/store-local/names/util  — shared helpers
       node.ts / browser.ts    Node + browser entry points (each loads the guest text)
scripts/  build-bundle.mjs     produce the signed bundle (npm run build:bundle)
          build-browser-demo               — stage all browser pages → build/browser-demo
          serve-rtc-holder + smoke-rtc        — relay-signaled P2P over RtcNetwork + STUN
tests/    codec / bridges / manifest / protocol / reputation / storage
          concurrency / net / browser / shell-run / holder-guest / bundle-fixture
```

The runtime itself — the shell, the `cap-bridge`, the `fs.*`/`net.*` capabilities,
the QuickJS confinement realms, the bundle format and policy — lives in
[seedkernel](https://github.com/arj03/seedkernel); seed store consumes it as the
`seedkernel-wasm` dependency and ships only the content above.

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
awaited request/response channel rather than a separate unsigned frame stream —
not a simplification at all but exactly what the kernel transport specifies: it
has no separate bulk frame kind, so block bytes ride ordinary req/res bodies
(inside the encrypted record layer) and content-addressing stays the app-level
admission check.

PUT also places **best-effort**: it spreads a chunk's placement slots across as
many distinct holders as the cohort offers (one block per holder, the §6/§10
sibling rule) and succeeds once at least *k* distinct blocks land, rather than
requiring every slot filled up front. Redundancy then falls below the chunk's
target on a thin cohort and repair (§9) restores it as holders appear — which is
what lets the browser demos store across just one or two holders. A deployment
that must *guarantee* the full durability at write time would instead fail the
PUT; the reference favours liveness.

**Coded and replicated chunks are one model.** A chunk is *k* + *m* ids (coded,
one block per holder) or *k* ids (replicated, each on *r* = *m*+1 holders), and
both record the same *m* — "survives *m* losses" (§4.1). Placement expands either
into the same list of slots, so `placeChunksBatched` fans both out identically;
reads take any *k* listed blocks; and repair is one audit against one health
number, the **loss margin**, healed back to whatever the chunk's own signed
descriptor asks for. Nothing about durability is injected config: *r* and the
low-water mark ⌈*m*/2⌉ are read off the descriptor (`replicaTarget` /
`lowWaterMargin` in `manifest-core.ts`), so a repairer needs no deployment config
and a mixed-geometry cohort heals each chunk to the count its author signed. The
browser demos run *k*=1 deliberately — surviving the loss of a holder in a two- or
three-node cohort means replication, not coding — and a *k*=1 chunk is simply the
replicated shape, never an RS code whose parity would come out byte-identical to
its lone data block.

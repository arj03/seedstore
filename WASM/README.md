# seed store — WASM implementation

An AssemblyScript + TypeScript implementation of **Part I** of the [seed
store](../README.md) spec: a durable, private, self-healing peer-to-peer storage
layer that runs *on* the [seedkernel](https://github.com/arj03/seedkernel). A
node runs the same protocol in Node, in Bun, and in the browser.

## seed store is content, not a binary

The deployable artifact is the **generic seedkernel runtime** (the "shell"),
which knows nothing about storage. seed store ships as **signed content** that
the shell loads and *becomes* a storage node:

```
seed store bundle (seedstore.skb — one signed blob, verified at load) ─────────────────┐
  codec.wasm  reputation.wasm        pure RS + reputation math, declare no grants     │
  guest.js                           PUT/GET/repair (initiator) + HAVE/OFFER/STORE/      │
                                     FETCH (holder): zero-authority JS, no ambient I/O   │
        │  reaches I/O only through ↓ the one guest seam                                 │
  host.call   crypto · fs · node · clock · bare module names · local service ids ──────┘
        │
  seedkernel runtime (the shell)     bundle loader → admission policy → kernel  +  the raw-byte seams
```

Everything with *structure* — content-addressing, the signed chunk descriptor,
the HAVE/OFFER/STORE/FETCH wire format, Reed–Solomon, the nonce convention, the
quota — is **seed store's**, and lives in the bundle. The kernel only moves
opaque bytes. So the same shell can host storage or any other signed app, and a
storage upgrade is new content, not a new binary (spec §2.1, §17). The runtime
side of this — the shell, the guest seam and its grants, the confinement realms,
and the bundle format — is documented in [seedkernel §12](https://github.com/arj03/seedkernel/blob/main/docs/RUNTIME.md)
and [EXPORTS](https://github.com/arj03/seedkernel/blob/main/docs/EXPORTS.md).

## What lives where, and why

The spec is explicit that the **only** cryptographic-grade algorithm in storage
WASM is Reed–Solomon — libsodium has no erasure coding (§2, §16) — and that the
two pure modules (`codec`, `reputation`) declare **no grants** so the
structural sandbox guarantees they touch neither disk nor network even if buggy
(§17). Under the runtime split, *all* storage logic is confined Tier-2 content:

| Component | Where it runs | Form | Spec |
| --- | --- | --- | --- |
| `codec` — GF(2⁸) + systematic Reed–Solomon RS(k,m) encode/decode, block-id | installed module, bare name (`host.call("codec", …)`) | **WASM**, no grants (`assembly/codec`) | §4.1, §4.2, §9 |
| `reputation` — decayed per-peer reciprocity counters | installed module, bare name (`host.call("reputation", …)`) | **WASM**, no grants (`assembly/reputation`) | §13 |
| coordinator (PUT/GET, placement, manifest) + cohort (have/want, verification-fetch) + repair | confined QuickJS realm — **async** `call()` | zero-authority JS (`host/tier2-guest.js`) | §5–§9 |
| holder side — admission, sibling rule, content-addressing, quota, the store writes | the **same** realm — **async** `call()` | zero-authority JS (`host/tier2-guest.js`) | §6, §10, §14 |
| the seam the guest reaches I/O through | seedkernel runtime | `host.call(name, bytes)` — services, residual `crypto/*` transforms, module names | §16 |
| `crypto/*`, `fs`, `node`, `clock` backends | seedkernel runtime | raw-byte services + frozen host-transform table | §12, §16 |

Hashing, ChaCha20-Poly1305, and signatures are **reused** from the runtime's core
libsodium — never bundled. The guest reaches the ungated
`crypto/blake2b-256` and `crypto/chacha20poly1305-ietf/{seal,open}` transforms,
keeps ciphertext length-preserving for RS, and carries each detached 16-byte tag
inside the signed descriptor. Its nonce convention and scoped
`node/sign`/`node/verify` use are storage policy layered on the generic seam.

**The one realm.** Storage runs its whole guest in a single confined realm
seedkernel provides (§12.3), over its genuinely-async seam: the initiator
(PUT/GET/repair) fans out over `_net` and awaits *real* promises, and the holder
side answers from local `fs` + crypto, both through the realm's `call()`. The
fs seam is asynchronous on every backend, and the realm's per-realm FIFO
(seedkernel realm-queue.ts) runs one entrypoint to completion before the next —
so an inbound request to a node whose initiator is parked waits for the queue to
drain: the serialization cost the runtime documents, and the price of a holder
that may `await` its own store. `StorageNode` (`host/storage-node.ts`) keeps a
host-side copy of both sides as the reference/parity path — the role the
host-side classes play in the tests — but the **shipped** node runs the confined
guest.

## Signing scope, storage index, and bundle versioning

Three seedkernel runtime contracts reach into the storage code, each with a
seedstore-side counterpart worth pinning down. The contracts are documented on
the runtime side — in [RUNTIME §12](https://github.com/arj03/seedkernel/blob/main/docs/RUNTIME.md) —
and the spec side in the [seed store spec](../README.md) (§16); this section is
the code map for where each lands in this repo — the guest, the host parity
mirror, and the bundle producer:

1. **Signatures are scoped on both paths** — the scoped sign pair
   (`node/sign`/`node/verify`: a guest signature is over
   `DOMAIN_guest ‖ scope ‖ msg`, the `scope` host-derived from the admitted
   manifest and applied on both paths; the raw `crypto/ed25519/verify` primitive
   stays ungated, seedkernel §12.2). `signCore` passes the bare core to
   `node/sign`, which signs `DOMAIN_guest ‖ scope ‖ core`, and `verifyEnv`
   checks the same preimage through `node/verify` for the author key in the
   envelope; the host mirror (`signDescriptor`/`verifyDescriptor` in
   `host/manifest.ts`) rides the same two scoped names, so the parity tests
   hold. Neither path ever reconstructs the prefix: the scope is the kernel's to
   apply, derived from the admitted manifest's `(author, app)` — one derivation,
   so the two cannot disagree.
2. **The descriptor's leading byte is the signed-format tag** (spec §16). The
   descriptor core leads with `TAG_DESCRIPTOR = 0x01` (`manifest-core.ts`), and
   the Part II signed formats reserve their own values before they exist
   (`TAG_TOMBSTONE = 0x02`, `TAG_HEAD = 0x03`). The tag sits inside `core`, so
   it is already under the signature and inside the scoped preimage.
3. **The holder indexes its app-owned store once** — on first access the guest
   rebuilds held ids and quota usage from `FS_LIST`/`FS_SIZE`, then updates that
   authoritative index with each STORE reservation. OFFER and STORE sibling checks
   therefore avoid repeated filesystem metadata calls. New blocks commit as one
   `<block-id>.rec` (`[descriptor length][descriptor][ciphertext]`) instead of a
   `.blk` plus `.dsc` pair; the guest and `FsBlobView` still read the legacy layout
   so an existing holder upgrades in place.
4. **The bundle carries an integer, monotonic `version`** (the monotonic
   downgrade refusal, seedkernel §12.4; `scripts/storage-bundle.mjs`):
   guarded by `Number.isInteger` and bumped on every publish, so the shell's
   freshness check (§12.4) has a real high-water mark to enforce.
5. **The tests that pin this**: `manifest` (tamper-evidence over the tagged,
   scoped preimage), `tier2-port` / `holder-guest` (parity across the scoped
   sign/verify paths), `shell-run` (bundle version freshness — a downgrade is
   refused), `net` (legacy and current durable layouts across a cold reopen), and
   `protocol` (concurrent STOREs cannot race the authoritative sibling reservation).

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
npm install        # one dependency: the sibling seedkernel-wasm (core libsodium + QuickJS live there)
npm run build      # compile codec+reputation WASM, stage the guest, compile host TS
npm test           # build + run the full test suite (Node); `bun tests/run.mjs` runs it on Bun
```

`npm run build` produces `build/codec.wasm`, `build/reputation.wasm`, the staged
`build/host/tier2-guest.js`, and the compiled host in `build/host/`.

## Run a node from the command line

A node is the generic seedkernel **shell** plus two signed bundles: the
kernel-shipped **transport bundle** (the signed program that IS the node's
network — the shell admits it for the transport role and stands its driver up)
and the signed seed store **bundle**. First build the bundle once (the offline
producer holds the app author key):

```sh
npm run build:bundle      # → ./bundle/ (manifest + codec/reputation wasm + installs + guest),
                          #   signed by ./seedstore-author.key (minted on first run; keep it secret)
```

The shell admits content only from authors named in its policy file
(seedkernel §12.5). Take the author public key it printed (`author …`) and allow
it — the transport role needs the transport author's key too (ask the shell for
it, or omit `roles` and the node boots without a network):

```sh
echo '{ "authors": ["<author-pubkey-hex>"], "roles": { "transport": ["<transport-author-hex>"] } }' > allowed-keys.json
```

Now run the shell from the seedkernel checkout. A **serving** node that has loaded
a bundle becomes a full storage node — it installs the modules, runs the confined
guest, and serves the holder side (HAVE/OFFER/STORE/FETCH) over TCP (and WebSocket
for browsers):

```sh
SHELL=../../seedkernel/WASM/build/host/main-node.js # the Node CLI application

# a holder: admits the transport bundle + the storage bundle, then serves the
# confined holder side
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
     --op put < ./notes.txt > ./receipt.bin
#   receipt.bin is the PutResult envelope, the handle a GET takes:
#   [K 32][chunkCount u32][placed u32][intended u32][rootLen u32][root …][idCount u32]…

node "$SHELL" --policy allowed-keys.json --bundle ./bundle/seedstore.skb --dir ./client \
     --peers "<pkA>@…,<pkB>@…,<pkC>@…,<pkD>@…" \
     --op get < ./getarg.bin > ./restored.txt
```

`--op` is the runtime's ONE app-facing flag (seedkernel §12.8): it names an op on the
app's `handle`, hands it **stdin** and writes its answer to **stdout**, and knows nothing
else — no argument shape, no response format, no storage word anywhere in the kernel.
A GET's argument is `[K 32][root …]`, so it is cut out of the receipt here, with whatever
tool you like:

```sh
# getarg = K ‖ root. The root is a signed DESCRIPTOR of variable length (§4.3), not a
# fixed-width id, so its length is read from the envelope rather than assumed.
node -e 'const b=require("fs").readFileSync("receipt.bin"), n=b.readUInt32BE(44);
process.stdout.write(Buffer.concat([b.subarray(0,32), b.subarray(48,48+n)]))' > getarg.bin
```

The root descriptor locates the file; the key `K` decrypts it (lose `K` and the holders
keep only permanent noise, §11). Operator lines go to stderr on both targets, so a
redirect carries only the app's bytes. The shell flags themselves
(`--listen`/`--ws-listen`/`--peers`/`--dir`/`--key`/`--timeout`) and `--op` are all
generic; only the storage bundle and the byte formats above are this node's. A node with
no listener is a pure client; one with `--listen`/`--ws-listen` keeps serving until
Ctrl-C.

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

`LoopbackNetwork` (host/loopback.ts) wires nodes in one process: the real
transport bundle runs between them — AKE, record layer, routing — over
microtask-delivered channel pairs, so an in-process cohort exercises the shipped
stack. There is one protocol implementation: `put`/`get`/`repair` always run the
*confined* guest (`host/tier2-guest.orchestration.js`) inside a QuickJS realm,
and the holder side (HAVE/OFFER/STORE/FETCH) runs the same guest in the same
realm — `StorageNode` is just the host that boots the kernel, admits the signed
transport + storage bundles, and drives it (§19, §2.1). The `BlobStore` backend
is in-memory by default; a server uses a directory (`new NodeFs(dir)`), a
browser uses OPFS/IndexedDB (§12).

## Browser

The host is platform-neutral (it imports seedkernel's `node:fs`-free browser
host). One build stages both browser pages into `build/browser-demo`:

```sh
npm run build && npm run build:browser-demo
npx http-server build/browser-demo -p 3000
#   in-tab cohort:          http://localhost:3000/index.html
#   real P2P:               http://localhost:3000/p2p.html    (holders, below)
```

**`index.html`** boots a cohort of nodes in one browser tab, stores a file with
client-side encryption + erasure coding across them, reads it back, and lets you
take peers offline and watch repair restore redundancy.

**`p2p.html`** makes the tab a full storage node against a real cohort. A file dropped
in is encrypted and erasure-coded (RS(1,1)) across the other nodes; any node rebuilds it
from the retrieval token. Two transports, picked on the page:

**Direct WebSocket** (the default) dials natively-reachable nodes straight at their
`--ws-listen` port — no relay, no STUN, no signaling of any kind. Start `seedloader`
holders, copy each one's `pubkey[.secret]@host:port` into the peers box, and store:

```sh
seedloader --ws-listen 0.0.0.0:47210 …   # one per holder; disk-backed store
#   then open http://localhost:3000/p2p.html and paste the endpoints
```

**WebRTC** instead has peers find each other through a WebSocket signaling relay and
then talk directly, peer-to-peer: the relay only introduces peers, STUN punches the path
through NAT, and no server sits in the data path. What it buys over a direct dial is
exactly that NAT traversal — reaching holders with no port you could paste — so if you
can copy a holder's endpoint you do not need it. The relay is app-neutral and ships with
[seedchat](https://github.com/arj03/seedchat) (`npm run relay` there); seed store runs
none of its own. The cohort is either **3+ tabs** in one room, or one tab plus **console
holders** — the same `RtcNetwork`, driven on the Node/Bun side by werift's pure-JS
WebRTC (§12.6):

```sh
cd ../../seedchat && npm run relay   # signaling rendezvous, ws://localhost:8080
npm run serve:rtc-holder             # a real StorageNode joining the room (Bun); run two
#   then open p2p.html, pick WebRTC  (relay ws://localhost:8080, room "seedstore-demo")
```

A caveat on the all-tabs cohort: a tab's `BlobStore` is in-RAM — the OPFS/IndexedDB
backend (§12) is not built yet — so tabs-as-holders forget everything on reload. Until
that lands, read the browser as the cohort's **owner** and let `seedloader` or the
console holders be the ones that actually keep bytes.

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
- **bridges** — crypto primitives, the `store.local` backend, and the
  service-gate end-to-end via seedkernel's forwarder fixture (§8.2).
- **manifest** — descriptor/manifest round trips, author signature is
  tamper-evident, index-list encrypt round trip, and the one-shape descriptor
  math: multiplicity as the replica count, `r` = *m*+1, the placement
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
- **net** — networking + filesystem integration: `FsBlobView` persisting across
  reopen, a full cohort over real TCP sockets with blocks landing on holders'
  disks, and a browser-like node reaching a server over a real WebSocket.
- **tier2-port** — the same PUT/GET/replication/offline/repair/crypto-shredding
  matrix driven *inside* the confined QuickJS realm over the generic guest seam,
  with cross-path parity proving the confined and host-side paths are byte-compatible.
- **shell-run** — a generic seedkernel-shell (no seed store imports) loads the
  signed bundle and runs the guest as the PUT/GET *initiator* against a cohort.
- **holder-guest** — a cohort of generic shells runs storage end-to-end with the
  *holder* side confined too; a guest initiator and a host-side initiator place
  concurrently (the realm serializes — an inbound request to a node whose
  initiator is parked queues behind it and is served as the queue drains, so the
  overlap costs latency on a busy realm, never correctness); and a host-side
  initiator → confined shell holders round-trips (parity).
- **browser** — the same node booted through the `fetch`-based browser entry.

## Performance

100 MB, RS(10,6), 64 KB blocks, single-threaded (Node 20):

| | time | rate | |
|---|---:|---:|---|
| **write** — full (encrypt + hash + RS encode) | ~0.44 s | ~227 MB/s | |
| &nbsp;&nbsp;↳ chacha20-poly1305 seal | ~0.26 s | ~390 MB/s | detached tag lives in the descriptor |
| &nbsp;&nbsp;↳ RS encode (SIMD) | ~0.07 s | ~1.38 GB/s | |
| &nbsp;&nbsp;↳ BLAKE2b block-ids | ~0.15 s | ~1.1 GB/s | hashes all *n* blocks (1.6×) |
| **read** — all data present (systematic) | ~0.03 s | ~3.0 GB/s | common path — a concat, no GF |
| **read** — one block missing (decode, SIMD) | ~0.07 s | ~1.5 GB/s | the common failure, §6/§21 |

Three optimizations got here. (1) The codec multiplies via a precomputed 256×256
GF(2⁸) table — one indexed load per byte — making encode **~26× faster** than the
naive exp/log multiply. (2) Block-ids hash with **BLAKE2b** instead of SHA-3,
**~6× faster** (~0.83 s of SHA-3 was the original write bottleneck) and, like
everything else, already in the libsodium the kernel loads — **no new bytes**
(§16). (3) The RS multiply-accumulate loops use **WASM SIMD** — the GF(2⁸)
split-table / `i8x16.swizzle` trick does 16 multiplies per instruction — for
another **~3.4×** on encode/decode. With all three, sealing is the largest part of
the write (~0.26 / ~0.15 / ~0.07 s for encrypt / hash / encode), while reads
cost nothing on the codec unless a block is actually missing. (SIMD needs a
runtime with the WASM simd feature — Node 16+ and every current browser.) `node
tests/bench.mjs` reproduces these.

**End to end, the link bounds throughput, not the codec.** A multi-MB file is
many blocks. WebRTC physical messages stay capped at 48 KiB, while the channel
adapter exposes a length-framed byte stream so a 256 KiB encrypted record can be
split and reassembled without paying another request round trip per physical
chunk. The coordinator batches blocks into those records and `fanoutWindow` keeps
records per holder in flight. Over a 10 ms-RTT link (4 MB, RS(2,2), 32 KiB blocks,
256 KiB logical batches split into 48 KiB physical messages, window 32):

| | time | rate | |
|---|---:|---:|---|
| **PUT** | ~0.61 s | ~6.5 MB/s | ships the 2× erasure overhead — RS(2,2) is 2 data + 2 parity |
| **GET** | ~0.30 s | ~13.4 MB/s | downloads any *k* of *n* — 1× the file |

`node tests/bench-net.mjs 10 4 32 256 48 32` reproduces this in a fresh W=32
process (omit the final `32` to sweep the window); the
latency is modelled at the wire — every message pays it, both directions, so one
request/response costs the full RTT, while its physical chunks share that delivery
delay as they do on an ordered byte stream. (The old ~11/~17 MB/s figures measured a
host-side delay that charged only the inbound request, not the response.) Over a
real browser↔browser WebRTC link the `p2p.html` demo reports ~13 MB/s both ways.

`node tests/bench-holder.mjs 16 256 1 1 disk` isolates holder admission and
durable STORE work on a real filesystem. Its capacity comparison uses total holder
payload over the complete PUT wall time as a conservative floor, and separately
sums the already co-resident holders' measured rates for the active holder window;
it does not divide by the holder count a second time.

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

riding on the seedkernel shell it shares with any app — the shell JS
(28 KB / **5 KB gz**, module table included: the kernel is host code, not a
module) and the core libsodium (217 KB, reused not bundled). So **seedstore's own runtime
footprint is ~15 KB of WASM + ~8 KB of gzipped JS (the guest)** (§2, §16: "logic +
RS, tens of KB, no second copy of a crypto library").

The host-side TypeScript (`build/host`, minified to `build/host-min`) is a
*separate* path — the **in-process library** (it boots the kernel and runs the same
guest in-process) that the browser demo and the `createConnectedCohort` tests load
*instead* of the shell+bundle. Minified it is **21 KB gz** (14 KB gz without its own
copy of the guest), debug 42 KB gz — so a browser-demo node carries ~26 KB gz of JS
(host + the shared `ModuleTable`) against a bundle node's ~13 KB (the 8 KB guest +
the 5 KB `ModuleTable`).

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
assembly/codec/        gf256.ts, rs.ts, index.ts   — Reed–Solomon WASM module
assembly/reputation/   index.ts                    — decayed reciprocity WASM module
host/  tier2-guest.js          the confined guest: the WHOLE protocol (PUT/GET/repair + holder)
       storage-node.ts         the host that boots the slot + drives the guest in one realm
       manifest (+core)/crypto/protocol/store-fs/store-local/names/util  — shared helpers
       node.ts / browser.ts    Node + browser entry points (each loads the guest text)
scripts/  build-bundle.mjs     produce the signed bundle (npm run build:bundle)
          build-browser-demo               — stage all browser pages → build/browser-demo
          serve-rtc-holder + smoke-rtc        — relay-signaled P2P over RtcNetwork + STUN
tests/    codec / bridges / manifest / protocol / reputation / storage
          concurrency / net / browser / shell-run / holder-guest / bundle-fixture
```

The runtime itself — the shell, the guest seam, the raw-byte services, the
QuickJS confinement realms, the bundle format and policy — lives in
[seedkernel](https://github.com/arj03/seedkernel) ([RUNTIME §12](https://github.com/arj03/seedkernel/blob/main/docs/RUNTIME.md),
[EXPORTS](https://github.com/arj03/seedkernel/blob/main/docs/EXPORTS.md)); seed
store consumes it as the `seedkernel-wasm` dependency and ships only the content
above.

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

**Coded and replicated chunks are one SHAPE, not two models.** Every chunk lists
*n* = *k* + *m* ids and records the same *m* — "survives *m* losses" (§4.1). Where
the code degenerates (*k*=1, RS(1,*m*) parity ≡ data) the descriptor simply lists
its one block *m*+1 times, so **multiplicity is the replica count** and there is
nothing to branch on: the placement slots are the listed ids, reads take any *k*
distinct listed blocks, and repair is one audit against one health number — the
**loss margin**, `Σ min(live, multiplicity) − k` — healed back to whatever the
chunk's own signed descriptor asks for. Nothing about durability is injected
config: *r* and the low-water mark ⌈*m*/2⌉ are read off the descriptor
(`copyTargets` / `lowWaterMargin` in `manifest-core.ts`), so a repairer needs no
deployment config and a mixed-geometry cohort heals each chunk to the count its
author signed. The browser demos run *k*=1 deliberately — surviving the loss of a
holder in a two- or three-node cohort means replication, not coding.

**A chunk holds file bytes or descriptors; a file is one descriptor.** There is no
manifest object and no second code path: `placeStream` is the only thing that turns
bytes into placed chunks, and a file's descriptor list is bytes, so `putFinish`
calls it again on its own output until one chunk is left. That loop runs *zero*
times for a file under `k·B`, once up to ~1 GB, twice up to ~2.5 TB — bounded and
shallow because one chunk holds thousands of descriptors. Its only precondition —
a chunk holds two descriptors — depends on `(k, blockSize)` alone and is checked
when a PUT opens. What a reader is handed is the **root descriptor**
(variable-length, `PutResult.root`) rather than a 32-byte id — the whole ergonomic
cost — and in exchange the nonce domain is the chunk's own signed `level`, and no
block on the wire is ever larger than `blockSize`.

# seed store performance

Numbers and tuning notes for the [WASM implementation](../WASM/README.md). Spec
references (`§n`) point to [SPEC.md](SPEC.md). Run the commands from `WASM/` after
`npm run build`.

## The codec

100 MB, RS(10,6), 64 KB blocks, single-threaded (Node 20), measured with
`node tests/bench.mjs`:

| | time | rate | |
|---|---:|---:|---|
| **write**: full (encrypt + hash + RS encode) | ~0.52 s | ~194 MB/s | |
| &nbsp;&nbsp;↳ chacha20-poly1305 seal | ~0.25 s | ~405 MB/s | the detached tag lives in the descriptor |
| &nbsp;&nbsp;↳ RS encode (SIMD) | ~0.07 s | ~1.5 GB/s | |
| &nbsp;&nbsp;↳ BLAKE2b block ids | ~0.21 s | ~752 MB/s | hashes all *n* blocks (1.6×) |
| **read**: all data present (systematic) | ~0.04 s | ~2.7 GB/s | the common path: a concat, no GF math |
| **read**: one block missing (decode, SIMD) | ~0.06 s | ~1.7 GB/s | the common failure, §6/§21 |

Three optimizations got the codec here:

1. **A 256×256 GF(2⁸) multiply table**: one indexed load per byte, which made encode
   **~26× faster** than the naive exp/log multiply.
2. **BLAKE2b block ids instead of SHA-3**: **~6× faster**. SHA-3 was originally the
   write bottleneck at ~0.83 s. BLAKE2b is also already in the libsodium the host
   loads, so it adds no bytes (§16).
3. **WASM SIMD for the RS multiply-accumulate loops**: another **~3.4×** on encode
   and decode.

With all three, sealing is the largest part of a write, and reads spend nothing in
the codec unless a block is actually missing. SIMD needs a runtime with the WASM simd
feature, which means Node 16+ or any current browser.

**The SIMD split-table trick (GF(2⁸) "PSHUFB").** For a fixed coefficient *c*, `c·x`
splits into two 4-bit lookups, `c·(x & 0x0F) ⊕ c·(x >> 4)`, each from a 16-byte table.
WASM's `i8x16.swizzle` does 16 table lookups in parallel, so one instruction multiplies
16 bytes. Output accumulators stay in `v128` registers across the *k* inputs (register
blocking), and a scalar tail handles a block whose size isn't a multiple of 16. Native
RS libraries use the same technique.

**Block-id hash: BLAKE2b now, BLAKE3 as the next step.** Block ids are internal to
storage and never cross into the host, so the hash is storage's own choice. The next
step up is BLAKE3: a vectorized `hash_many` could compute all *n* block ids of a
chunk across parallel SIMD lanes, at a projected multi-GB/s. Using BLAKE3's *interior
tree nodes* as block ids would **not** work, though. Content-addressed ids must be
position-independent, because a holder re-verifies `hash(bytes) == id` with no
context (§4.2). BLAKE3 chaining values depend on position, and using them would
bring back the Merkle-path machinery the spec avoids (§8).

## End to end: the link is the limit

Once a file spans many blocks, the link bounds throughput, not the codec. The
coordinator batches blocks into records of up to `maxMessageBytes`. WebRTC physical
messages stay capped at 48 KiB, but the channel adapter exposes a length-framed byte
stream, so a 256 KiB record is split and reassembled without an extra round trip.

### Modelled latency (`bench-net.mjs`)

10 ms RTT, 4 MB, RS(2,2), 32 KiB blocks, 256 KiB batches in 48 KiB physical
messages, window 32 (`node tests/bench-net.mjs 10 4 32 256 48 32`; leave off the
final `32` to sweep the window):

| | time | rate | |
|---|---:|---:|---|
| **PUT** | ~0.41 s | ~9.7 MB/s | ships the 2× erasure overhead: RS(2,2) is 2 data + 2 parity |
| **GET** | ~0.24 s | ~16.9 MB/s | downloads any *k* of *n*, i.e. 1× the file |

The bench applies latency at the wire. Every message pays it in both directions, so
one request/response costs a full RTT. The physical chunks of one message share a
single delivery delay, as they would on an ordered byte stream.

A 64 MB file over 40 ms with 1 MiB batches
(`node tests/bench-net.mjs 40 64 256 1024 48 32`) runs PUT ~2.7 s (~24 MB/s) and GET
~1.34 s (~48 MB/s).

### Live WAN

Two remote holders, RS(1,1), 256 KiB blocks, 512 KiB batches, 8 connections per
holder (the most a holder admits from one address), a 24 MB streaming window, 50 MB
per run:

| | rate | |
|---|---:|---|
| **PUT** | ~12.5 MB/s wire | ~6.2 MB/s of file, because RS(1,1) ships 2× |
| **GET** | ~18.5 MB/s | |

Reproduce it against live nodes with:

```sh
node --experimental-websocket scripts/p2p-cli.mjs --peers … --size 50 \
     --timeout 30000 --guest-deadline 60000
```

A real browser↔browser WebRTC link in the `p2p.html` demo reports ~13 MB/s in both
directions.

### The two benches answer different questions

`bench-net.mjs` models a fixed per-message delay with no bandwidth limit and no
loss. Every message costs one RTT and a round of *W* messages lands together, so it
can't show refill or straggler effects. It does show guest CPU nearly at full value:
the `toHex` work alone moved its PUT by 7% and its GET by 10%, which the live link
doesn't show. Use `bench-net` to price guest CPU, and judge wire behaviour on a live
cohort.

## How the transfer engine is tuned

**Per-lane refill.** The window's *width* is not the lever. The host-call ledger
paces it to the realm's budget either way. What matters is how slots **refill**.
Lock-step rounds let one slow holder idle every other slot in the round. Giving each
slot its own lane over a shared cursor (`runStoreBatches`) measured **+22%** on the
same holders (paired and order-interleaved runs), and it removed a slow tail that
was making whole PUTs miss their deadline.

**Pipelined windows.** A streamed PUT keeps one window placing while the next one
encodes and sends its OFFERs, and the index places alongside the file's last window.
A streamed GET fetches the next window while the current one is decrypted and handed
back. Without this, the wire would sit idle at every window boundary. Over a 40 ms
link (16 MB, RS(2,2), 32 KiB blocks, 4 MiB windows;
`node tests/bench-net.mjs 40 16 32 256 48 32 4`), pipelining took PUT from ~1.99 s to
~1.60 s and GET from ~1.10 s to ~0.83 s.

**One host-call ledger.** The two windows in flight share the realm's host-call
budget through one ledger (`hostBudget`), and every initiator call is charged against
it. The ledger has two FIFO classes. Foreground calls (crypto, codec, OFFER, HAVE)
are admitted before bulk calls (STORE, FETCH), and bulk always leaves room for the
largest call, so the next window's encode never waits behind the last window's
STOREs. Holder work stays off the ledger, so two nodes storing to each other can't
deadlock. A frame is built only once the ledger admits its call, so a lane waiting
its turn holds no copy of its blocks.

**Holder admission.** A holder admits only so many request bytes from one source at
once and answers the rest empty. The ledger alone doesn't prevent over-sending to one
holder: at defaults it lets out ~15 MiB while a holder admits ~10 MiB. So STORE lanes
start round-robin across peers, and a lane whose request comes back empty hands it to
that peer's other lanes and retires. Before this, most local 50 MB PUTs to two
holders failed with "no holder returned a verdict".

**Memory.** Two windows in flight cost memory, so the default window is a sixth of
`realmMemoryBytes`. A 64 MiB realm peaks at ~56 MiB during a PUT on a slow link.

## The guest deadline

seedkernel gives each guest invocation `DEFAULT_GUEST_DEADLINE_MS` (5 s). The budget
covers guest execution *and* the wall-clock time of every handoff. A window's calls
run under the invocation that fed that window, so its encode and placement must
finish within the deadline, even though placement completes during the next feed.
Running over fails the whole PUT with
`guest: handoff deadline exhausted before host.call`.

This is not the request timeout. Raise `guestDeadlineMs` (`--guest-deadline` in
p2p-cli), not `--timeout`. Nothing derives the window size from the deadline
(`windowTargetBytes` comes from `realmMemoryBytes`), so a wider window or a slower
link needs a higher deadline to match. Also raise it before any throughput A/B test.
Otherwise the deadline kills the slow runs, and the arm that loses its slow runs
looks faster.

## Holder ingest

`node tests/bench-holder.mjs 16 256 1 1 disk` isolates holder admission and durable
STORE work on a real filesystem: ~6.6 ms per 256 KiB block, a ~37 MB/s mean holder
rate, and PUT ~0.67 s (~24 MB/s) with the initiator and the holders sharing one
process. Most of the per-block time is waiting for that one thread; the crypto floor
is ~0.36 ms per block. So treat the result as a bound on a co-resident cohort, not on
a dedicated holder machine. The capacity comparison uses total holder payload over
the complete PUT wall time as a conservative floor. It separately sums the
co-resident holders' measured rates for the active holder window, without dividing
by the holder count a second time.
